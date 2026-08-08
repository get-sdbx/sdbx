package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/get-sdbx/sdbx/internal/management"
	"github.com/get-sdbx/sdbx/internal/redact"
	"github.com/get-sdbx/sdbx/internal/securefs"
)

const maxAuditFieldBytes = 512

type AuditEvent = management.AuditEvent

type Auditor interface {
	Record(context.Context, AuditEvent) error
}

type AuditReader interface {
	Recent(context.Context, int) ([]management.AuditEvent, error)
}

type FileAuditor struct {
	file *os.File
	mu   sync.Mutex
}

func OpenFileAuditor(path string) (*FileAuditor, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("audit log path must be absolute")
	}
	path = filepath.Clean(path)
	parentPath := filepath.Dir(path)
	name := filepath.Base(path)
	if err := securefs.EnsureDir(parentPath, 0o750); err != nil {
		return nil, fmt.Errorf("prepare audit directory: %w", err)
	}
	root, parentInfo, err := securefs.OpenVerifiedRoot(parentPath)
	if err != nil {
		return nil, fmt.Errorf("pin audit directory: %w", err)
	}
	defer root.Close()
	if parentInfo.Mode().Perm()&0o022 != 0 ||
		!securefs.OwnedBy(parentInfo, os.Geteuid()) {
		return nil, fmt.Errorf(
			"audit directory must be owned by the daemon user and not writable by group or other users",
		)
	}

	var before os.FileInfo
	before, err = root.Lstat(name)
	switch {
	case err == nil:
		if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
			return nil, fmt.Errorf("audit log must be a regular file, not a symlink or special file")
		}
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("inspect audit log: %w", err)
	}

	flags := os.O_APPEND | os.O_RDWR
	if before == nil {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := root.OpenFile(name, flags, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect open audit log: %w", err)
	}
	if !opened.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("open audit log is not a regular file")
	}
	if before != nil && !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, fmt.Errorf("audit log changed while it was being opened")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("repair audit log permissions: %w", err)
	}
	return &FileAuditor{file: file}, nil
}

func (a *FileAuditor) Record(ctx context.Context, event AuditEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	event = sanitizeAuditEvent(event)
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	} else {
		event.Timestamp = event.Timestamp.UTC()
	}

	var record bytes.Buffer
	encoder := json.NewEncoder(&record)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(event); err != nil {
		return fmt.Errorf("encode audit event: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.file.Write(record.Bytes()); err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	if err := a.file.Sync(); err != nil {
		return fmt.Errorf("sync audit event: %w", err)
	}
	return nil
}

func sanitizeAuditEvent(event AuditEvent) AuditEvent {
	event.RequestID = boundedAuditField(event.RequestID)
	event.Actor = boundedAuditField(event.Actor)
	event.Operation = boundedAuditField(event.Operation)
	event.Method = boundedAuditField(event.Method)
	event.Path = boundedAuditField(event.Path)
	event.Outcome = boundedAuditField(event.Outcome)
	if len(event.Groups) > 32 {
		event.Groups = event.Groups[:32]
	}
	for index := range event.Groups {
		event.Groups[index] = boundedAuditField(event.Groups[index])
	}
	return event
}

func (a *FileAuditor) Recent(
	ctx context.Context,
	limit int,
) ([]management.AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		return nil, fmt.Errorf("audit limit must be between 1 and 500")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	before, err := a.file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect audit log: %w", err)
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("audit log must remain a regular file")
	}
	const window = int64(8 << 20)
	start := before.Size() - window
	if start < 0 {
		start = 0
	}
	reader := io.NewSectionReader(a.file, start, window+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	if int64(len(data)) > window {
		return nil, fmt.Errorf("audit read window exceeded")
	}
	if start > 0 {
		if newline := bytes.IndexByte(data, '\n'); newline >= 0 {
			data = data[newline+1:]
		} else {
			return []management.AuditEvent{}, nil
		}
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	result := make([]management.AuditEvent, 0, limit)
	for index := len(lines) - 1; index >= 0 && len(result) < limit; index-- {
		if len(bytes.TrimSpace(lines[index])) == 0 {
			continue
		}
		var event management.AuditEvent
		if err := json.Unmarshal(lines[index], &event); err != nil {
			return nil, fmt.Errorf("audit log contains an invalid event")
		}
		result = append(result, sanitizeAuditEvent(event))
	}
	return result, nil
}

func (a *FileAuditor) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return nil
	}
	err := a.file.Close()
	a.file = nil
	return err
}

func boundedAuditField(value string) string {
	value = strings.TrimSpace(redact.Text(value))
	if len(value) <= maxAuditFieldBytes {
		return value
	}
	return value[:maxAuditFieldBytes]
}
