package registry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	externalSourceFetchTimeout       = 2 * time.Minute
	externalSourceOutputLimit        = 64 * 1024
	externalSourceCacheLimit         = 64 * 1024 * 1024
	externalSourceGlobalCacheLimit   = 256 * 1024 * 1024
	externalSourceCacheEntryLimit    = 12_000
	externalSourceObjectLimit        = 10_000
	externalSourceWorkingTreeLimit   = 32 * 1024 * 1024
	externalSourceWorkingFileLimit   = 4 * 1024 * 1024
	externalSourceWorkingEntryLimit  = 4_096
	externalSourceMonitorInterval    = 25 * time.Millisecond
	externalSourceBlobFilterArgument = "blob:limit=4m"
)

var (
	errExternalSourceOutputLimit = errors.New("external source Git command exceeded the diagnostic output limit")
	errExternalSourceTimeout     = errors.New("external source Git command exceeded the execution timeout")
	errExternalSourceSymlink     = errors.New("external source checkout contains a symbolic link")
)

type sourceDirectoryLimits struct {
	maxBytes            int64
	maxEntries          int64
	maxWorkingFileBytes int64
	rejectSymlinks      bool
}

type sourceDirectoryUsage struct {
	bytes              int64
	entries            int64
	workingTreeBytes   int64
	workingTreeEntries int64
}

type sourceResourceError struct {
	resource string
	limit    int64
}

func (e *sourceResourceError) Error() string {
	return fmt.Sprintf("external source exceeded the %s limit (%d)", e.resource, e.limit)
}

type boundedCommandOutput struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	exceeded bool
	cancel   context.CancelFunc
}

func newBoundedCommandOutput(limit int, cancel context.CancelFunc) *boundedCommandOutput {
	return &boundedCommandOutput{
		limit:  limit,
		cancel: cancel,
	}
}

func (w *boundedCommandOutput) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	remaining := w.limit - w.buffer.Len()
	if remaining > 0 {
		writeLength := len(data)
		if writeLength > remaining {
			writeLength = remaining
		}
		_, _ = w.buffer.Write(data[:writeLength])
	}
	if len(data) > remaining && !w.exceeded {
		w.exceeded = true
		w.cancel()
	}
	return len(data), nil
}

func (w *boundedCommandOutput) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()

	result := make([]byte, w.buffer.Len())
	copy(result, w.buffer.Bytes())
	return result
}

func (w *boundedCommandOutput) Exceeded() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.exceeded
}

func inspectSourceDirectory(root string, limits sourceDirectoryLimits) (sourceDirectoryUsage, error) {
	var usage sourceDirectoryUsage

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if path == root {
			return nil
		}

		usage.entries++
		if limits.maxEntries > 0 && usage.entries > limits.maxEntries {
			return &sourceResourceError{
				resource: "per-source cache entry",
				limit:    limits.maxEntries,
			}
		}

		relativePath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		insideGitDirectory := relativePath == ".git" ||
			strings.HasPrefix(relativePath, ".git"+string(filepath.Separator))

		info, err := entry.Info()
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 && limits.rejectSymlinks && !insideGitDirectory {
			return errExternalSourceSymlink
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		usage.bytes += info.Size()
		if limits.maxBytes > 0 && usage.bytes > limits.maxBytes {
			return &sourceResourceError{
				resource: "per-source cache byte",
				limit:    limits.maxBytes,
			}
		}

		if insideGitDirectory {
			return nil
		}

		usage.workingTreeBytes += info.Size()
		usage.workingTreeEntries++
		if limits.maxWorkingFileBytes > 0 && info.Size() > limits.maxWorkingFileBytes {
			return &sourceResourceError{
				resource: "working-tree file byte",
				limit:    limits.maxWorkingFileBytes,
			}
		}
		return nil
	})
	return usage, err
}

func validateSourceWorkingTree(root string) error {
	usage, err := inspectSourceDirectory(root, sourceDirectoryLimits{
		maxBytes:            externalSourceCacheLimit,
		maxEntries:          externalSourceCacheEntryLimit,
		maxWorkingFileBytes: externalSourceWorkingFileLimit,
		rejectSymlinks:      true,
	})
	if err != nil {
		return err
	}
	if usage.workingTreeBytes > externalSourceWorkingTreeLimit {
		return &sourceResourceError{
			resource: "working-tree byte",
			limit:    externalSourceWorkingTreeLimit,
		}
	}
	if usage.workingTreeEntries > externalSourceWorkingEntryLimit {
		return &sourceResourceError{
			resource: "working-tree file",
			limit:    externalSourceWorkingEntryLimit,
		}
	}
	return nil
}

func parseGitObjectUsage(output string) (int64, int64, error) {
	values := make(map[string]int64)
	for _, line := range strings.Split(output, "\n") {
		key, rawValue, ok := strings.Cut(strings.TrimSpace(line), ": ")
		if !ok {
			continue
		}
		switch key {
		case "count", "in-pack", "size", "size-pack":
			value, err := strconv.ParseInt(rawValue, 10, 64)
			if err != nil || value < 0 {
				return 0, 0, fmt.Errorf("invalid git object usage value %q", line)
			}
			values[key] = value
		}
	}
	for _, required := range []string{"count", "in-pack", "size", "size-pack"} {
		if _, ok := values[required]; !ok {
			return 0, 0, fmt.Errorf("git object usage did not report %s", required)
		}
	}

	objectCount := values["count"] + values["in-pack"]
	objectBytes := (values["size"] + values["size-pack"]) * 1024
	return objectCount, objectBytes, nil
}
