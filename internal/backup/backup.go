package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"filippo.io/age"
	"github.com/get-sdbx/sdbx/internal/securefs"
	"gopkg.in/yaml.v3"
)

const (
	backupSuffix          = ".tar.gz.age"
	maxBackupNodes        = 200_000
	maxProjectConfigBytes = 1 << 20
	maxIdentityFileBytes  = 1 << 20
	maxMetadataBytes      = 64 << 10
	maxRestoreEntries     = 200_000
	maxRestoreFileBytes   = int64(8 << 30)
	maxRestoreTotalBytes  = int64(64 << 30)
	maxRestoreTrailing    = int64(1 << 20)
	maxArchivePathLength  = 4096
	maxArchivePathBytes   = int64(64 << 20)
)

// EncryptOptions selects exactly one encryption mode. Recipient mode never
// requires SDBX to possess or persist the corresponding private identity.
type EncryptOptions struct {
	Recipient  string
	Passphrase []byte
}

// DecryptOptions selects exactly one restore identity source.
type DecryptOptions struct {
	IdentityFile string
	Passphrase   []byte
}

// ManagedRoots captures the already verified config and secrets roots used by
// a privileged backup or restore flow. Supplying these paths prevents a later
// .sdbx.yaml reread from redirecting filesystem access after project
// verification.
type ManagedRoots struct {
	ConfigPath  string
	SecretsPath string
}

// RestoreHooks lets a trusted caller constrain and validate a restore.
// PreserveProject restores only service configuration and secrets into the
// current target roots. SkipConfigPaths keeps target-generated configuration
// intact. InspectProjectFile can compare archived intent and lock state before
// promotion. ValidateArchive runs after complete staging and before the first
// promotion. Validation runs after promotion but before commit; a failure
// restores every original target.
type RestoreHooks struct {
	PreserveProject    bool
	SkipConfigPaths    []string
	InspectProjectFile func(name string, data []byte) error
	ValidateArchive    func() error
	Validate           func(context.Context) error
	VerifiedRoots      *ManagedRoots
}

// Metadata contains information stored inside the encrypted archive.
type Metadata struct {
	Version   string     `json:"version"`
	Timestamp time.Time  `json:"timestamp"`
	Hostname  string     `json:"hostname"`
	ProjectID string     `json:"project_id"`
	Files     []string   `json:"files"`
	Omissions []Omission `json:"omissions,omitempty"`
}

// Omission records an ephemeral or reproducible filesystem node that was
// deliberately excluded from an encrypted backup. The archive never contains
// the node itself, so restore cannot recreate it.
type Omission struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

// Backup represents an encrypted backup archive.
type Backup struct {
	Name     string
	Path     string
	Metadata Metadata
}

// Manager handles backup operations.
type Manager struct {
	projectDir  string
	backupDir   string
	restoreHook func(phase, target string) error
}

func NewManager(projectDir string) *Manager {
	return &Manager{
		projectDir: projectDir,
		backupDir:  filepath.Join(projectDir, "backups"),
	}
}

type pathConfig struct {
	ConfigPath  string `yaml:"config_path"`
	SecretsPath string `yaml:"secrets_path"`
}

type backupSource struct {
	ArchivePrefix string
	HostPath      string
}

type backupBudget struct {
	nodes     int
	entries   int
	total     int64
	pathBytes int64
}

// Create writes an authenticated age-encrypted tar.gz archive atomically.
// Plaintext archive bytes are streamed directly into the age writer and are
// never persisted beside the final backup.
func (m *Manager) Create(ctx context.Context, options EncryptOptions) (*Backup, error) {
	pc, err := readPathConfig(m.projectDir)
	if err != nil {
		return nil, err
	}
	return m.CreateWithRoots(ctx, options, ManagedRoots{
		ConfigPath:  pc.ConfigPath,
		SecretsPath: pc.SecretsPath,
	})
}

// CreateWithRoots creates a backup from paths captured by the caller's
// verification transaction instead of rereading mutable project intent.
func (m *Manager) CreateWithRoots(
	ctx context.Context,
	options EncryptOptions,
	roots ManagedRoots,
) (*Backup, error) {
	recipient, err := encryptionRecipient(options)
	if err != nil {
		return nil, err
	}
	if err := securefs.EnsureDir(m.backupDir, 0o700); err != nil {
		return nil, fmt.Errorf("prepare backup directory: %w", err)
	}

	now := time.Now().UTC()
	name := "sdbx-backup-" + now.Format("20060102T150405.000000000Z") + backupSuffix
	backupPath := filepath.Join(m.backupDir, name)
	hostname, _ := os.Hostname()

	sources, err := m.resolveSources(roots)
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(sources))
	for _, source := range sources {
		files = append(files, source.ArchivePrefix)
	}
	omissions, err := m.inspectBackupSources(ctx, sources)
	if err != nil {
		return nil, fmt.Errorf("inspect backup sources: %w", err)
	}
	metadata := Metadata{
		Version:   "2.0.0",
		Timestamp: now,
		Hostname:  hostname,
		ProjectID: filepath.Base(m.projectDir),
		Files:     files,
		Omissions: omissions,
	}

	if err := m.createEncryptedArchive(
		ctx,
		backupPath,
		sources,
		metadata,
		recipient,
	); err != nil {
		return nil, fmt.Errorf("create encrypted backup: %w", err)
	}
	return &Backup{Name: name, Path: backupPath, Metadata: metadata}, nil
}

func encryptionRecipient(options EncryptOptions) (age.Recipient, error) {
	hasRecipient := strings.TrimSpace(options.Recipient) != ""
	hasPassphrase := len(options.Passphrase) > 0
	if hasRecipient == hasPassphrase {
		return nil, fmt.Errorf("select exactly one backup encryption mode: recipient or passphrase")
	}
	if hasPassphrase {
		recipient, err := age.NewScryptRecipient(string(options.Passphrase))
		if err != nil {
			return nil, fmt.Errorf("configure passphrase encryption: %w", err)
		}
		return recipient, nil
	}

	value := strings.TrimSpace(options.Recipient)
	if strings.HasPrefix(value, "age1pq1") {
		recipient, err := age.ParseHybridRecipient(value)
		if err != nil {
			return nil, fmt.Errorf("parse age hybrid recipient: %w", err)
		}
		return recipient, nil
	}
	recipient, err := age.ParseX25519Recipient(value)
	if err != nil {
		return nil, fmt.Errorf("parse age recipient: %w", err)
	}
	return recipient, nil
}

func decryptionIdentities(options DecryptOptions) ([]age.Identity, error) {
	hasIdentity := strings.TrimSpace(options.IdentityFile) != ""
	hasPassphrase := len(options.Passphrase) > 0
	if hasIdentity == hasPassphrase {
		return nil, fmt.Errorf("select exactly one backup decryption mode: identity file or passphrase")
	}
	if hasPassphrase {
		identity, err := age.NewScryptIdentity(string(options.Passphrase))
		if err != nil {
			return nil, fmt.Errorf("configure passphrase decryption: %w", err)
		}
		// SDBX writes age's current logN=18 default. Do not accept a crafted
		// archive requesting more work and turning restore into a CPU/memory
		// denial of service.
		identity.SetMaxWorkFactor(18)
		return []age.Identity{identity}, nil
	}

	data, err := securefs.ReadRegularFile(options.IdentityFile, maxIdentityFileBytes)
	if err != nil {
		return nil, fmt.Errorf("read age identity file: %w", err)
	}
	defer wipeBytes(data)
	identities, err := age.ParseIdentities(strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("parse age identity file: %w", err)
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("age identity file contains no identities")
	}
	return identities, nil
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func (m *Manager) resolveSources(roots ManagedRoots) ([]backupSource, error) {
	configRoot, err := resolveConfiguredRoot(m.projectDir, roots.ConfigPath, "configs")
	if err != nil {
		return nil, fmt.Errorf("resolve config_path: %w", err)
	}
	secretsRoot, err := resolveConfiguredRoot(m.projectDir, roots.SecretsPath, "secrets")
	if err != nil {
		return nil, fmt.Errorf("resolve secrets_path: %w", err)
	}
	if pathWithin(configRoot, m.backupDir) || pathWithin(secretsRoot, m.backupDir) {
		return nil, fmt.Errorf(
			"config and secrets roots must not contain the managed backup directory",
		)
	}
	return []backupSource{
		{ArchivePrefix: ".sdbx.yaml", HostPath: filepath.Join(m.projectDir, ".sdbx.yaml")},
		{ArchivePrefix: ".sdbx.lock", HostPath: filepath.Join(m.projectDir, ".sdbx.lock")},
		{ArchivePrefix: "compose.yaml", HostPath: filepath.Join(m.projectDir, "compose.yaml")},
		{ArchivePrefix: ".env", HostPath: filepath.Join(m.projectDir, ".env")},
		{ArchivePrefix: "secrets", HostPath: secretsRoot},
		{ArchivePrefix: "configs", HostPath: configRoot},
	}, nil
}

func (m *Manager) inspectBackupSources(
	ctx context.Context,
	sources []backupSource,
) ([]Omission, error) {
	backupRootInfo, err := os.Stat(m.backupDir)
	if err != nil {
		return nil, err
	}
	omissions := make([]Omission, 0)
	budget := &backupBudget{}
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		info, err := os.Lstat(source.HostPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			root, openedRoot, err := securefs.OpenVerifiedRoot(source.HostPath)
			if err != nil {
				return nil, err
			}
			if os.SameFile(openedRoot, backupRootInfo) {
				_ = root.Close()
				return nil, fmt.Errorf(
					"backup source resolves to the managed backup directory",
				)
			}
			err = inspectBackupRoot(
				ctx,
				root,
				".",
				source.ArchivePrefix,
				backupRootInfo,
				budget,
				&omissions,
			)
			_ = root.Close()
			if err != nil {
				return nil, err
			}
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf(
				"%s is a symlink and cannot be backed up safely",
				source.HostPath,
			)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", source.HostPath)
		}
	}
	sort.Slice(omissions, func(left, right int) bool {
		return omissions[left].Path < omissions[right].Path
	})
	return omissions, nil
}

func inspectBackupRoot(
	ctx context.Context,
	root *os.Root,
	relativeDirectory string,
	archivePrefix string,
	backupRootInfo os.FileInfo,
	budget *backupBudget,
	omissions *[]Omission,
) error {
	directory, err := root.Open(relativeDirectory)
	if err != nil {
		return err
	}
	defer directory.Close()
	for {
		entries, readErr := directory.Readdir(256)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := budget.visitNode(); err != nil {
				return err
			}
			relativeName := filepath.Join(relativeDirectory, entry.Name())
			info, err := root.Lstat(relativeName)
			if err != nil {
				return err
			}
			archiveName := path.Join(
				archivePrefix,
				filepath.ToSlash(relativeName),
			)
			if info.Mode()&os.ModeSymlink != 0 ||
				info.Mode()&os.ModeSocket != 0 {
				omission, err := inspectOmittableNode(
					root,
					relativeName,
					archiveName,
					info,
				)
				if err != nil {
					return err
				}
				*omissions = append(*omissions, omission)
				continue
			}
			if info.IsDir() {
				child, err := root.OpenRoot(relativeName)
				if err != nil {
					return err
				}
				opened, statErr := child.Stat(".")
				if statErr != nil || !os.SameFile(info, opened) {
					_ = child.Close()
					if statErr != nil {
						return statErr
					}
					return fmt.Errorf(
						"%s changed while it was being opened",
						archiveName,
					)
				}
				if os.SameFile(opened, backupRootInfo) {
					_ = child.Close()
					return fmt.Errorf(
						"backup source contains the managed backup directory",
					)
				}
				if err := inspectBackupRoot(
					ctx,
					child,
					".",
					archiveName,
					backupRootInfo,
					budget,
					omissions,
				); err != nil {
					_ = child.Close()
					return err
				}
				if err := child.Close(); err != nil {
					return err
				}
				continue
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("%s is not a regular file", archiveName)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func inspectOmittableNode(
	root *os.Root,
	relativeName string,
	archiveName string,
	info os.FileInfo,
) (Omission, error) {
	if info.Mode()&os.ModeSocket != 0 {
		return Omission{
			Path:   archiveName,
			Type:   "unix_socket",
			Reason: "ephemeral Unix socket",
		}, nil
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return Omission{}, fmt.Errorf("%s is not a regular file", archiveName)
	}
	target, err := root.Readlink(relativeName)
	if err != nil {
		return Omission{}, fmt.Errorf("inspect symlink %s: %w", archiveName, err)
	}
	if target == "" || filepath.IsAbs(target) {
		return Omission{}, fmt.Errorf(
			"%s is not a relative in-root symlink",
			archiveName,
		)
	}
	resolvedName := filepath.Clean(filepath.Join(filepath.Dir(relativeName), target))
	if resolvedName == ".." ||
		strings.HasPrefix(resolvedName, ".."+string(filepath.Separator)) {
		return Omission{}, fmt.Errorf(
			"%s resolves outside its managed root",
			archiveName,
		)
	}
	resolved, err := root.Stat(relativeName)
	if err != nil {
		return Omission{}, fmt.Errorf(
			"%s does not resolve to an in-root regular file: %w",
			archiveName,
			err,
		)
	}
	if !resolved.Mode().IsRegular() {
		return Omission{}, fmt.Errorf(
			"%s does not resolve to a regular file",
			archiveName,
		)
	}
	return Omission{
		Path:   archiveName,
		Type:   "symlink",
		Reason: "relative symlink to an in-root regular file",
	}, nil
}

func readPathConfig(projectDir string) (pathConfig, error) {
	var pc pathConfig
	configPath := filepath.Join(projectDir, ".sdbx.yaml")
	data, err := securefs.ReadRegularFile(configPath, maxProjectConfigBytes)
	if errors.Is(err, os.ErrNotExist) {
		return pc, nil
	}
	if err != nil {
		return pc, fmt.Errorf("read project configuration: %w", err)
	}
	if err := yaml.Unmarshal(data, &pc); err != nil {
		return pc, fmt.Errorf("parse project configuration paths: %w", err)
	}
	return pc, nil
}

func resolveConfiguredRoot(projectDir, configured, fallback string) (string, error) {
	value := configured
	if value == "" {
		value = fallback
	}
	cleaned := filepath.Clean(value)
	if cleaned == "." {
		return "", fmt.Errorf("path must name a dedicated directory")
	}
	if filepath.IsAbs(cleaned) {
		if filepath.Dir(cleaned) == cleaned {
			return "", fmt.Errorf("filesystem root is not allowed")
		}
		return cleaned, nil
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("relative path escapes the project")
	}
	return filepath.Join(projectDir, cleaned), nil
}

func (m *Manager) createEncryptedArchive(
	ctx context.Context,
	archivePath string,
	sources []backupSource,
	metadata Metadata,
	recipient age.Recipient,
) (returnErr error) {
	archiveName := filepath.Base(archivePath)
	if err := ValidateBackupName(archiveName); err != nil {
		return err
	}
	backupRoot, backupRootInfo, err := securefs.OpenVerifiedRoot(m.backupDir)
	if err != nil {
		return err
	}
	defer backupRoot.Close()
	transactionID, err := newRestoreTransactionID()
	if err != nil {
		return err
	}
	tempName := ".sdbx-backup-" + transactionID + ".tmp"
	temp, err := backupRoot.OpenFile(
		tempName,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return err
	}
	defer func() {
		_ = temp.Close()
		if tempName != "" {
			_ = backupRoot.Remove(tempName)
		}
	}()
	if err := securefs.InheritFileOwnership(temp, backupRootInfo); err != nil {
		return err
	}
	if err := temp.Chmod(0o600); err != nil {
		return err
	}

	encrypted, err := age.Encrypt(temp, recipient)
	if err != nil {
		return err
	}
	compressed := gzip.NewWriter(encrypted)
	archive := tar.NewWriter(compressed)

	closeWriters := func() error {
		var firstErr error
		if err := archive.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := compressed.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := encrypted.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		return firstErr
	}

	metadataJSON, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	if err := writeTarEntry(archive, "metadata.json", metadataJSON, 0o600); err != nil {
		return err
	}
	budget := &backupBudget{
		entries:   1,
		total:     int64(len(metadataJSON)),
		pathBytes: int64(len("metadata.json")),
	}
	expectedOmissions := make(map[string]Omission, len(metadata.Omissions))
	for _, omission := range metadata.Omissions {
		expectedOmissions[omission.Path] = omission
	}
	consumedOmissions := make(map[string]struct{}, len(expectedOmissions))
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := os.Lstat(source.HostPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink and cannot be backed up safely", source.HostPath)
		}
		if err := addToArchive(
			ctx,
			archive,
			source,
			budget,
			backupRootInfo,
			expectedOmissions,
			consumedOmissions,
		); err != nil {
			return fmt.Errorf("add %s: %w", source.ArchivePrefix, err)
		}
	}
	if len(consumedOmissions) != len(expectedOmissions) {
		return fmt.Errorf("backup sources changed after omission inspection")
	}

	if err := closeWriters(); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := backupRoot.Link(tempName, archiveName); err != nil {
		return err
	}
	if err := backupRoot.Remove(tempName); err != nil {
		_ = backupRoot.Remove(archiveName)
		return err
	}
	tempName = ""
	if err := syncRootDirectory(backupRoot, "."); err != nil {
		return err
	}
	return nil
}

func addToArchive(
	ctx context.Context,
	archive *tar.Writer,
	source backupSource,
	budget *backupBudget,
	backupRootInfo os.FileInfo,
	expectedOmissions map[string]Omission,
	consumedOmissions map[string]struct{},
) error {
	info, err := os.Lstat(source.HostPath)
	if err != nil {
		return err
	}
	if info.IsDir() {
		root, openedRoot, err := securefs.OpenVerifiedRoot(source.HostPath)
		if err != nil {
			return err
		}
		defer root.Close()
		if os.SameFile(openedRoot, backupRootInfo) {
			return fmt.Errorf("backup source resolves to the managed backup directory")
		}
		return walkBackupRoot(
			ctx,
			archive,
			root,
			".",
			source.ArchivePrefix,
			budget,
			backupRootInfo,
			expectedOmissions,
			consumedOmissions,
		)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", source.HostPath)
	}
	parent, _, err := securefs.OpenVerifiedRoot(filepath.Dir(source.HostPath))
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(source.HostPath)
	before, err := parent.Lstat(name)
	if err != nil {
		return err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return fmt.Errorf("%s is not a real regular file", source.HostPath)
	}
	file, err := parent.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return fmt.Errorf("%s changed while it was being opened", source.HostPath)
	}
	if err := budget.visitNode(); err != nil {
		return err
	}
	return writeOpenFileToArchive(
		ctx,
		archive,
		file,
		source.ArchivePrefix,
		opened,
		budget,
	)
}

func walkBackupRoot(
	ctx context.Context,
	archive *tar.Writer,
	root *os.Root,
	relativeDirectory string,
	archivePrefix string,
	budget *backupBudget,
	backupRootInfo os.FileInfo,
	expectedOmissions map[string]Omission,
	consumedOmissions map[string]struct{},
) error {
	directory, err := root.Open(relativeDirectory)
	if err != nil {
		return err
	}
	defer directory.Close()
	for {
		entries, readErr := directory.Readdir(256)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := budget.visitNode(); err != nil {
				return err
			}
			name := entry.Name()
			relativeName := filepath.Join(relativeDirectory, name)
			before, err := root.Lstat(relativeName)
			if err != nil {
				return err
			}
			archiveName := path.Join(
				archivePrefix,
				filepath.ToSlash(relativeName),
			)
			if before.Mode()&os.ModeSymlink != 0 ||
				before.Mode()&os.ModeSocket != 0 {
				omission, err := inspectOmittableNode(
					root,
					relativeName,
					archiveName,
					before,
				)
				if err != nil {
					return err
				}
				expected, ok := expectedOmissions[archiveName]
				if !ok ||
					expected.Type != omission.Type ||
					expected.Reason != omission.Reason {
					return fmt.Errorf("%s changed after omission inspection", archiveName)
				}
				consumedOmissions[archiveName] = struct{}{}
				continue
			}
			if before.IsDir() {
				child, openErr := root.OpenRoot(relativeName)
				if openErr != nil {
					return openErr
				}
				opened, statErr := child.Stat(".")
				if statErr != nil || !os.SameFile(before, opened) {
					_ = child.Close()
					if statErr != nil {
						return statErr
					}
					return fmt.Errorf("%s changed while it was being opened", archiveName)
				}
				if os.SameFile(opened, backupRootInfo) {
					_ = child.Close()
					return fmt.Errorf(
						"backup source contains the managed backup directory",
					)
				}
				err = walkBackupRoot(
					ctx,
					archive,
					child,
					".",
					archiveName,
					budget,
					backupRootInfo,
					expectedOmissions,
					consumedOmissions,
				)
				closeErr := child.Close()
				if err != nil {
					return err
				}
				if closeErr != nil {
					return closeErr
				}
				continue
			}
			if !before.Mode().IsRegular() {
				return fmt.Errorf("%s is not a regular file", archiveName)
			}
			file, err := root.Open(relativeName)
			if err != nil {
				return err
			}
			opened, statErr := file.Stat()
			if statErr != nil ||
				!opened.Mode().IsRegular() ||
				!os.SameFile(before, opened) {
				_ = file.Close()
				if statErr != nil {
					return statErr
				}
				return fmt.Errorf("%s changed while it was being opened", archiveName)
			}
			err = writeOpenFileToArchive(
				ctx,
				archive,
				file,
				archiveName,
				opened,
				budget,
			)
			_ = file.Close()
			if err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func (b *backupBudget) visitNode() error {
	if b == nil {
		return fmt.Errorf("backup budget is required")
	}
	b.nodes++
	if b.nodes > maxBackupNodes {
		return fmt.Errorf("backup source exceeds %d filesystem entries", maxBackupNodes)
	}
	return nil
}

func (b *backupBudget) reserveFile(name string, size int64) error {
	if b == nil {
		return fmt.Errorf("backup budget is required")
	}
	b.entries++
	if err := validateRestoreEntryCount(b.entries); err != nil {
		return err
	}
	if err := validateRestorePathBudget(name, &b.pathBytes); err != nil {
		return err
	}
	header := &tar.Header{Size: size}
	if err := validateRestoreSize(header, b.total); err != nil {
		return err
	}
	if err := validateManagedRestoreSize(name, size); err != nil {
		return err
	}
	b.total += size
	return nil
}

func writeOpenFileToArchive(
	ctx context.Context,
	archive *tar.Writer,
	file *os.File,
	archiveName string,
	opened os.FileInfo,
	budget *backupBudget,
) error {
	if err := budget.reserveFile(archiveName, opened.Size()); err != nil {
		return err
	}
	header, err := tar.FileInfoHeader(opened, "")
	if err != nil {
		return err
	}
	header.Name = archiveName
	header.Typeflag = tar.TypeReg
	header.Linkname = ""
	// Never carry set-id or group/world-write bits into a restore archive.
	// Existing service files can inherit a permissive umask, but a backup must
	// normalize them before the restore policy validates its own output.
	header.Mode &= 0o755
	if err := archive.WriteHeader(header); err != nil {
		return err
	}
	written, err := io.CopyN(
		archive,
		&contextReader{ctx: ctx, reader: file},
		opened.Size(),
	)
	if err != nil {
		return err
	}
	if written != opened.Size() {
		return fmt.Errorf("%s changed size while it was being archived", archiveName)
	}
	var probe [1]byte
	probeLength, probeErr := file.Read(probe[:])
	if probeLength != 0 || (probeErr != nil && !errors.Is(probeErr, io.EOF)) {
		return fmt.Errorf("%s grew while it was being archived", archiveName)
	}
	after, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(opened, after) || after.Size() != opened.Size() {
		return fmt.Errorf("%s changed while it was being archived", archiveName)
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

func writeTarEntry(archive *tar.Writer, name string, data []byte, mode int64) error {
	header := &tar.Header{
		Name:     name,
		Mode:     mode,
		Size:     int64(len(data)),
		ModTime:  time.Now().UTC(),
		Typeflag: tar.TypeReg,
	}
	if err := archive.WriteHeader(header); err != nil {
		return err
	}
	_, err := archive.Write(data)
	return err
}

// List does not decrypt archives. It exposes only filesystem metadata so
// listing never requires a private identity and encrypted metadata stays
// confidential.
func (m *Manager) List(ctx context.Context) ([]*Backup, error) {
	entries, err := os.ReadDir(m.backupDir)
	if errors.Is(err, os.ErrNotExist) {
		return []*Backup{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read backup directory: %w", err)
	}
	backups := make([]*Backup, 0)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.IsDir() || ValidateBackupName(entry.Name()) != nil {
			continue
		}
		backupPath := filepath.Join(m.backupDir, entry.Name())
		info, err := os.Lstat(backupPath)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		backups = append(backups, &Backup{
			Name: entry.Name(),
			Path: backupPath,
			Metadata: Metadata{
				Version:   "2.0.0",
				Timestamp: info.ModTime().UTC(),
				ProjectID: filepath.Base(m.projectDir),
			},
		})
	}
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].Metadata.Timestamp.After(backups[j].Metadata.Timestamp)
	})
	return backups, nil
}

// Restore validates and stages the complete decrypted archive before promoting
// any file. Promotion is journaled and rolls back the entire managed set on an
// ordinary failure; an interrupted transaction is recovered before the next
// restore starts.
func (m *Manager) Restore(ctx context.Context, backupName string, options DecryptOptions) error {
	return m.RestoreWithHooks(ctx, backupName, options, RestoreHooks{})
}

// RestoreWithHooks keeps the restore transaction open through trusted
// post-promotion validation.
func (m *Manager) RestoreWithHooks(
	ctx context.Context,
	backupName string,
	options DecryptOptions,
	hooks RestoreHooks,
) error {
	if err := recoverRestoreTransaction(m.projectDir); err != nil {
		return fmt.Errorf("recover interrupted restore: %w", err)
	}
	identities, err := decryptionIdentities(options)
	if err != nil {
		return err
	}
	if _, err := secureBackupPath(m.backupDir, backupName); err != nil {
		return err
	}
	backupRoot, _, err := securefs.OpenVerifiedRoot(m.backupDir)
	if err != nil {
		return fmt.Errorf("open backup directory: %w", err)
	}
	defer backupRoot.Close()
	info, err := backupRoot.Lstat(backupName)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("backup not found: %s", backupName)
	}
	if err != nil {
		return fmt.Errorf("inspect backup: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("backup must be a regular file, not a symlink or special file")
	}
	file, err := backupRoot.Open(backupName)
	if err != nil {
		return fmt.Errorf("open backup: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect open backup: %w", err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return fmt.Errorf("backup changed while it was being opened")
	}

	if err := validateArchive(ctx, file, identities); err != nil {
		return fmt.Errorf("validate encrypted backup: %w", err)
	}
	targets, err := m.resolveRestoreTargets(hooks.VerifiedRoots)
	if err != nil {
		return err
	}
	if err := applyArchiveTransactional(
		ctx,
		file,
		identities,
		targets,
		m.restoreHook,
		hooks,
	); err != nil {
		return fmt.Errorf("restore encrypted backup: %w", err)
	}
	return nil
}

type restoreTargets struct {
	projectPath string
	configPath  string
	secretsPath string
}

type restoreRoots struct {
	project     *os.Root
	config      *os.Root
	secrets     *os.Root
	projectPath string
	configPath  string
	secretsPath string
}

func (m *Manager) resolveRestoreTargets(verifiedRoots *ManagedRoots) (restoreTargets, error) {
	var roots ManagedRoots
	if verifiedRoots == nil {
		pc, err := readPathConfig(m.projectDir)
		if err != nil {
			return restoreTargets{}, err
		}
		roots = ManagedRoots{
			ConfigPath:  pc.ConfigPath,
			SecretsPath: pc.SecretsPath,
		}
	} else {
		roots = *verifiedRoots
	}
	configPath, err := resolveConfiguredRoot(m.projectDir, roots.ConfigPath, "configs")
	if err != nil {
		return restoreTargets{}, fmt.Errorf("resolve config restore root: %w", err)
	}
	secretsPath, err := resolveConfiguredRoot(m.projectDir, roots.SecretsPath, "secrets")
	if err != nil {
		return restoreTargets{}, fmt.Errorf("resolve secrets restore root: %w", err)
	}
	projectPath, err := filepath.Abs(m.projectDir)
	if err != nil {
		return restoreTargets{}, err
	}
	configPath, err = filepath.Abs(configPath)
	if err != nil {
		return restoreTargets{}, err
	}
	secretsPath, err = filepath.Abs(secretsPath)
	if err != nil {
		return restoreTargets{}, err
	}
	targets := restoreTargets{
		projectPath: filepath.Clean(projectPath),
		configPath:  filepath.Clean(configPath),
		secretsPath: filepath.Clean(secretsPath),
	}
	if err := validateRestoreTargetPaths(targets); err != nil {
		return restoreTargets{}, err
	}
	return targets, nil
}

func validateRestoreTargetPaths(targets restoreTargets) error {
	projectPath := targets.projectPath
	configPath := targets.configPath
	secretsPath := targets.secretsPath
	if !filepath.IsAbs(projectPath) ||
		!filepath.IsAbs(configPath) ||
		!filepath.IsAbs(secretsPath) {
		return fmt.Errorf("restore roots must be absolute")
	}
	if filepath.Dir(projectPath) == projectPath ||
		filepath.Dir(configPath) == configPath ||
		filepath.Dir(secretsPath) == secretsPath {
		return fmt.Errorf("restore roots must not be filesystem roots")
	}
	if configPath == projectPath || secretsPath == projectPath {
		return fmt.Errorf("config and secrets restore roots must not equal the project root")
	}
	if pathWithin(configPath, projectPath) || pathWithin(secretsPath, projectPath) {
		return fmt.Errorf("config and secrets restore roots must not contain the project root")
	}
	if configPath == secretsPath {
		return fmt.Errorf("config and secrets restore roots must be distinct")
	}
	if pathsOverlap(configPath, secretsPath) {
		return fmt.Errorf("config and secrets restore roots must not overlap")
	}
	return nil
}

func openRestoreRootsAt(
	projectPath, configPath, secretsPath string,
	createManagedRoots bool,
) (*restoreRoots, error) {
	var err error
	projectPath, err = filepath.Abs(projectPath)
	if err != nil {
		return nil, err
	}
	configPath, err = filepath.Abs(configPath)
	if err != nil {
		return nil, err
	}
	secretsPath, err = filepath.Abs(secretsPath)
	if err != nil {
		return nil, err
	}
	projectPath = filepath.Clean(projectPath)
	configPath = filepath.Clean(configPath)
	secretsPath = filepath.Clean(secretsPath)
	if err := validateRestoreTargetPaths(restoreTargets{
		projectPath: projectPath,
		configPath:  configPath,
		secretsPath: secretsPath,
	}); err != nil {
		return nil, err
	}
	if err := ensureRestoreRoot(projectPath, false, 0o755); err != nil {
		return nil, err
	}
	if err := ensureRestoreRoot(configPath, createManagedRoots, 0o755); err != nil {
		return nil, err
	}
	if err := ensureRestoreRoot(secretsPath, createManagedRoots, 0o700); err != nil {
		return nil, err
	}
	projectRoot, _, err := securefs.OpenVerifiedRoot(projectPath)
	if err != nil {
		return nil, err
	}
	configRoot, _, err := securefs.OpenVerifiedRoot(configPath)
	if err != nil {
		_ = projectRoot.Close()
		return nil, err
	}
	secretsRoot, _, err := securefs.OpenVerifiedRoot(secretsPath)
	if err != nil {
		_ = projectRoot.Close()
		_ = configRoot.Close()
		return nil, err
	}
	return &restoreRoots{
		project:     projectRoot,
		config:      configRoot,
		secrets:     secretsRoot,
		projectPath: projectPath,
		configPath:  configPath,
		secretsPath: secretsPath,
	}, nil
}

func ensureRestoreRoot(rootPath string, create bool, mode os.FileMode) error {
	info, err := os.Lstat(rootPath)
	if errors.Is(err, os.ErrNotExist) && create {
		return securefs.EnsureDir(rootPath, mode.Perm())
	}
	if err != nil {
		return fmt.Errorf("inspect restore root %s: %w", rootPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("restore root %s must be a real directory", rootPath)
	}
	return nil
}

func pathsOverlap(first, second string) bool {
	return pathWithin(first, second) || pathWithin(second, first)
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return relative == "." ||
		(relative != ".." && !strings.HasPrefix(
			relative,
			".."+string(filepath.Separator),
		))
}

func (r *restoreRoots) Close() {
	_ = r.project.Close()
	_ = r.config.Close()
	_ = r.secrets.Close()
}

func validateArchive(ctx context.Context, file *os.File, identities []age.Identity) error {
	archive, closeReader, err := openArchive(file, identities)
	if err != nil {
		return err
	}
	readerClosed := false
	defer func() {
		if !readerClosed {
			_ = closeReader(false)
		}
	}()

	seen := make(map[string]struct{})
	var entries int
	var total int64
	var pathBytes int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		entries++
		if err := validateRestoreEntryCount(entries); err != nil {
			return err
		}
		cleaned, err := validateArchiveHeader(header, entries == 1)
		if err != nil {
			return err
		}
		if err := validateRestorePathBudget(cleaned, &pathBytes); err != nil {
			return err
		}
		if _, duplicate := seen[cleaned]; duplicate {
			return fmt.Errorf("archive contains duplicate entry %q", cleaned)
		}
		seen[cleaned] = struct{}{}
		if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
			if err := validateRestoreSize(header, total); err != nil {
				return fmt.Errorf("entry %q: %w", cleaned, err)
			}
			if err := validateManagedRestoreSize(cleaned, header.Size); err != nil {
				return fmt.Errorf("entry %q: %w", cleaned, err)
			}
			total += header.Size
			if cleaned == "metadata.json" {
				if header.Size > maxMetadataBytes {
					return fmt.Errorf("metadata exceeds %d bytes", maxMetadataBytes)
				}
			}
			if cleaned == "metadata.json" {
				data, err := readExactRestoreEntry(ctx, archive, header.Size)
				if err != nil {
					return fmt.Errorf("read metadata: %w", err)
				}
				var metadata Metadata
				if err := json.Unmarshal(data, &metadata); err != nil {
					return fmt.Errorf("invalid metadata: %w", err)
				}
				if metadata.Version != "2.0.0" {
					return fmt.Errorf("unsupported backup metadata version %q", metadata.Version)
				}
			} else if err := discardExactRestoreEntry(ctx, archive, header.Size); err != nil {
				return fmt.Errorf("read entry %q: %w", cleaned, err)
			}
		}
	}
	if entries == 0 {
		return fmt.Errorf("archive is empty")
	}
	if err := closeReader(true); err != nil {
		return fmt.Errorf("finish encrypted archive: %w", err)
	}
	readerClosed = true
	return nil
}

func validateRestoreEntryCount(entries int) error {
	if entries < 0 || entries > maxRestoreEntries {
		return fmt.Errorf("archive exceeds %d entries", maxRestoreEntries)
	}
	return nil
}

func validateArchiveHeader(header *tar.Header, first bool) (string, error) {
	cleaned, err := safeArchivePath(header.Name)
	if err != nil {
		return "", fmt.Errorf("invalid archive path %q: %w", header.Name, err)
	}
	if first && cleaned != "metadata.json" {
		return "", fmt.Errorf("first archive entry must be metadata.json")
	}
	if !first && cleaned == "metadata.json" {
		return "", fmt.Errorf("metadata.json must be the first archive entry")
	}
	if !allowedArchivePath(cleaned) {
		return "", fmt.Errorf("archive entry %q is outside the backup allowlist", cleaned)
	}
	switch header.Typeflag {
	case tar.TypeReg, tar.TypeRegA:
	default:
		return "", fmt.Errorf("unsupported archive entry type for %q", cleaned)
	}
	if cleaned == "configs" || cleaned == "secrets" {
		return "", fmt.Errorf("archive root %q must be represented by contained files", cleaned)
	}
	if header.Mode < 0 ||
		header.Mode&^0o777 != 0 ||
		header.Mode&0o022 != 0 ||
		header.Mode&0o400 == 0 {
		return "", fmt.Errorf("unsafe mode %04o for %q", header.Mode, cleaned)
	}
	return cleaned, nil
}

func validateRestorePathBudget(name string, total *int64) error {
	if len(name) > maxArchivePathLength {
		return fmt.Errorf("archive path exceeds %d bytes", maxArchivePathLength)
	}
	if total == nil || *total < 0 || int64(len(name)) > maxArchivePathBytes-*total {
		return fmt.Errorf("archive paths exceed the %d-byte restore limit", maxArchivePathBytes)
	}
	*total += int64(len(name))
	return nil
}

func validateRestoreSize(header *tar.Header, currentTotal int64) error {
	if header.Size < 0 || header.Size > maxRestoreFileBytes {
		return fmt.Errorf("declared size exceeds the per-file limit")
	}
	if currentTotal < 0 || currentTotal > maxRestoreTotalBytes-header.Size {
		return fmt.Errorf("archive exceeds the %d-byte restore limit", maxRestoreTotalBytes)
	}
	return nil
}

func validateManagedRestoreSize(name string, size int64) error {
	var limit int64
	switch name {
	case "metadata.json":
		limit = maxMetadataBytes
	case ".sdbx.yaml", ".env":
		limit = maxProjectConfigBytes
	case ".sdbx.lock", "compose.yaml":
		limit = 16 << 20
	default:
		return nil
	}
	if size > limit {
		return fmt.Errorf("managed project file exceeds %d bytes", limit)
	}
	return nil
}

func safeArchivePath(name string) (string, error) {
	if name == "" || !utf8.ValidString(name) || strings.Contains(name, "\\") {
		return "", fmt.Errorf("path must be a valid non-empty slash path")
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return "", fmt.Errorf("path contains control characters")
		}
	}
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("absolute paths are not allowed")
	}
	cleaned := path.Clean(name)
	if cleaned != name || cleaned == "." || cleaned == ".." ||
		strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("path is not canonical or escapes the archive root")
	}
	return cleaned, nil
}

func allowedArchivePath(name string) bool {
	switch name {
	case "metadata.json", ".sdbx.yaml", ".sdbx.lock", "compose.yaml", ".env",
		"configs", "secrets":
		return true
	}
	return strings.HasPrefix(name, "configs/") || strings.HasPrefix(name, "secrets/")
}

func openArchive(
	file *os.File,
	identities []age.Identity,
) (*tar.Reader, func(bool) error, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, nil, err
	}
	decrypted, err := age.Decrypt(file, identities...)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt age archive: %w", err)
	}
	compressed, err := gzip.NewReader(decrypted)
	if err != nil {
		return nil, nil, fmt.Errorf("open compressed archive: %w", err)
	}
	return tar.NewReader(compressed), func(finish bool) error {
		var finishErr error
		if finish {
			var drained int64
			drained, finishErr = io.CopyN(
				io.Discard,
				compressed,
				maxRestoreTrailing+1,
			)
			if errors.Is(finishErr, io.EOF) {
				finishErr = nil
			}
			if drained > maxRestoreTrailing {
				finishErr = fmt.Errorf(
					"compressed archive has more than %d trailing bytes",
					maxRestoreTrailing,
				)
			}
		}
		return errors.Join(finishErr, compressed.Close())
	}, nil
}

func ensureRootParentsNoSymlink(root *os.Root, name string) error {
	current := filepath.Dir(name)
	var components []string
	for current != "." && current != "" {
		components = append(components, current)
		next := filepath.Dir(current)
		if next == current {
			break
		}
		current = next
	}
	for i := len(components) - 1; i >= 0; i-- {
		info, err := root.Lstat(components[i])
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("restore parent %q is a symlink or non-directory", components[i])
		}
	}
	return nil
}

func (m *Manager) Delete(ctx context.Context, backupName string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := secureBackupPath(m.backupDir, backupName); err != nil {
		return err
	}
	backupRoot, _, err := securefs.OpenVerifiedRoot(m.backupDir)
	if err != nil {
		return fmt.Errorf("open backup directory: %w", err)
	}
	defer backupRoot.Close()
	info, err := backupRoot.Lstat(backupName)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("backup not found: %s", backupName)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("backup must be a regular file")
	}
	if err := backupRoot.Remove(backupName); err != nil {
		return fmt.Errorf("delete backup: %w", err)
	}
	return syncRootDirectory(backupRoot, ".")
}

func secureBackupPath(backupDir, backupName string) (string, error) {
	if err := ValidateBackupName(backupName); err != nil {
		return "", err
	}
	return filepath.Join(backupDir, backupName), nil
}

// ValidateBackupName rejects path and terminal-control syntax before a backup
// name is discovered, displayed, or resolved.
func ValidateBackupName(backupName string) error {
	if backupName == "" || strings.ContainsAny(backupName, `/\`) {
		return fmt.Errorf("backup name must be a base filename")
	}
	if filepath.Base(backupName) != backupName || !strings.HasSuffix(backupName, backupSuffix) {
		return fmt.Errorf("backup name must end with %s", backupSuffix)
	}
	if !utf8.ValidString(backupName) {
		return fmt.Errorf("backup name must be valid UTF-8")
	}
	for _, character := range backupName {
		if unicode.IsControl(character) || unicode.Is(unicode.Bidi_Control, character) {
			return fmt.Errorf("backup name must not contain terminal control characters")
		}
	}
	return nil
}

func (b *Backup) GetSize() (int64, error) {
	info, err := os.Lstat(b.Path)
	if err != nil {
		return 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return 0, fmt.Errorf("backup must be a regular file")
	}
	return info.Size(), nil
}
