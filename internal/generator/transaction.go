package generator

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/integrate"
	"github.com/get-sdbx/sdbx/internal/registry"
	"github.com/get-sdbx/sdbx/internal/securefs"
)

const (
	projectTransactionDirName = ".sdbx-init-transaction"
	transactionManifestName   = "manifest.json"
	transactionSchemaVersion  = 3
	digestTransactionVersion  = 2
	legacyTransactionVersion  = 1
	transactionFileLimit      = 16 << 20
)

type ProjectTransactionOptions struct {
	// ValidateStage runs after the complete staged tree has been generated and
	// before any destination file is changed.
	ValidateStage func(projectDir string) error
	// RuntimeOnly stages generated runtime policy plus .sdbx.lock without
	// rewriting initializer-only static configuration.
	RuntimeOnly bool
}

type transactionManifest struct {
	Version      int                `json:"version"`
	State        string             `json:"state"`
	ProjectRoot  string             `json:"project_root"`
	SecretsRoot  string             `json:"secrets_root"`
	AllowedRoots []string           `json:"allowed_roots"`
	Entries      []transactionEntry `json:"entries"`
}

type transactionEntry struct {
	Kind         string `json:"kind"`
	Source       string `json:"source"`
	Target       string `json:"target"`
	Backup       string `json:"backup,omitempty"`
	Existed      bool   `json:"existed"`
	OriginalMode uint32 `json:"original_mode,omitempty"`
	OriginalUID  *int   `json:"original_uid,omitempty"`
	OriginalGID  *int   `json:"original_gid,omitempty"`
	DesiredMode  uint32 `json:"desired_mode"`
	StagedDigest string `json:"staged_digest,omitempty"`
	BackupDigest string `json:"backup_digest,omitempty"`
}

// ProjectTransactionPending reports whether an interrupted initializer journal
// exists. It does not mutate or recover it.
func ProjectTransactionPending(projectDir string) (bool, error) {
	root, err := filepath.Abs(projectDir)
	if err != nil {
		return false, err
	}
	_, err = os.Lstat(filepath.Join(root, projectTransactionDirName))
	switch {
	case err == nil:
		return true, nil
	case os.IsNotExist(err):
		return false, nil
	default:
		return false, err
	}
}

// RecoverProjectTransaction restores every destination from a private
// interrupted transaction journal. A committed journal only needs cleanup.
func RecoverProjectTransaction(projectDir string) error {
	projectRoot, err := filepath.Abs(projectDir)
	if err != nil {
		return fmt.Errorf("resolve project root: %w", err)
	}
	transactionRoot := filepath.Join(projectRoot, projectTransactionDirName)
	info, err := os.Lstat(transactionRoot)
	switch {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return fmt.Errorf("inspect initializer transaction: %w", err)
	}
	if err := validatePrivateTransactionDir(info, transactionRoot); err != nil {
		return err
	}

	manifestPath := filepath.Join(transactionRoot, transactionManifestName)
	data, err := securefs.ReadRegularFile(manifestPath, 4<<20)
	if os.IsNotExist(err) {
		// A crash during staging cannot have changed a destination because the
		// journal is written before promotion begins.
		return removeTransactionDir(transactionRoot)
	}
	if err != nil {
		return fmt.Errorf("read initializer transaction journal: %w", err)
	}
	var manifest transactionManifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return fmt.Errorf("parse initializer transaction journal: %w", err)
	}
	if err := validateTransactionManifest(&manifest, projectRoot, transactionRoot); err != nil {
		return err
	}
	if manifest.State != "committed" {
		if err := rollbackTransaction(&manifest); err != nil {
			return fmt.Errorf("recover interrupted initializer transaction: %w", err)
		}
	}
	return removeTransactionDir(transactionRoot)
}

// GenerateProjectTransactional generates a complete project in a private stage,
// validates it, journals every destination, and promotes each file atomically.
// Any error restores the exact pre-operation file contents and modes.
func GenerateProjectTransactional(
	cfg *config.Config,
	projectDir string,
	reg *registry.Registry,
	lock *registry.LockFile,
	cliVersion string,
	options ProjectTransactionOptions,
) (err error) {
	if cfg == nil || reg == nil || lock == nil {
		return fmt.Errorf("configuration, registry, and lock are required")
	}
	projectRoot, err := filepath.Abs(projectDir)
	if err != nil {
		return fmt.Errorf("resolve project root: %w", err)
	}
	if err := RecoverProjectTransaction(projectRoot); err != nil {
		return err
	}

	configTarget := resolveTransactionRoot(projectRoot, cfg.ConfigPath, "configs")
	secretsTarget := resolveTransactionRoot(projectRoot, cfg.SecretsPath, "secrets")
	if pathsOverlap(configTarget, secretsTarget) {
		return fmt.Errorf("config_path and secrets_path must not overlap")
	}

	transactionRoot := filepath.Join(projectRoot, projectTransactionDirName)
	if err := os.Mkdir(transactionRoot, 0o700); err != nil {
		return fmt.Errorf("create initializer transaction: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = removeTransactionDir(transactionRoot)
		}
	}()

	stageRoot := filepath.Join(transactionRoot, "stage")
	stageProject := filepath.Join(stageRoot, "project")
	if err := securefs.EnsureDir(stageProject, 0o700); err != nil {
		return err
	}
	stageConfig, configExternal := transactionStageRoot(
		stageProject,
		stageRoot,
		cfg.ConfigPath,
		"configs",
		"external-config",
	)
	stageSecrets, secretsExternal := transactionStageRoot(
		stageProject,
		stageRoot,
		cfg.SecretsPath,
		"secrets",
		"external-secrets",
	)
	if err := securefs.EnsureDir(stageConfig, 0o755); err != nil {
		return err
	}
	if err := securefs.EnsureDir(stageSecrets, 0o700); err != nil {
		return err
	}
	if err := seedTransactionState(
		cfg,
		configTarget,
		secretsTarget,
		stageConfig,
		stageSecrets,
	); err != nil {
		return err
	}

	stagedGenerator := NewGeneratorWithLock(
		cfg,
		stageProject,
		reg,
		lock,
		cliVersion,
	).WithManagedRoots(
		stageConfig,
		stageSecrets,
	).WithDeferredVolumeOwnership()
	if options.RuntimeOnly {
		err = stagedGenerator.GenerateRuntimeFiles()
	} else {
		err = stagedGenerator.Generate()
	}
	if err != nil {
		return fmt.Errorf("generate staged project: %w", err)
	}
	if err := registry.NewLoader().SaveLockFile(
		filepath.Join(stageProject, ".sdbx.lock"),
		lock,
	); err != nil {
		return fmt.Errorf("save staged lock: %w", err)
	}
	if options.ValidateStage != nil {
		if err := options.ValidateStage(stageProject); err != nil {
			return fmt.Errorf("validate staged project: %w", err)
		}
	}
	targetGenerator := NewGeneratorWithLock(
		cfg,
		projectRoot,
		reg,
		lock,
		cliVersion,
	).WithManagedRoots(configTarget, secretsTarget)
	targetGraph, err := targetGenerator.Plan()
	if err != nil {
		return fmt.Errorf("plan promoted runtime ownership: %w", err)
	}

	roots := []transactionRootMapping{
		{Stage: stageProject, Target: projectRoot, IncludeRoot: false},
	}
	if configExternal {
		roots = append(roots, transactionRootMapping{
			Stage: stageConfig, Target: configTarget, IncludeRoot: true,
		})
	}
	if secretsExternal {
		roots = append(roots, transactionRootMapping{
			Stage: stageSecrets, Target: secretsTarget, IncludeRoot: true,
		})
	}
	var dataTargets []string
	if !options.RuntimeOnly {
		dataTargets = transactionDataDirectories(projectRoot, cfg)
		dataStageRoot := filepath.Join(stageRoot, "data-directories")
		if err := securefs.EnsureDir(dataStageRoot, 0o700); err != nil {
			return err
		}
		for index, target := range dataTargets {
			stageDir := filepath.Join(dataStageRoot, fmt.Sprintf("%06d", index))
			if err := securefs.EnsureDir(stageDir, 0o755); err != nil {
				return err
			}
			roots = append(roots, transactionRootMapping{
				Stage: stageDir, Target: target, IncludeRoot: true,
			})
		}
	}
	entries, err := prepareTransactionEntries(
		transactionRoot,
		roots,
		secretsTarget,
	)
	if err != nil {
		return err
	}
	manifest := transactionManifest{
		Version:     transactionSchemaVersion,
		State:       "prepared",
		ProjectRoot: projectRoot,
		SecretsRoot: secretsTarget,
		AllowedRoots: uniqueCleanPaths(append(
			[]string{projectRoot, configTarget, secretsTarget},
			dataTargets...,
		)),
		Entries: entries,
	}
	if err := validateTransactionManifest(&manifest, projectRoot, transactionRoot); err != nil {
		return err
	}
	if err := writeTransactionManifest(transactionRoot, &manifest); err != nil {
		return err
	}

	manifest.State = "promoting"
	if err := writeTransactionManifest(transactionRoot, &manifest); err != nil {
		return err
	}
	if err := applyTransaction(&manifest); err != nil {
		rollbackErr := rollbackTransaction(&manifest)
		if rollbackErr != nil {
			cleanup = false
			return errors.Join(err, fmt.Errorf("rollback failed: %w", rollbackErr))
		}
		return err
	}
	if err := repairTransactionManagedFileOwnership(cfg, configTarget); err != nil {
		rollbackErr := rollbackTransaction(&manifest)
		if rollbackErr != nil {
			cleanup = false
			return errors.Join(err, fmt.Errorf("rollback failed: %w", rollbackErr))
		}
		return err
	}
	if err := targetGenerator.applyVolumeOwnership(targetGraph); err != nil {
		rollbackErr := rollbackTransaction(&manifest)
		if rollbackErr != nil {
			cleanup = false
			return errors.Join(err, fmt.Errorf("rollback failed: %w", rollbackErr))
		}
		return fmt.Errorf("prepare promoted runtime ownership: %w", err)
	}
	manifest.State = "committed"
	if err := writeTransactionManifest(transactionRoot, &manifest); err != nil {
		cleanup = false
		return fmt.Errorf("record committed initializer transaction: %w", err)
	}
	return nil
}

type transactionRootMapping struct {
	Stage       string
	Target      string
	IncludeRoot bool
}

func resolveTransactionRoot(projectRoot, configured, fallback string) string {
	if configured == "" {
		configured = fallback
	}
	if filepath.IsAbs(configured) {
		return filepath.Clean(configured)
	}
	return filepath.Join(projectRoot, filepath.Clean(configured))
}

func transactionStageRoot(
	stageProject, stageRoot, configured, fallback, externalName string,
) (string, bool) {
	if configured == "" {
		configured = fallback
	}
	if filepath.IsAbs(configured) {
		return filepath.Join(stageRoot, externalName), true
	}
	return filepath.Join(stageProject, filepath.Clean(configured)), false
}

func transactionDataDirectories(projectRoot string, cfg *config.Config) []string {
	dataRoot := resolveTransactionRoot(projectRoot, cfg.DataPath, "data")
	downloadsRoot := resolveTransactionRoot(
		projectRoot,
		cfg.DownloadsPath,
		filepath.Join("data", "downloads"),
	)
	mediaRoot := resolveTransactionRoot(
		projectRoot,
		cfg.MediaPath,
		filepath.Join("data", "media"),
	)
	directories := []string{
		dataRoot,
		filepath.Join(dataRoot, "authelia"),
		downloadsRoot,
		mediaRoot,
		filepath.Join(mediaRoot, "movies"),
		filepath.Join(mediaRoot, "tv"),
		filepath.Join(mediaRoot, "music"),
		filepath.Join(mediaRoot, "books"),
	}
	if cfg.VPNEnabled {
		directories = append(directories, filepath.Join(dataRoot, "gluetun"))
	}
	return uniqueCleanPaths(directories)
}

func seedTransactionState(
	cfg *config.Config,
	configTarget, secretsTarget, stageConfig, stageSecrets string,
) error {
	if err := copyExistingSecrets(secretsTarget, stageSecrets); err != nil {
		return err
	}
	if cfg.Expose.Mode == config.ExposeModeDirect {
		if err := copyExistingTransactionFile(
			filepath.Join(configTarget, "traefik", "acme.json"),
			filepath.Join(stageConfig, "traefik", "acme.json"),
			transactionFileLimit,
		); err != nil {
			return fmt.Errorf("stage existing Traefik ACME state: %w", err)
		}
	}
	for _, service := range integrate.EnabledArrs(cfg) {
		if err := copyExistingTransactionFile(
			filepath.Join(configTarget, service, "config.xml"),
			filepath.Join(stageConfig, service, "config.xml"),
			transactionFileLimit,
		); err != nil {
			return fmt.Errorf("stage existing %s config.xml: %w", service, err)
		}
	}
	return nil
}

func copyExistingSecrets(sourceDir, targetDir string) error {
	entries, err := os.ReadDir(sourceDir)
	switch {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return fmt.Errorf("read existing secrets: %w", err)
	}
	if len(entries) > 1024 {
		return fmt.Errorf("existing secrets directory exceeds 1024 entries")
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf(
				"existing secret %s must be a regular file, not a directory or symlink",
				entry.Name(),
			)
		}
		if err := copyExistingTransactionFile(
			filepath.Join(sourceDir, entry.Name()),
			filepath.Join(targetDir, entry.Name()),
			1<<20,
		); err != nil {
			return fmt.Errorf("stage existing secret %s: %w", entry.Name(), err)
		}
	}
	return nil
}

func copyExistingTransactionFile(source, target string, maxBytes int64) error {
	info, err := os.Lstat(source)
	switch {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file, not a symlink or special file", source)
	}
	data, err := securefs.ReadRegularFile(source, maxBytes)
	if err != nil {
		return err
	}
	return securefs.WriteFileAtomicPreserveDir(target, data, 0o700, info.Mode().Perm())
}

func prepareTransactionEntries(
	transactionRoot string,
	roots []transactionRootMapping,
	secretsRoot string,
) ([]transactionEntry, error) {
	var entries []transactionEntry
	seenTargets := make(map[string]struct{})
	rollbackRoot := filepath.Join(transactionRoot, "rollback")
	if err := securefs.EnsureDir(rollbackRoot, 0o700); err != nil {
		return nil, err
	}
	for _, mapping := range roots {
		err := filepath.WalkDir(mapping.Stage, func(path string, item fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if path == mapping.Stage && !mapping.IncludeRoot {
				return nil
			}
			info, err := item.Info()
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("staged path %s must not be a symlink", path)
			}
			kind := "dir"
			if !info.IsDir() {
				if !info.Mode().IsRegular() {
					return fmt.Errorf("staged path %s must be a regular file or directory", path)
				}
				if info.Size() > transactionFileLimit {
					return fmt.Errorf("staged file %s exceeds %d bytes", path, transactionFileLimit)
				}
				kind = "file"
			}
			relative, err := filepath.Rel(mapping.Stage, path)
			if err != nil {
				return err
			}
			target := mapping.Target
			if relative != "." {
				target = filepath.Join(mapping.Target, relative)
			}
			target = filepath.Clean(target)
			if _, duplicate := seenTargets[target]; duplicate {
				return fmt.Errorf("duplicate transaction target %s", target)
			}
			seenTargets[target] = struct{}{}

			entry := transactionEntry{
				Kind:        kind,
				Source:      path,
				Target:      target,
				DesiredMode: uint32(info.Mode().Perm()),
			}
			if kind == "file" {
				entry.StagedDigest, err = transactionFileDigest(path)
				if err != nil {
					return fmt.Errorf("digest staged file %s: %w", path, err)
				}
			}
			if pathWithin(secretsRoot, target) {
				if kind == "dir" {
					entry.DesiredMode = 0o700
				}
			}
			existing, err := os.Lstat(target)
			switch {
			case err == nil:
				if existing.Mode()&os.ModeSymlink != 0 {
					return fmt.Errorf("transaction target %s must not be a symlink", target)
				}
				if kind == "dir" && !existing.IsDir() {
					return fmt.Errorf("transaction target %s must be a directory", target)
				}
				if kind == "file" && !existing.Mode().IsRegular() {
					return fmt.Errorf("transaction target %s must be a regular file", target)
				}
				entry.Existed = true
				entry.OriginalMode = uint32(existing.Mode().Perm())
				if kind == "file" {
					if stat, ok := existing.Sys().(*syscall.Stat_t); ok {
						uid := int(stat.Uid)
						gid := int(stat.Gid)
						entry.OriginalUID = &uid
						entry.OriginalGID = &gid
					}
					backup := filepath.Join(
						rollbackRoot,
						fmt.Sprintf("%06d", len(entries)),
					)
					if err := copyExistingTransactionFile(
						target,
						backup,
						transactionFileLimit,
					); err != nil {
						return fmt.Errorf("backup %s: %w", target, err)
					}
					entry.Backup = backup
					entry.BackupDigest, err = transactionFileDigest(backup)
					if err != nil {
						return fmt.Errorf("digest backup for %s: %w", target, err)
					}
				}
			case !os.IsNotExist(err):
				return err
			}
			entries = append(entries, entry)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Kind != entries[j].Kind {
			return entries[i].Kind == "dir"
		}
		return pathDepth(entries[i].Target) < pathDepth(entries[j].Target)
	})
	return entries, nil
}

func repairTransactionManagedFileOwnership(
	cfg *config.Config,
	configRoot string,
) error {
	for _, service := range integrate.EnabledArrs(cfg) {
		relative := filepath.Join(service, "config.xml")
		if err := securefs.RepairRegularFileMetadataAt(
			configRoot,
			relative,
			0o600,
			cfg.PUID,
			cfg.PGID,
		); err != nil {
			return fmt.Errorf(
				"repair promoted %s ownership: %w",
				service,
				err,
			)
		}
	}
	return nil
}

func applyTransaction(manifest *transactionManifest) error {
	for _, entry := range manifest.Entries {
		mode := os.FileMode(entry.DesiredMode).Perm()
		switch entry.Kind {
		case "dir":
			if err := securefs.EnsureDir(entry.Target, mode); err != nil {
				return fmt.Errorf("promote directory %s: %w", entry.Target, err)
			}
		case "file":
			if err := verifyTransactionFileDigest(
				entry.Source,
				entry.StagedDigest,
			); err != nil {
				return fmt.Errorf("verify staged file %s: %w", entry.Source, err)
			}
			data, err := securefs.ReadRegularFile(entry.Source, transactionFileLimit)
			if err != nil {
				return fmt.Errorf("read staged file %s: %w", entry.Source, err)
			}
			dirMode := os.FileMode(0o755)
			if pathWithin(manifest.SecretsRoot, entry.Target) {
				dirMode = 0o700
			}
			if err := securefs.WriteFileAtomicPreserveDir(
				entry.Target,
				data,
				dirMode,
				mode,
			); err != nil {
				return fmt.Errorf("promote file %s: %w", entry.Target, err)
			}
			if err := verifyTransactionFileDigest(
				entry.Target,
				entry.StagedDigest,
			); err != nil {
				return fmt.Errorf("verify promoted file %s: %w", entry.Target, err)
			}
		default:
			return fmt.Errorf("unsupported transaction entry kind %q", entry.Kind)
		}
	}
	return nil
}

func rollbackTransaction(manifest *transactionManifest) error {
	var rollbackErrors []error
	for index := len(manifest.Entries) - 1; index >= 0; index-- {
		entry := manifest.Entries[index]
		switch entry.Kind {
		case "file":
			if entry.Existed {
				if err := verifyTransactionFileDigest(
					entry.Backup,
					entry.BackupDigest,
				); err != nil {
					rollbackErrors = append(
						rollbackErrors,
						fmt.Errorf("verify rollback backup for %s: %w", entry.Target, err),
					)
					continue
				}
				data, err := securefs.ReadRegularFile(entry.Backup, transactionFileLimit)
				if err != nil {
					rollbackErrors = append(rollbackErrors, err)
					continue
				}
				if err := restoreTransactionFile(entry, data); err != nil {
					rollbackErrors = append(rollbackErrors, err)
				}
				if err := verifyTransactionFileDigest(
					entry.Target,
					entry.BackupDigest,
				); err != nil {
					rollbackErrors = append(
						rollbackErrors,
						fmt.Errorf("verify restored file %s: %w", entry.Target, err),
					)
				}
			} else if err := removeTransactionTargetFile(entry.Target); err != nil {
				rollbackErrors = append(rollbackErrors, err)
			}
		case "dir":
			if entry.Existed {
				if err := os.Chmod(entry.Target, os.FileMode(entry.OriginalMode).Perm()); err != nil {
					rollbackErrors = append(rollbackErrors, err)
				}
			} else if err := os.Remove(entry.Target); err != nil && !os.IsNotExist(err) {
				rollbackErrors = append(rollbackErrors, err)
			}
		}
	}
	return errors.Join(rollbackErrors...)
}

func restoreTransactionFile(entry transactionEntry, data []byte) error {
	mode := os.FileMode(entry.OriginalMode).Perm()
	if entry.OriginalUID != nil && entry.OriginalGID != nil {
		return securefs.WriteFileAtomicOwnedPreserveDir(
			entry.Target,
			data,
			0o755,
			mode,
			*entry.OriginalUID,
			*entry.OriginalGID,
		)
	}
	return securefs.WriteFileAtomicPreserveDir(
		entry.Target,
		data,
		0o755,
		mode,
	)
}

func removeTransactionTargetFile(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("refusing to remove directory at transaction file target %s", path)
	}
	return os.Remove(path)
}

func transactionFileDigest(path string) (string, error) {
	data, err := securefs.ReadRegularFile(path, transactionFileLimit)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum), nil
}

func verifyTransactionFileDigest(path, expected string) error {
	// Version-1 journals did not record digests. They remain recoverable so an
	// upgrade cannot strand an already interrupted transaction.
	if expected == "" {
		return nil
	}
	actual, err := transactionFileDigest(path)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("digest mismatch: got %s, want %s", actual, expected)
	}
	return nil
}

func validTransactionDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func writeTransactionManifest(root string, manifest *transactionManifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal initializer transaction journal: %w", err)
	}
	if err := securefs.WriteFileAtomic(
		filepath.Join(root, transactionManifestName),
		data,
		0o700,
		0o600,
	); err != nil {
		return fmt.Errorf("write initializer transaction journal: %w", err)
	}
	return nil
}

func validateTransactionManifest(
	manifest *transactionManifest,
	projectRoot, transactionRoot string,
) error {
	if manifest.Version != transactionSchemaVersion &&
		manifest.Version != digestTransactionVersion &&
		manifest.Version != legacyTransactionVersion {
		return fmt.Errorf("unsupported initializer transaction version %d", manifest.Version)
	}
	if filepath.Clean(manifest.ProjectRoot) != filepath.Clean(projectRoot) {
		return fmt.Errorf("initializer transaction belongs to a different project")
	}
	if !filepath.IsAbs(manifest.SecretsRoot) ||
		filepath.Dir(filepath.Clean(manifest.SecretsRoot)) == filepath.Clean(manifest.SecretsRoot) {
		return fmt.Errorf("initializer transaction has an unsafe secrets root")
	}
	if manifest.State != "prepared" &&
		manifest.State != "promoting" &&
		manifest.State != "committed" {
		return fmt.Errorf("invalid initializer transaction state %q", manifest.State)
	}
	if len(manifest.AllowedRoots) == 0 {
		return fmt.Errorf("initializer transaction has no allowed roots")
	}
	for _, root := range manifest.AllowedRoots {
		if !filepath.IsAbs(root) || filepath.Dir(root) == root {
			return fmt.Errorf("unsafe initializer transaction root %q", root)
		}
	}
	seen := make(map[string]struct{}, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		if entry.Kind != "dir" && entry.Kind != "file" {
			return fmt.Errorf("invalid initializer transaction entry kind %q", entry.Kind)
		}
		if entry.Kind == "dir" &&
			(entry.StagedDigest != "" || entry.BackupDigest != "") {
			return fmt.Errorf("initializer transaction directory entry has file digests")
		}
		if (entry.OriginalUID == nil) != (entry.OriginalGID == nil) {
			return fmt.Errorf(
				"initializer transaction ownership is incomplete for %s",
				entry.Target,
			)
		}
		if entry.Kind != "file" && entry.OriginalUID != nil {
			return fmt.Errorf(
				"initializer transaction directory entry has file ownership",
			)
		}
		if manifest.Version < transactionSchemaVersion && entry.OriginalUID != nil {
			return fmt.Errorf(
				"initializer transaction version %d cannot record ownership",
				manifest.Version,
			)
		}
		if manifest.Version >= digestTransactionVersion && entry.Kind == "file" {
			if !validTransactionDigest(entry.StagedDigest) {
				return fmt.Errorf(
					"initializer transaction staged digest is invalid for %s",
					entry.Target,
				)
			}
			if entry.Existed != (entry.BackupDigest != "") ||
				entry.BackupDigest != "" && !validTransactionDigest(entry.BackupDigest) {
				return fmt.Errorf(
					"initializer transaction backup digest is invalid for %s",
					entry.Target,
				)
			}
		}
		if !pathWithin(transactionRoot, entry.Source) {
			return fmt.Errorf("initializer transaction source escapes journal: %s", entry.Source)
		}
		if entry.Backup != "" && !pathWithin(transactionRoot, entry.Backup) {
			return fmt.Errorf("initializer transaction backup escapes journal: %s", entry.Backup)
		}
		allowed := false
		for _, root := range manifest.AllowedRoots {
			if pathWithin(root, entry.Target) {
				allowed = true
				break
			}
		}
		if !allowed || pathWithin(transactionRoot, entry.Target) {
			return fmt.Errorf("initializer transaction target is outside managed roots: %s", entry.Target)
		}
		target := filepath.Clean(entry.Target)
		if _, duplicate := seen[target]; duplicate {
			return fmt.Errorf("duplicate initializer transaction target %s", target)
		}
		seen[target] = struct{}{}
	}
	return nil
}

func validatePrivateTransactionDir(info os.FileInfo, path string) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("initializer transaction %s must be a directory, not a symlink", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("initializer transaction %s must not be accessible by group or other users", path)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("initializer transaction %s is not owned by the current user", path)
	}
	return nil
}

func removeTransactionDir(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := validatePrivateTransactionDir(info, path); err != nil {
		return err
	}
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("remove initializer transaction %s: %w", path, err)
	}
	return nil
}

func pathWithin(root, target string) bool {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	relative, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return relative == "." ||
		relative != ".." &&
			!strings.HasPrefix(relative, ".."+string(filepath.Separator)) &&
			!filepath.IsAbs(relative)
}

func pathsOverlap(left, right string) bool {
	return pathWithin(left, right) || pathWithin(right, left)
}

func uniqueCleanPaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		path = filepath.Clean(path)
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		result = append(result, path)
	}
	return result
}

func pathDepth(path string) int {
	return strings.Count(filepath.Clean(path), string(filepath.Separator))
}
