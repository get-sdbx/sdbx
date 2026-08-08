package generator

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

type transactionImageResolver struct {
	salt string
}

func (r transactionImageResolver) Resolve(
	_ context.Context,
	repository, tag string,
) (registry.ResolvedImage, error) {
	digest := transactionDigest(repository + ":" + tag + r.salt)
	return registry.ResolvedImage{
		Digest: digest,
		PlatformDigests: map[string]string{
			"linux/amd64": transactionDigest(
				repository + ":" + tag + ":amd64" + r.salt,
			),
			"linux/arm64/v8": transactionDigest(
				repository + ":" + tag + ":arm64" + r.salt,
			),
		},
	}, nil
}

func transactionDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", sum)
}

func transactionFixture(
	t *testing.T,
	projectDir string,
) (*config.Config, *registry.Registry, *registry.LockFile) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Domain = "box.example.test"
	cfg.AdminUser = "admin"
	cfg.AdminPasswordHash = "$argon2id$test"
	cfg.ProjectDir = projectDir
	reg, err := registry.New(&registry.SourceConfig{
		APIVersion: registry.APIVersion,
		Kind:       registry.KindSourceConfig,
	})
	if err != nil {
		t.Fatal(err)
	}
	lock, _, err := reg.GenerateLockFileWithOptions(
		context.Background(),
		cfg,
		registry.LockOptions{
			CLIVersion:    "v1.0.0",
			ImageResolver: transactionImageResolver{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, reg, lock
}

func TestGenerateProjectTransactionalPromotesOnlyAfterValidation(t *testing.T) {
	projectDir := t.TempDir()
	cfg, reg, lock := transactionFixture(t, projectDir)
	oldCompose := []byte("old compose\n")
	if err := os.WriteFile(filepath.Join(projectDir, "compose.yaml"), oldCompose, 0o644); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(projectDir, "secrets", "authelia_jwt_secret.txt")
	if err := os.MkdirAll(filepath.Dir(secretPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretPath, []byte("keep-this-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	customSecretPath := filepath.Join(projectDir, "secrets", "custom-source-token.txt")
	if err := os.WriteFile(customSecretPath, []byte("keep-custom-secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	validated := false
	err := GenerateProjectTransactional(
		cfg,
		projectDir,
		reg,
		lock,
		"v1.0.0",
		ProjectTransactionOptions{
			ValidateStage: func(stageProject string) error {
				validated = true
				if _, err := os.Stat(filepath.Join(stageProject, "compose.yaml")); err != nil {
					return err
				}
				current, err := os.ReadFile(filepath.Join(projectDir, "compose.yaml"))
				if err != nil {
					return err
				}
				if string(current) != string(oldCompose) {
					return fmt.Errorf("destination changed before validation")
				}
				return nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !validated {
		t.Fatal("staged project was not validated")
	}
	compose, err := os.ReadFile(filepath.Join(projectDir, "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(compose) == string(oldCompose) || !strings.Contains(string(compose), "services:") {
		t.Fatalf("compose was not promoted:\n%s", compose)
	}
	secret, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "keep-this-secret" {
		t.Fatalf("existing secret changed to %q", secret)
	}
	customSecret, err := os.ReadFile(customSecretPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(customSecret) != "keep-custom-secret" {
		t.Fatalf("custom secret changed to %q", customSecret)
	}
	if _, err := os.Stat(filepath.Join(projectDir, ".sdbx.lock")); err != nil {
		t.Fatal("lock was not promoted:", err)
	}
	pending, err := ProjectTransactionPending(projectDir)
	if err != nil {
		t.Fatal(err)
	}
	if pending {
		t.Fatal("completed transaction journal was not cleaned")
	}
}

func TestGenerateProjectTransactionalValidationFailureLeavesDestinationsUntouched(t *testing.T) {
	projectDir := t.TempDir()
	cfg, reg, lock := transactionFixture(t, projectDir)
	target := filepath.Join(projectDir, "compose.yaml")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := GenerateProjectTransactional(
		cfg,
		projectDir,
		reg,
		lock,
		"v1.0.0",
		ProjectTransactionOptions{
			ValidateStage: func(string) error {
				return fmt.Errorf("invalid staged compose")
			},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "invalid staged compose") {
		t.Fatalf("error = %v", err)
	}
	body, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(body) != "original" {
		t.Fatalf("destination changed to %q", body)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("destination mode = %o, want 600", info.Mode().Perm())
	}
	pending, err := ProjectTransactionPending(projectDir)
	if err != nil {
		t.Fatal(err)
	}
	if pending {
		t.Fatal("failed staging left a transaction journal")
	}
}

func TestGenerateRuntimeTransactionalCommitsLockAndRuntimeTogether(t *testing.T) {
	projectDir := t.TempDir()
	cfg, reg, previous := transactionFixture(t, projectDir)
	if err := GenerateProjectTransactional(
		cfg,
		projectDir,
		reg,
		previous,
		"v1.0.0",
		ProjectTransactionOptions{},
	); err != nil {
		t.Fatal(err)
	}
	staticPath := filepath.Join(
		projectDir,
		"configs",
		"authelia",
		"users_database.yml",
	)
	const staticSentinel = "user-managed-static-state\n"
	if err := os.WriteFile(staticPath, []byte(staticSentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	oldCompose, err := os.ReadFile(filepath.Join(projectDir, "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	oldLock, err := os.ReadFile(filepath.Join(projectDir, ".sdbx.lock"))
	if err != nil {
		t.Fatal(err)
	}
	oldConfig, err := os.ReadFile(filepath.Join(projectDir, ".sdbx.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Domain = "updated.example.test"
	next, _, err := reg.GenerateLockFileWithOptions(
		context.Background(),
		cfg,
		registry.LockOptions{
			CLIVersion: "v1.0.0",
			ImageResolver: transactionImageResolver{
				salt: ":updated",
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	var stagedCompose, stagedLock, stagedConfig []byte
	err = GenerateProjectTransactional(
		cfg,
		projectDir,
		reg,
		next,
		"v1.0.0",
		ProjectTransactionOptions{
			RuntimeOnly: true,
			ValidateStage: func(stageProject string) error {
				var readErr error
				stagedCompose, readErr = os.ReadFile(
					filepath.Join(stageProject, "compose.yaml"),
				)
				if readErr != nil {
					return readErr
				}
				stagedLock, readErr = os.ReadFile(
					filepath.Join(stageProject, ".sdbx.lock"),
				)
				if readErr != nil {
					return readErr
				}
				stagedConfig, readErr = os.ReadFile(
					filepath.Join(stageProject, ".sdbx.yaml"),
				)
				if readErr != nil {
					return readErr
				}
				liveCompose, readErr := os.ReadFile(
					filepath.Join(projectDir, "compose.yaml"),
				)
				if readErr != nil {
					return readErr
				}
				liveLock, readErr := os.ReadFile(
					filepath.Join(projectDir, ".sdbx.lock"),
				)
				if readErr != nil {
					return readErr
				}
				liveConfig, readErr := os.ReadFile(
					filepath.Join(projectDir, ".sdbx.yaml"),
				)
				if readErr != nil {
					return readErr
				}
				if string(liveCompose) != string(oldCompose) ||
					string(liveLock) != string(oldLock) ||
					string(liveConfig) != string(oldConfig) {
					return fmt.Errorf(
						"live config, lock, or runtime changed before validation",
					)
				}
				return nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	liveCompose, err := os.ReadFile(filepath.Join(projectDir, "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	liveLock, err := os.ReadFile(filepath.Join(projectDir, ".sdbx.lock"))
	if err != nil {
		t.Fatal(err)
	}
	liveConfig, err := os.ReadFile(filepath.Join(projectDir, ".sdbx.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(liveCompose) != string(stagedCompose) ||
		string(liveLock) != string(stagedLock) ||
		string(liveConfig) != string(stagedConfig) {
		t.Fatal("promoted config, lock, and runtime do not match the validated stage")
	}
	if string(liveCompose) == string(oldCompose) ||
		string(liveLock) == string(oldLock) ||
		string(liveConfig) == string(oldConfig) {
		t.Fatal(
			"runtime-only transaction did not promote the updated config, lock, and runtime",
		)
	}
	staticBody, err := os.ReadFile(staticPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(staticBody) != staticSentinel {
		t.Fatalf("runtime-only transaction rewrote static state: %q", staticBody)
	}
}

func TestRecoverRuntimeTransactionRestoresLockAndComposeTogether(t *testing.T) {
	projectDir := t.TempDir()
	transactionRoot := filepath.Join(projectDir, projectTransactionDirName)
	stageRoot := filepath.Join(transactionRoot, "stage", "project")
	rollbackRoot := filepath.Join(transactionRoot, "rollback")
	if err := os.MkdirAll(stageRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(rollbackRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	type fileFixture struct {
		name string
		old  string
		new  string
	}
	fixtures := []fileFixture{
		{name: "compose.yaml", old: "old compose\n", new: "new compose\n"},
		{name: ".sdbx.lock", old: "old lock\n", new: "new lock\n"},
	}
	entries := make([]transactionEntry, 0, len(fixtures))
	for index, fixture := range fixtures {
		target := filepath.Join(projectDir, fixture.name)
		source := filepath.Join(stageRoot, fixture.name)
		backup := filepath.Join(rollbackRoot, fmt.Sprintf("%06d", index))
		if err := os.WriteFile(target, []byte(fixture.old), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(source, []byte(fixture.new), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(backup, []byte(fixture.old), 0o600); err != nil {
			t.Fatal(err)
		}
		stagedDigest, err := transactionFileDigest(source)
		if err != nil {
			t.Fatal(err)
		}
		backupDigest, err := transactionFileDigest(backup)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, transactionEntry{
			Kind:         "file",
			Source:       source,
			Target:       target,
			Backup:       backup,
			Existed:      true,
			OriginalMode: 0o600,
			DesiredMode:  0o600,
			StagedDigest: stagedDigest,
			BackupDigest: backupDigest,
		})
	}
	// Simulate interruption after compose was promoted but before the lock.
	if err := os.WriteFile(
		filepath.Join(projectDir, "compose.yaml"),
		[]byte("new compose\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	manifest := transactionManifest{
		Version:      transactionSchemaVersion,
		State:        "promoting",
		ProjectRoot:  projectDir,
		SecretsRoot:  filepath.Join(projectDir, "secrets"),
		AllowedRoots: []string{projectDir},
		Entries:      entries,
	}
	if err := writeTransactionManifest(transactionRoot, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := RecoverProjectTransaction(projectDir); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		body, err := os.ReadFile(filepath.Join(projectDir, fixture.name))
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != fixture.old {
			t.Fatalf("%s recovered to %q, want %q", fixture.name, body, fixture.old)
		}
	}
}

func TestRecoverProjectTransactionRejectsTamperedBackup(t *testing.T) {
	projectDir := t.TempDir()
	target := filepath.Join(projectDir, "compose.yaml")
	transactionRoot := filepath.Join(projectDir, projectTransactionDirName)
	source := filepath.Join(transactionRoot, "stage", "project", "compose.yaml")
	backup := filepath.Join(transactionRoot, "rollback", "000000")
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(backup), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		target: "new",
		source: "new",
		backup: "old",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stagedDigest, err := transactionFileDigest(source)
	if err != nil {
		t.Fatal(err)
	}
	backupDigest, err := transactionFileDigest(backup)
	if err != nil {
		t.Fatal(err)
	}
	manifest := transactionManifest{
		Version:      transactionSchemaVersion,
		State:        "promoting",
		ProjectRoot:  projectDir,
		SecretsRoot:  filepath.Join(projectDir, "secrets"),
		AllowedRoots: []string{projectDir},
		Entries: []transactionEntry{{
			Kind:         "file",
			Source:       source,
			Target:       target,
			Backup:       backup,
			Existed:      true,
			OriginalMode: 0o600,
			DesiredMode:  0o600,
			StagedDigest: stagedDigest,
			BackupDigest: backupDigest,
		}},
	}
	if err := writeTransactionManifest(transactionRoot, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}

	err = RecoverProjectTransaction(projectDir)
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tampered backup recovery error = %v", err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "new" {
		t.Fatalf("unsafe recovery modified target to %q", body)
	}
	if pending, pendingErr := ProjectTransactionPending(projectDir); pendingErr != nil || !pending {
		t.Fatalf("failed recovery journal was not retained: pending=%v err=%v", pending, pendingErr)
	}
}

func TestRecoverProjectTransactionRestoresPromotingJournal(t *testing.T) {
	projectDir := t.TempDir()
	target := filepath.Join(projectDir, "compose.yaml")
	if err := os.WriteFile(target, []byte("partially promoted"), 0o644); err != nil {
		t.Fatal(err)
	}
	transactionRoot := filepath.Join(projectDir, projectTransactionDirName)
	stageFile := filepath.Join(transactionRoot, "stage", "project", "compose.yaml")
	backupFile := filepath.Join(transactionRoot, "rollback", "000000")
	if err := os.MkdirAll(filepath.Dir(stageFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(backupFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stageFile, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupFile, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	stagedDigest, err := transactionFileDigest(stageFile)
	if err != nil {
		t.Fatal(err)
	}
	backupDigest, err := transactionFileDigest(backupFile)
	if err != nil {
		t.Fatal(err)
	}
	manifest := transactionManifest{
		Version:      digestTransactionVersion,
		State:        "promoting",
		ProjectRoot:  projectDir,
		SecretsRoot:  filepath.Join(projectDir, "secrets"),
		AllowedRoots: []string{projectDir},
		Entries: []transactionEntry{{
			Kind:         "file",
			Source:       stageFile,
			Target:       target,
			Backup:       backupFile,
			Existed:      true,
			OriginalMode: 0o600,
			DesiredMode:  0o644,
			StagedDigest: stagedDigest,
			BackupDigest: backupDigest,
		}},
	}
	if err := writeTransactionManifest(transactionRoot, &manifest); err != nil {
		t.Fatal(err)
	}

	if err := RecoverProjectTransaction(projectDir); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "original" {
		t.Fatalf("recovered body = %q", body)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("recovered mode = %o, want 600", info.Mode().Perm())
	}
}

func TestRecoverProjectTransactionRestoresRecordedOwnership(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("requires a Linux root test environment")
	}

	projectDir := t.TempDir()
	target := filepath.Join(projectDir, "compose.yaml")
	transactionRoot := filepath.Join(projectDir, projectTransactionDirName)
	stageFile := filepath.Join(transactionRoot, "stage", "project", "compose.yaml")
	backupFile := filepath.Join(transactionRoot, "rollback", "000000")
	for _, directory := range []string{filepath.Dir(stageFile), filepath.Dir(backupFile)} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(stageFile, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupFile, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("partially promoted"), 0o600); err != nil {
		t.Fatal(err)
	}

	const (
		originalUID = 12345
		originalGID = 12346
		promotedUID = 23456
		promotedGID = 23457
	)
	if err := os.Chown(target, promotedUID, promotedGID); err != nil {
		t.Fatal(err)
	}
	stagedDigest, err := transactionFileDigest(stageFile)
	if err != nil {
		t.Fatal(err)
	}
	backupDigest, err := transactionFileDigest(backupFile)
	if err != nil {
		t.Fatal(err)
	}
	manifest := transactionManifest{
		Version:      transactionSchemaVersion,
		State:        "promoting",
		ProjectRoot:  projectDir,
		SecretsRoot:  filepath.Join(projectDir, "secrets"),
		AllowedRoots: []string{projectDir},
		Entries: []transactionEntry{{
			Kind:         "file",
			Source:       stageFile,
			Target:       target,
			Backup:       backupFile,
			Existed:      true,
			OriginalMode: 0o600,
			OriginalUID:  intAddress(originalUID),
			OriginalGID:  intAddress(originalGID),
			DesiredMode:  0o600,
			StagedDigest: stagedDigest,
			BackupDigest: backupDigest,
		}},
	}
	if err := writeTransactionManifest(transactionRoot, &manifest); err != nil {
		t.Fatal(err)
	}

	if err := RecoverProjectTransaction(projectDir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("recovered file has no syscall.Stat_t")
	}
	if int(stat.Uid) != originalUID || int(stat.Gid) != originalGID {
		t.Fatalf(
			"recovered ownership = %d:%d, want %d:%d",
			stat.Uid,
			stat.Gid,
			originalUID,
			originalGID,
		)
	}
}

func intAddress(value int) *int {
	return &value
}

func TestGenerateProjectTransactionalSupportsExternalManagedRoots(t *testing.T) {
	projectDir := t.TempDir()
	external := t.TempDir()
	cfg, reg, _ := transactionFixture(t, projectDir)
	cfg.ConfigPath = filepath.Join(external, "configs")
	cfg.SecretsPath = filepath.Join(external, "secrets")
	lock, _, err := reg.GenerateLockFileWithOptions(
		context.Background(),
		cfg,
		registry.LockOptions{
			CLIVersion:    "v1.0.0",
			ImageResolver: transactionImageResolver{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := GenerateProjectTransactional(
		cfg,
		projectDir,
		reg,
		lock,
		"v1.0.0",
		ProjectTransactionOptions{},
	); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(projectDir, "compose.yaml"),
		filepath.Join(cfg.ConfigPath, "authelia", "configuration.yml"),
		filepath.Join(cfg.SecretsPath, "authelia_jwt_secret.txt"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("promoted path %s: %v", path, err)
		}
	}
}

func TestRecoverProjectTransactionRejectsTargetsOutsideManagedRoots(t *testing.T) {
	projectDir := t.TempDir()
	outsideDir := t.TempDir()
	outsideTarget := filepath.Join(outsideDir, "do-not-touch")
	if err := os.WriteFile(outsideTarget, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	transactionRoot := filepath.Join(projectDir, projectTransactionDirName)
	stageFile := filepath.Join(transactionRoot, "stage", "project", "compose.yaml")
	if err := os.MkdirAll(filepath.Dir(stageFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stageFile, []byte("malicious"), 0o600); err != nil {
		t.Fatal(err)
	}
	stagedDigest, err := transactionFileDigest(stageFile)
	if err != nil {
		t.Fatal(err)
	}
	manifest := transactionManifest{
		Version:      transactionSchemaVersion,
		State:        "promoting",
		ProjectRoot:  projectDir,
		SecretsRoot:  filepath.Join(projectDir, "secrets"),
		AllowedRoots: []string{projectDir},
		Entries: []transactionEntry{{
			Kind:         "file",
			Source:       stageFile,
			Target:       outsideTarget,
			DesiredMode:  0o600,
			StagedDigest: stagedDigest,
		}},
	}
	if err := writeTransactionManifest(transactionRoot, &manifest); err != nil {
		t.Fatal(err)
	}
	err = RecoverProjectTransaction(projectDir)
	if err == nil || !strings.Contains(err.Error(), "outside managed roots") {
		t.Fatalf("recovery error = %v", err)
	}
	body, readErr := os.ReadFile(outsideTarget)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(body) != "safe" {
		t.Fatalf("outside target changed to %q", body)
	}
}

func TestRecoverProjectTransactionRejectsSymlinkJournal(t *testing.T) {
	projectDir := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(
		outside,
		filepath.Join(projectDir, projectTransactionDirName),
	); err != nil {
		t.Fatal(err)
	}
	err := RecoverProjectTransaction(projectDir)
	if err == nil || !strings.Contains(err.Error(), "not a symlink") {
		t.Fatalf("symlink journal error = %v", err)
	}
}

func TestApplyFailureCanRollBackPreviouslyPromotedFile(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "compose.yaml")
	source := filepath.Join(root, "staged-compose.yaml")
	backup := filepath.Join(root, "backup-compose.yaml")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("replacement"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := transactionManifest{
		SecretsRoot: filepath.Join(root, "secrets"),
		Entries: []transactionEntry{
			{
				Kind:         "file",
				Source:       source,
				Target:       target,
				Backup:       backup,
				Existed:      true,
				OriginalMode: 0o600,
				DesiredMode:  0o644,
			},
			{
				Kind:        "file",
				Source:      filepath.Join(root, "missing-stage"),
				Target:      filepath.Join(root, "second-target"),
				DesiredMode: 0o644,
			},
		},
	}
	if err := applyTransaction(&manifest); err == nil {
		t.Fatal("applyTransaction succeeded with a missing staged file")
	}
	if err := rollbackTransaction(&manifest); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "original" {
		t.Fatalf("rolled-back target = %q", body)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("rolled-back mode = %o, want 600", info.Mode().Perm())
	}
}
