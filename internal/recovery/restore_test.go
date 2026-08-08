package recovery

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/backup"
	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/generator"
	"github.com/get-sdbx/sdbx/internal/registry"
)

const recoveryTestVersion = "recovery-test"

type recoveryTestResolver struct{}

func (recoveryTestResolver) Resolve(
	_ context.Context,
	_, _ string,
) (registry.ResolvedImage, error) {
	digest := "sha256:" + strings.Repeat("a", 64)
	return registry.ResolvedImage{
		Digest: digest,
		PlatformDigests: map[string]string{
			"linux/amd64": digest,
			"linux/arm64": digest,
		},
	}, nil
}

func TestRelocateManagedRootsPreservesTargetRuntimeAndRestoresState(t *testing.T) {
	root := t.TempDir()
	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	sourceProject := filepath.Join(root, "source-project")
	sourceConfigRoot := filepath.Join(root, "source-config")
	sourceSecretsRoot := filepath.Join(root, "source-secrets")
	targetProject := filepath.Join(root, "target-project")
	targetConfigRoot := filepath.Join(root, "target-config")
	targetSecretsRoot := filepath.Join(root, "target-secrets")

	sourceConfig := recoveryConfig(
		sourceProject,
		sourceConfigRoot,
		sourceSecretsRoot,
	)
	targetConfig := recoveryConfig(
		targetProject,
		targetConfigRoot,
		targetSecretsRoot,
	)
	buildRecoveryProject(t, sourceProject, sourceConfig, reg)
	buildRecoveryProject(t, targetProject, targetConfig, reg)

	sourceState := filepath.Join(sourceConfigRoot, "application", "state.db")
	if err := os.MkdirAll(filepath.Dir(sourceState), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourceState, []byte("portable-state\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceSecret := filepath.Join(sourceSecretsRoot, "portable-token.txt")
	if err := os.WriteFile(sourceSecret, []byte("portable-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	created, err := backup.NewManager(sourceProject).Create(
		context.Background(),
		backup.EncryptOptions{Passphrase: []byte("synthetic relocation passphrase")},
	)
	if err != nil {
		t.Fatal(err)
	}
	targetArchiveDir := filepath.Join(targetProject, "backups")
	if err := os.MkdirAll(targetArchiveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	archiveData, err := os.ReadFile(created.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(targetArchiveDir, created.Name),
		archiveData,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	preserved := map[string][]byte{}
	for _, path := range []string{
		filepath.Join(targetProject, ".sdbx.yaml"),
		filepath.Join(targetProject, ".sdbx.lock"),
		filepath.Join(targetProject, "compose.yaml"),
		filepath.Join(targetProject, ".env"),
		filepath.Join(targetConfigRoot, "traefik", "traefik.yml"),
		filepath.Join(targetConfigRoot, "authelia", "configuration.yml"),
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		preserved[path] = data
	}

	hooks, err := RestoreHooks(
		context.Background(),
		targetProject,
		reg,
		recoveryTestVersion,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.NewManager(targetProject).RestoreWithHooks(
		context.Background(),
		created.Name,
		backup.DecryptOptions{
			Passphrase: []byte("synthetic relocation passphrase"),
		},
		hooks,
	); err != nil {
		t.Fatal(err)
	}

	for path, expected := range preserved {
		actual, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(actual) != string(expected) {
			t.Fatalf("target runtime %s changed during relocation", path)
		}
	}
	assertRecoveryFile(
		t,
		filepath.Join(targetConfigRoot, "application", "state.db"),
		"portable-state\n",
	)
	assertRecoveryFile(
		t,
		filepath.Join(targetSecretsRoot, "portable-token.txt"),
		"portable-secret\n",
	)
}

func TestRelocateManagedRootsRejectsOtherIntentChangesBeforePromotion(t *testing.T) {
	root := t.TempDir()
	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	sourceProject := filepath.Join(root, "source-project")
	targetProject := filepath.Join(root, "target-project")
	sourceConfig := recoveryConfig(
		sourceProject,
		filepath.Join(root, "source-config"),
		filepath.Join(root, "source-secrets"),
	)
	sourceConfig.Timezone = "UTC"
	targetConfig := recoveryConfig(
		targetProject,
		filepath.Join(root, "target-config"),
		filepath.Join(root, "target-secrets"),
	)
	buildRecoveryProject(t, sourceProject, sourceConfig, reg)
	buildRecoveryProject(t, targetProject, targetConfig, reg)
	created, err := backup.NewManager(sourceProject).Create(
		context.Background(),
		backup.EncryptOptions{Passphrase: []byte("synthetic relocation passphrase")},
	)
	if err != nil {
		t.Fatal(err)
	}
	targetArchiveDir := filepath.Join(targetProject, "backups")
	if err := os.MkdirAll(targetArchiveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(created.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(targetArchiveDir, created.Name),
		data,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	targetConfigPath := filepath.Join(targetProject, ".sdbx.yaml")
	before, err := os.ReadFile(targetConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	hooks, err := RestoreHooks(
		context.Background(),
		targetProject,
		reg,
		recoveryTestVersion,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	err = backup.NewManager(targetProject).RestoreWithHooks(
		context.Background(),
		created.Name,
		backup.DecryptOptions{
			Passphrase: []byte("synthetic relocation passphrase"),
		},
		hooks,
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"permits differences in config_path or secrets_path",
	) {
		t.Fatalf("incompatible relocation error = %v", err)
	}
	after, err := os.ReadFile(targetConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("incompatible relocation mutated target project intent")
	}
}

func TestStateRestorePreservesTrustedControlPlaneAgainstSelfConsistentArchive(t *testing.T) {
	root := t.TempDir()
	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	sourceProject := filepath.Join(root, "source-project")
	targetProject := filepath.Join(root, "target-project")
	sourceConfig := relativeRecoveryConfig(sourceProject)
	targetConfig := relativeRecoveryConfig(targetProject)
	buildRecoveryProject(t, sourceProject, sourceConfig, reg)
	buildRecoveryProject(t, targetProject, targetConfig, reg)

	maliciousCompose := []byte(`services:
  archive-payload:
    image: alpine
    privileged: true
    volumes:
      - /:/host
`)
	if err := os.WriteFile(
		filepath.Join(sourceProject, "compose.yaml"),
		maliciousCompose,
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	sourceLockPath := filepath.Join(sourceProject, ".sdbx.lock")
	sourceLock, err := registry.NewLoader().LoadLockFile(sourceLockPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(maliciousCompose)
	sourceLock.GeneratedFiles["compose.yaml"] = fmt.Sprintf("sha256:%x", digest[:])
	if err := registry.NewLoader().SaveLockFile(sourceLockPath, sourceLock); err != nil {
		t.Fatal(err)
	}
	sourceState := filepath.Join(
		sourceProject,
		"configs",
		"application",
		"state.db",
	)
	if err := os.MkdirAll(filepath.Dir(sourceState), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourceState, []byte("restored-state\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	created, err := backup.NewManager(sourceProject).Create(
		context.Background(),
		backup.EncryptOptions{Passphrase: []byte("synthetic state passphrase")},
	)
	if err != nil {
		t.Fatal(err)
	}
	copyRecoveryArchive(t, created.Path, targetProject, created.Name)

	preserved := preserveRecoveryFiles(t, targetProject, targetConfig.ConfigPath)
	hooks, err := RestoreHooks(
		context.Background(),
		targetProject,
		reg,
		recoveryTestVersion,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.NewManager(targetProject).RestoreWithHooks(
		context.Background(),
		created.Name,
		backup.DecryptOptions{
			Passphrase: []byte("synthetic state passphrase"),
		},
		hooks,
	); err != nil {
		t.Fatal(err)
	}

	assertPreservedRecoveryFiles(t, preserved)
	assertRecoveryFile(
		t,
		filepath.Join(targetProject, "configs", "application", "state.db"),
		"restored-state\n",
	)
}

func TestStateRestoreRejectsManagedRootChangesWithoutRelocation(t *testing.T) {
	root := t.TempDir()
	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	sourceProject := filepath.Join(root, "source-project")
	targetProject := filepath.Join(root, "target-project")
	sourceConfig := recoveryConfig(
		sourceProject,
		filepath.Join(root, "source-config"),
		filepath.Join(root, "source-secrets"),
	)
	targetConfig := recoveryConfig(
		targetProject,
		filepath.Join(root, "target-config"),
		filepath.Join(root, "target-secrets"),
	)
	buildRecoveryProject(t, sourceProject, sourceConfig, reg)
	buildRecoveryProject(t, targetProject, targetConfig, reg)
	created, err := backup.NewManager(sourceProject).Create(
		context.Background(),
		backup.EncryptOptions{Passphrase: []byte("synthetic exact passphrase")},
	)
	if err != nil {
		t.Fatal(err)
	}
	copyRecoveryArchive(t, created.Path, targetProject, created.Name)

	targetCompose := filepath.Join(targetProject, "compose.yaml")
	before, err := os.ReadFile(targetCompose)
	if err != nil {
		t.Fatal(err)
	}
	hooks, err := RestoreHooks(
		context.Background(),
		targetProject,
		reg,
		recoveryTestVersion,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	err = backup.NewManager(targetProject).RestoreWithHooks(
		context.Background(),
		created.Name,
		backup.DecryptOptions{
			Passphrase: []byte("synthetic exact passphrase"),
		},
		hooks,
	)
	if err == nil || !strings.Contains(err.Error(), "permits differences in no fields") {
		t.Fatalf("incompatible state restore error = %v", err)
	}
	after, err := os.ReadFile(targetCompose)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("rejected state restore mutated the target control plane")
	}
}

func recoveryConfig(
	projectDir, configRoot, secretsRoot string,
) *config.Config {
	cfg := config.DefaultConfig()
	cfg.Domain = "recovery.example.test"
	cfg.ProjectDir = projectDir
	cfg.ConfigPath = configRoot
	cfg.SecretsPath = secretsRoot
	return cfg
}

func relativeRecoveryConfig(projectDir string) *config.Config {
	cfg := recoveryConfig(projectDir, "./configs", "./secrets")
	return cfg
}

func buildRecoveryProject(
	t *testing.T,
	projectDir string,
	cfg *config.Config,
	reg *registry.Registry,
) {
	t.Helper()
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatal(err)
	}
	lock, _, err := reg.GenerateLockFileWithOptions(
		context.Background(),
		cfg,
		registry.LockOptions{
			CLIVersion:     recoveryTestVersion,
			TargetPlatform: "linux/" + runtime.GOARCH,
			ImageResolver:  recoveryTestResolver{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(projectDir, ".sdbx.lock")
	if err := registry.NewLoader().SaveLockFile(lockPath, lock); err != nil {
		t.Fatal(err)
	}
	if err := generator.NewGeneratorWithLock(
		cfg,
		projectDir,
		reg,
		lock,
		recoveryTestVersion,
	).Generate(); err != nil {
		t.Fatal(err)
	}
	if err := registry.NewLoader().SaveLockFile(lockPath, lock); err != nil {
		t.Fatal(err)
	}
}

func assertRecoveryFile(t *testing.T, path, expected string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != expected {
		t.Fatalf("%s = %q, want %q", path, data, expected)
	}
}

func copyRecoveryArchive(
	t *testing.T,
	sourcePath, targetProject, archiveName string,
) {
	t.Helper()
	targetArchiveDir := filepath.Join(targetProject, "backups")
	if err := os.MkdirAll(targetArchiveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(targetArchiveDir, archiveName),
		data,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func preserveRecoveryFiles(
	t *testing.T,
	projectDir, configuredConfigRoot string,
) map[string][]byte {
	t.Helper()
	configRoot := configuredConfigRoot
	if !filepath.IsAbs(configRoot) {
		configRoot = filepath.Join(projectDir, configRoot)
	}
	paths := []string{
		filepath.Join(projectDir, ".sdbx.yaml"),
		filepath.Join(projectDir, ".sdbx.lock"),
		filepath.Join(projectDir, "compose.yaml"),
		filepath.Join(projectDir, ".env"),
		filepath.Join(configRoot, "authelia", "configuration.yml"),
		filepath.Join(configRoot, "traefik", "traefik.yml"),
		filepath.Join(configRoot, "traefik", "dynamic", "middlewares.yml"),
	}
	preserved := make(map[string][]byte, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		preserved[path] = data
	}
	return preserved
}

func assertPreservedRecoveryFiles(
	t *testing.T,
	preserved map[string][]byte,
) {
	t.Helper()
	for path, expected := range preserved {
		actual, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(actual) != string(expected) {
			t.Fatalf("trusted control-plane file %s changed during restore", path)
		}
	}
}
