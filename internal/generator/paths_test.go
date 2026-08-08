package generator

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

// TestGenerateWithAbsolutePaths verifies that Generate() honours absolute
// ConfigPath, DataPath, and SecretsPath: project files land in their configured
// roots, compose.yaml host paths are absolute, and the relative ./configs /
// ./data / ./secrets prefixes do not leak into the generated compose.
func TestGenerateWithAbsolutePaths(t *testing.T) {
	root := t.TempDir()
	outputDir := filepath.Join(root, "project")
	configRoot := filepath.Join(root, "configs")
	dataRoot := filepath.Join(root, "data")
	secretsRoot := filepath.Join(root, "secrets")

	for _, d := range []string{outputDir, configRoot, dataRoot, secretsRoot} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	cfg := config.DefaultConfig()
	cfg.ConfigPath = configRoot
	cfg.DataPath = dataRoot
	cfg.DownloadsPath = filepath.Join(dataRoot, "downloads")
	cfg.MediaPath = filepath.Join(dataRoot, "media")
	cfg.SecretsPath = secretsRoot
	cfg.Expose.Mode = "cloudflared"
	cfg.VPNEnabled = true
	cfg.VPNProvider = "mullvad"
	cfg.Addons = []string{"sonarr", "radarr"}

	gen := newTestGenerator(t, cfg, outputDir)

	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Project root should contain compose.yaml + .env, NOT configs/.
	for _, f := range []string{"compose.yaml", ".env", ".sdbx.yaml"} {
		if _, err := os.Stat(filepath.Join(outputDir, f)); err != nil {
			t.Errorf("expected %s in OutputDir, got err: %v", f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(outputDir, "configs")); err == nil {
		t.Error("OutputDir/configs should NOT exist when ConfigPath is absolute elsewhere")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "secrets")); err == nil {
		t.Error("OutputDir/secrets should NOT exist when SecretsPath is absolute elsewhere")
	}

	// Static config files should be written under absolute ConfigPath.
	expectedConfigFiles := []string{
		"traefik/traefik.yml",
		"authelia/configuration.yml",
		"authelia/users_database.yml",
		"gluetun/gluetun.env",
		"traefik/dynamic/middlewares.yml",
	}
	for _, rel := range expectedConfigFiles {
		path := filepath.Join(configRoot, rel)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected config file at %s, got err: %v", path, err)
		}
	}

	// Per-service config dirs should be created under absolute ConfigPath.
	for _, name := range []string{"traefik", "authelia", "sonarr", "radarr"} {
		path := filepath.Join(configRoot, name)
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			t.Errorf("expected config dir at %s, got err: %v", path, err)
		}
	}

	// Secrets should be written under absolute SecretsPath, not under OutputDir.
	if _, err := os.Stat(filepath.Join(secretsRoot, "authelia_jwt_secret.txt")); err != nil {
		t.Errorf("expected secret in SecretsPath, got err: %v", err)
	}

	// compose.yaml content checks: absolute host paths, no relative leaks.
	composeBytes, err := os.ReadFile(filepath.Join(outputDir, "compose.yaml"))
	if err != nil {
		t.Fatalf("read compose.yaml: %v", err)
	}
	compose := string(composeBytes)

	for _, want := range []string{
		configRoot + "/",
		dataRoot,
	} {
		if !strings.Contains(compose, want) {
			t.Errorf("compose.yaml missing expected absolute path %q", want)
		}
	}

	for _, leak := range []string{
		`"./configs/`,
		`"./data/`,
		`"./secrets/`,
		` ./configs/`,
		` ./data/`,
	} {
		if strings.Contains(compose, leak) {
			t.Errorf("compose.yaml leaks relative path %q", leak)
		}
	}

	// Compose-level secret files must point at absolute SecretsPath.
	if !strings.Contains(compose, secretsRoot) {
		t.Errorf("compose.yaml secrets section missing absolute SecretsPath %q", secretsRoot)
	}
}

// TestGenerateRuntimeFilesRespectsConfigPath verifies that the
// "regenerate after config set" path (used by sdbx config set) does NOT write
// runtime files back to OutputDir/configs when ConfigPath is absolute.
func TestGenerateRuntimeFilesRespectsConfigPath(t *testing.T) {
	root := t.TempDir()
	outputDir := filepath.Join(root, "project")
	configRoot := filepath.Join(root, "abs-configs")
	secretsRoot := filepath.Join(root, "abs-secrets")

	for _, d := range []string{outputDir, configRoot, secretsRoot} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	cfg := config.DefaultConfig()
	cfg.ConfigPath = configRoot
	cfg.SecretsPath = secretsRoot
	cfg.Expose.Mode = "cloudflared"

	gen := newTestGenerator(t, cfg, outputDir)
	if err := gen.GenerateRuntimeFiles(); err != nil {
		t.Fatalf("GenerateRuntimeFiles failed: %v", err)
	}

	// Compose lands in OutputDir.
	if _, err := os.Stat(filepath.Join(outputDir, "compose.yaml")); err != nil {
		t.Errorf("expected compose.yaml in OutputDir: %v", err)
	}

	// Runtime files land under absolute ConfigPath.
	for _, rel := range []string{
		"traefik/dynamic/middlewares.yml",
	} {
		if _, err := os.Stat(filepath.Join(configRoot, rel)); err != nil {
			t.Errorf("runtime file %s missing under absolute ConfigPath: %v", rel, err)
		}
	}

	// They MUST NOT be written to OutputDir/configs.
	for _, rel := range []string{
		"configs/traefik/dynamic/middlewares.yml",
	} {
		if _, err := os.Stat(filepath.Join(outputDir, rel)); err == nil {
			t.Errorf("runtime file leaked to OutputDir/%s when ConfigPath is absolute", rel)
		}
	}
}

// TestApplyVolumeOwnershipChownsFlaggedVolumes verifies that volumes marked
// with chown: true get their host paths chowned to PUID:PGID after directory
// creation. Non-Linux development hosts deliberately skip the syscall; Linux
// runs use the current UID/GID so the required ownership operation succeeds.
func TestApplyVolumeOwnershipChownsFlaggedVolumes(t *testing.T) {
	root := t.TempDir()
	outputDir := filepath.Join(root, "project")

	cfg := config.DefaultConfig()
	cfg.Expose.Mode = "cloudflared"
	cfg.Addons = []string{"filebrowser"}
	cfg.PUID = os.Getuid()
	cfg.PGID = os.Getgid()

	gen := newTestGenerator(t, cfg, outputDir)
	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// filebrowser declares chown: true on the database volume; this dir
	// must exist after Generate (otherwise applyVolumeOwnership would have
	// nothing to chown). With PUID/PGID set to the current user, the chown
	// should actually succeed.
	dbDir := filepath.Join(outputDir, "configs", "filebrowser")
	if _, err := os.Stat(dbDir); err != nil {
		t.Fatalf("expected filebrowser config dir at %s: %v", dbDir, err)
	}
}

func TestApplyVolumeOwnershipRejectsSymlinkedManagedTarget(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("volume ownership is only applied on Linux")
	}
	parent := t.TempDir()
	outputDir := filepath.Join(parent, "project")
	configRoot := filepath.Join(outputDir, "configs")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(configRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(configRoot, "filebrowser")
	if err := os.Symlink(outside, target); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.ConfigPath = configRoot
	cfg.PUID = os.Getuid()
	cfg.PGID = os.Getgid()
	gen := newTestGenerator(t, cfg, outputDir)
	definition := &registry.ServiceDefinition{
		Spec: registry.ServiceSpec{
			Volumes: []registry.VolumeMount{{
				HostPath: target,
				Chown:    true,
			}},
		},
	}
	graph := &registry.ResolutionGraph{
		Order: []string{"filebrowser"},
		Services: map[string]*registry.ResolvedService{
			"filebrowser": {
				Name:            "filebrowser",
				Enabled:         true,
				FinalDefinition: definition,
			},
		},
	}
	before, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}

	err = gen.applyVolumeOwnershipWithPolicy(graph, true)
	if err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("symlinked ownership target error = %v", err)
	}
	after, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode() != after.Mode() {
		t.Fatalf("outside directory metadata changed: before=%v after=%v", before.Mode(), after.Mode())
	}
}

func TestOwnershipVolumeHostPathsUseStrictComposeContract(t *testing.T) {
	outputDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ConfigPath = filepath.Join(outputDir, "configs")
	cfg.VPNEnabled = false
	gen := &Generator{Config: cfg, OutputDir: outputDir}

	definition := &registry.ServiceDefinition{
		Metadata: registry.ServiceMetadata{Name: "example"},
		Spec: registry.ServiceSpec{
			Volumes: []registry.VolumeMount{
				{
					HostPath: "{{ .Config.ConfigPath }}/enabled",
					Chown:    true,
					When:     "{{ not .Config.VPNEnabled }}",
				},
				{
					HostPath: "{{ .Config.ConfigPath }}/disabled",
					Chown:    true,
					When:     "{{ .Config.VPNEnabled }}",
				},
				{
					HostPath: "{{ .Config.ConfigPath }}/no-chown",
					When:     "{{ not .Config.VPNEnabled }}",
				},
			},
		},
	}

	targets, err := gen.ownershipVolumeTargets(definition)
	if err != nil {
		t.Fatalf("ownershipVolumeTargets failed: %v", err)
	}
	want := filepath.Join(cfg.ConfigPath, "enabled")
	if len(targets) != 1 ||
		targets[0].path != want ||
		targets[0].uid != cfg.PUID ||
		targets[0].gid != cfg.PGID {
		t.Fatalf("ownership targets = %#v, want %q at %d:%d", targets, want, cfg.PUID, cfg.PGID)
	}

	definition.Spec.Volumes[0].When = "enabled"
	if _, err := gen.ownershipVolumeTargets(definition); err == nil ||
		!strings.Contains(err.Error(), "expected true or false") {
		t.Fatalf("invalid ownership condition error = %v", err)
	}

	definition.Spec.Volumes[0].When = "true"
	definition.Spec.Volumes[0].HostPath = "{{ .Config.Unknown }}"
	if _, err := gen.ownershipVolumeTargets(definition); err == nil ||
		!strings.Contains(err.Error(), "render example ownership volume 0") {
		t.Fatalf("invalid ownership template error = %v", err)
	}
}

func TestOwnershipVolumeTargetsUseFixedDocumentedIdentity(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.PUID = 2000
	cfg.PGID = 2001
	gen := &Generator{Config: cfg, OutputDir: t.TempDir()}
	definition := &registry.ServiceDefinition{
		Metadata: registry.ServiceMetadata{Name: "fixed-user"},
		Spec: registry.ServiceSpec{
			Volumes: []registry.VolumeMount{{
				HostPath: "{{ .Config.ConfigPath }}/fixed-user",
				Chown:    true,
				ChownUID: 1000,
				ChownGID: 1000,
			}},
		},
	}

	targets, err := gen.ownershipVolumeTargets(definition)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].uid != 1000 || targets[0].gid != 1000 {
		t.Fatalf("fixed ownership targets = %#v", targets)
	}
}

// TestGenerateRelativePathsStillWork is a regression guard: with default
// (relative) paths, generated files must still land under OutputDir as before.
func TestGenerateRelativePathsStillWork(t *testing.T) {
	outputDir := t.TempDir()

	cfg := config.DefaultConfig()
	cfg.Expose.Mode = "cloudflared"

	gen := newTestGenerator(t, cfg, outputDir)
	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	for _, rel := range []string{
		"compose.yaml",
		"configs/traefik/traefik.yml",
		"secrets/authelia_jwt_secret.txt",
	} {
		if _, err := os.Stat(filepath.Join(outputDir, rel)); err != nil {
			t.Errorf("expected %s under OutputDir with relative paths: %v", rel, err)
		}
	}
}

func TestGenerateRejectsRelativeManagedPathSymlinkTraversal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on Windows")
	}
	root := t.TempDir()
	projectDir := filepath.Join(root, "project")
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(projectDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(projectDir, "state")); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.ConfigPath = "state/configs"
	gen := newTestGenerator(t, cfg, projectDir)
	err := gen.Generate()
	if err == nil {
		t.Fatal("Generate accepted a relative managed path through a symlink")
	}
	if !strings.Contains(err.Error(), "traverses symlink") {
		t.Fatalf("error = %q, want symlink traversal rejection", err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("generator wrote outside project through symlink: %#v", entries)
	}
}
