package generator

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/integrate"
	"github.com/get-sdbx/sdbx/internal/registry"
	"gopkg.in/yaml.v3"
)

func newTestGenerator(t *testing.T, cfg *config.Config, outputDir string) *Generator {
	t.Helper()

	sourceCfg := registry.DefaultSourceConfig()
	sourceCfg.Cache.Directory = t.TempDir()

	reg, err := registry.New(sourceCfg)
	if err != nil {
		t.Fatalf("Failed to create test registry: %v", err)
	}

	return NewGeneratorWithRegistry(cfg, outputDir, reg)
}

func TestNewGenerator(t *testing.T) {
	cfg := config.DefaultConfig()
	tmpDir := "/tmp/test"

	gen := NewGenerator(cfg, tmpDir)

	if gen.Config != cfg {
		t.Error("Generator config should match input config")
	}
	if gen.OutputDir != tmpDir {
		t.Errorf("Generator OutputDir = %s, want %s", gen.OutputDir, tmpDir)
	}
}

func TestGenerateDirectoryStructure(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "sdbx-gen-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create generator
	cfg := config.DefaultConfig()
	gen := newTestGenerator(t, cfg, tmpDir)

	// Generate project
	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Verify directories were created
	expectedDirs := []string{
		"configs",
		"configs/traefik",
		"configs/traefik/dynamic",
		"configs/authelia",
		"secrets",
	}

	for _, dir := range expectedDirs {
		path := filepath.Join(tmpDir, dir)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("Directory %s should have been created", dir)
		}
	}
	for _, unexpected := range []string{"configs/gluetun", "configs/homepage"} {
		if _, err := os.Stat(filepath.Join(tmpDir, unexpected)); !os.IsNotExist(err) {
			t.Errorf("unused directory %s should not have been created", unexpected)
		}
	}
}

func TestGenerateWithCloudflared(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "sdbx-gen-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create generator with cloudflared mode
	cfg := config.DefaultConfig()
	cfg.Expose.Mode = "cloudflared"
	gen := newTestGenerator(t, cfg, tmpDir)

	// Generate project
	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Tunnel-token mode is remote-managed. A local ingress file would be
	// silently ignored by cloudflared and must never be generated.
	cloudflaredConfig := filepath.Join(tmpDir, "configs/cloudflared/config.yml")
	if _, err := os.Stat(cloudflaredConfig); !os.IsNotExist(err) {
		t.Fatalf(
			"remote-managed tunnel received a local config: %v",
			err,
		)
	}
}

func TestGenerateWithoutCloudflared(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "sdbx-gen-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create generator with LAN mode (no cloudflared)
	cfg := config.DefaultConfig()
	cfg.Expose.Mode = "lan"
	gen := newTestGenerator(t, cfg, tmpDir)

	// Generate project
	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Verify cloudflared config directory was NOT created
	cloudflaredDir := filepath.Join(tmpDir, "configs/cloudflared")
	if _, err := os.Stat(cloudflaredDir); !os.IsNotExist(err) {
		t.Error("Cloudflared config directory should not exist in LAN mode")
	}
}

func TestGenerateFiles(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "sdbx-gen-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create generator
	cfg := config.DefaultConfig()
	gen := newTestGenerator(t, cfg, tmpDir)

	// Generate project
	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	for _, name := range []string{"traefik", "authelia", "qbittorrent"} {
		if !cfg.ActiveServices[name] {
			t.Errorf("resolved active-service set omitted %s: %v", name, cfg.ActiveServices)
		}
	}
	for _, name := range []string{"plex", "jellyfin", "gluetun", "cloudflared", "filebrowser"} {
		if cfg.ActiveServices[name] {
			t.Errorf("resolved active-service set included disabled %s: %v", name, cfg.ActiveServices)
		}
	}

	// Verify core files were created
	expectedFiles := []string{
		"compose.yaml",
		".env",
		".sdbx.yaml",
		".gitignore",
		"configs/traefik/traefik.yml",
		"configs/traefik/dynamic/middlewares.yml",
		"configs/authelia/configuration.yml",
		"configs/authelia/users_database.yml",
	}

	for _, file := range expectedFiles {
		path := filepath.Join(tmpDir, file)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("File %s should have been created", file)
		}
	}
	for _, unexpected := range []string{
		"configs/homepage/settings.yaml",
		"configs/homepage/services.yaml",
		"configs/homepage/docker.yaml",
		"configs/gluetun/gluetun.env",
	} {
		if _, err := os.Stat(filepath.Join(tmpDir, unexpected)); !os.IsNotExist(err) {
			t.Errorf("unused file %s should not have been created", unexpected)
		}
	}
	gitignore, err := os.ReadFile(filepath.Join(tmpDir, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"/configs/", "/data/", "/secrets/"} {
		if !strings.Contains(string(gitignore), expected+"\n") {
			t.Errorf("generated .gitignore is missing %q", expected)
		}
	}
	for _, redundant := range []string{"/data/downloads/", "/data/media/"} {
		if strings.Contains(string(gitignore), redundant) {
			t.Errorf("generated .gitignore contains redundant %q", redundant)
		}
	}
}

func TestProjectIgnorePatternsDoNotExposeExternalHostPaths(t *testing.T) {
	root := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ConfigPath = "./runtime/config"
	cfg.SecretsPath = "./runtime/secrets"
	cfg.DataPath = "/srv/sdbx-data"
	cfg.DownloadsPath = "/srv/sdbx-downloads"
	cfg.MediaPath = filepath.Join(root, "media")
	generator := &Generator{Config: cfg, OutputDir: root}

	patterns, err := generator.projectIgnorePatterns()
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"/media/", "/runtime/config/", "/runtime/secrets/"}
	if !reflect.DeepEqual(patterns, expected) {
		t.Fatalf("project ignores = %#v, want %#v", patterns, expected)
	}
	for _, pattern := range patterns {
		if strings.Contains(pattern, "/srv/") {
			t.Fatalf("external host path leaked into .gitignore: %q", pattern)
		}
	}
}

func TestProjectIgnorePatternsRejectControlCharacters(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigPath = "./configs\n.env"
	generator := &Generator{Config: cfg, OutputDir: t.TempDir()}

	if _, err := generator.projectIgnorePatterns(); err == nil {
		t.Fatal("control character in managed path was accepted")
	}
}

func TestGenerateSecrets(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "sdbx-gen-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create generator
	cfg := config.DefaultConfig()
	gen := newTestGenerator(t, cfg, tmpDir)

	// Generate project
	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Verify secrets directory was created
	secretsDir := filepath.Join(tmpDir, "secrets")
	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		t.Error("Secrets directory should have been created")
	}

	// Only secrets declared by the resolved graph plus the mandatory console
	// proxy trust set are created.
	entries, err := os.ReadDir(secretsDir)
	if err != nil {
		t.Fatalf("Failed to read secrets dir: %v", err)
	}
	expected := map[string]bool{
		"authelia_jwt_secret.txt":             true,
		"authelia_session_secret.txt":         true,
		"authelia_storage_encryption_key.txt": true,
		"qbittorrent_password.txt":            true,
		"console_proxy_ca.txt":                true,
		"console_proxy_server_cert.txt":       true,
		"console_proxy_server_key.txt":        true,
		"console_proxy_client_cert.txt":       true,
		"console_proxy_client_key.txt":        true,
	}
	if len(entries) != len(expected) {
		t.Fatalf("secret entries = %d, want %d: %v", len(entries), len(expected), entries)
	}
	for _, entry := range entries {
		if !expected[entry.Name()] {
			t.Errorf("unused secret %s was created", entry.Name())
		}
	}
}

func TestGenerateCreatesOnlyResolvedServiceConfigsAndCredentials(t *testing.T) {
	root := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Expose.Mode = config.ExposeModeCloudflared
	cfg.VPNEnabled = true
	cfg.VPNProvider = "mullvad"
	cfg.PlexEnabled = true
	cfg.Addons = []string{"filebrowser"}
	gen := newTestGenerator(t, cfg, root)
	if err := gen.Generate(); err != nil {
		t.Fatal(err)
	}

	for _, expected := range []string{
		"configs/gluetun/gluetun.env",
		"secrets/authelia_jwt_secret.txt",
		"secrets/cloudflared_tunnel_token.txt",
		"secrets/plex_claim_token.txt",
		"secrets/qbittorrent_password.txt",
		"secrets/filebrowser_admin_password.txt",
	} {
		if _, err := os.Stat(filepath.Join(root, expected)); err != nil {
			t.Errorf("resolved service asset %s: %v", expected, err)
		}
	}
	for _, name := range []string{
		"authelia_jwt_secret.txt",
		"authelia_session_secret.txt",
		"authelia_storage_encryption_key.txt",
		"cloudflared_tunnel_token.txt",
	} {
		info, err := os.Stat(filepath.Join(root, "secrets", name))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o644 {
			t.Fatalf("%s mode = %o, want 644", name, got)
		}
	}
	if _, err := os.Stat(
		filepath.Join(root, "secrets", "vpn_password.txt"),
	); !os.IsNotExist(err) {
		t.Fatal("obsolete unused VPN password placeholder was generated")
	}

	gluetunConfig, err := os.ReadFile(
		filepath.Join(root, "configs", "gluetun", "gluetun.env"),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, currentSetting := range []string{
		"DNS_UPSTREAM_RESOLVER_TYPE=dot",
		"DNS_UPSTREAM_RESOLVERS=cloudflare",
		"UPDATER_PERIOD=0",
		"HTTP_CONTROL_SERVER_ADDRESS=127.0.0.1:8000",
		"HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH=/run/sdbx/gluetun-control-auth-disabled.toml",
		"HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE={}",
	} {
		if !strings.Contains(string(gluetunConfig), currentSetting) {
			t.Fatalf("gluetun.env is missing %q", currentSetting)
		}
	}
	if strings.Contains(string(gluetunConfig), "UPDATER_PERIOD=480h") {
		t.Fatal("gluetun.env re-enabled the vulnerable provider metadata updater")
	}
	for _, deprecatedSetting := range []string{"DOT=", "DOT_PROVIDERS="} {
		if strings.Contains(string(gluetunConfig), deprecatedSetting) {
			t.Fatalf("gluetun.env still contains deprecated %q", deprecatedSetting)
		}
	}
}

func TestGeneratedCatalogSecurityDispositionPolicy(t *testing.T) {
	root := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Domain = "media.example.test"
	cfg.Expose.Mode = config.ExposeModeCloudflared
	cfg.VPNEnabled = true
	cfg.VPNProvider = "mullvad"
	cfg.PlexEnabled = true
	cfg.JellyfinEnabled = true
	cfg.Addons = []string{"sonarr"}

	gen := newTestGenerator(t, cfg, root)
	if err := gen.Generate(); err != nil {
		t.Fatal(err)
	}

	composeBody, err := os.ReadFile(filepath.Join(root, "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var compose ComposeFile
	if err := yaml.Unmarshal(composeBody, &compose); err != nil {
		t.Fatalf("invalid generated Compose: %v\n%s", err, composeBody)
	}

	assertNoLinuxServerExtensions := func(serviceName string) {
		t.Helper()
		service := compose.Services[serviceName]
		if service.Command != "" {
			t.Fatalf("%s command = %q, want image default", serviceName, service.Command)
		}
		for _, environment := range service.Environment {
			if strings.HasPrefix(environment, "DOCKER_MODS=") {
				t.Fatalf("%s enables Docker Mods: %q", serviceName, environment)
			}
		}
		for _, volume := range service.Volumes {
			if strings.Contains(volume, ":/custom-cont-init.d") ||
				strings.Contains(volume, "mod-pip-packages-to-install") {
				t.Fatalf("%s exposes extension input %q", serviceName, volume)
			}
		}
	}
	for _, serviceName := range []string{"plex", "jellyfin", "qbittorrent", "sonarr"} {
		assertNoLinuxServerExtensions(serviceName)
	}

	plex := compose.Services["plex"]
	if !contains(plex.Environment, "VERSION=docker") {
		t.Fatalf("Plex environment = %#v, want immutable image-managed version", plex.Environment)
	}
	for _, suffix := range []string{
		":/media/movies:ro",
		":/media/tv:ro",
		":/media/music:ro",
		":/media/concerts:ro",
	} {
		if !containsSuffix(plex.Volumes, suffix) {
			t.Fatalf("Plex volumes = %#v, missing %q", plex.Volumes, suffix)
		}
	}
	for _, volume := range plex.Volumes {
		if strings.HasSuffix(volume, ":/media:ro") ||
			strings.Contains(volume, "/stash:/media/") {
			t.Fatalf("Plex receives broad or Stash media mount %q", volume)
		}
	}

	jellyfin := compose.Services["jellyfin"]
	for _, suffix := range []string{":/data/media:ro", ":/data/downloads:ro"} {
		if !containsSuffix(jellyfin.Volumes, suffix) {
			t.Fatalf("Jellyfin volumes = %#v, missing %q", jellyfin.Volumes, suffix)
		}
	}

	cloudflared := compose.Services["cloudflared"]
	if cloudflared.Command != "tunnel run" ||
		!cloudflared.ReadOnly ||
		!contains(cloudflared.CapDrop, "ALL") ||
		len(cloudflared.Networks) != 1 ||
		cloudflared.Networks[0] != registry.NetworkEdge ||
		len(cloudflared.Volumes) != 0 {
		t.Fatalf("Cloudflared execution policy = %#v", cloudflared)
	}

	autheliaBody, err := os.ReadFile(
		filepath.Join(root, "configs", "authelia", "configuration.yml"),
	)
	if err != nil {
		t.Fatal(err)
	}
	autheliaText := string(autheliaBody)
	for _, required := range []string{
		"authentication_backend:\n  file:",
		"webauthn:\n  metadata:\n    enabled: false",
		"storage:\n  local:",
		"notifier:\n  filesystem:",
	} {
		if !strings.Contains(autheliaText, required) {
			t.Fatalf("Authelia policy missing %q:\n%s", required, autheliaBody)
		}
	}
	for _, forbidden := range []string{
		"ldap:",
		"mysql:",
		"postgres:",
		"redis:",
		"smtp:",
	} {
		if strings.Contains(autheliaText, forbidden) {
			t.Fatalf("Authelia policy unexpectedly enables %q:\n%s", forbidden, autheliaBody)
		}
	}

	traefikBody, err := os.ReadFile(
		filepath.Join(root, "configs", "traefik", "traefik.yml"),
	)
	if err != nil {
		t.Fatal(err)
	}
	traefikText := string(traefikBody)
	for _, required := range []string{
		"checkNewVersion: false",
		"sendAnonymousUsage: false",
		"providers:\n  file:",
	} {
		if !strings.Contains(traefikText, required) {
			t.Fatalf("Traefik policy missing %q:\n%s", required, traefikBody)
		}
	}
	for _, forbidden := range []string{
		"dnsChallenge:",
		"experimental:",
		"plugins:",
		"providers:\n  docker:",
	} {
		if strings.Contains(traefikText, forbidden) {
			t.Fatalf("Traefik policy unexpectedly enables %q:\n%s", forbidden, traefikBody)
		}
	}

	gluetunBody, err := os.ReadFile(
		filepath.Join(root, "configs", "gluetun", "gluetun.env"),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"UPDATER_PERIOD=0",
		"HTTP_CONTROL_SERVER_ADDRESS=127.0.0.1:8000",
		"HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH=/run/sdbx/gluetun-control-auth-disabled.toml",
		"HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE={}",
	} {
		if !strings.Contains(string(gluetunBody), required) {
			t.Fatalf("Gluetun policy missing %q:\n%s", required, gluetunBody)
		}
	}
}

func containsSuffix(values []string, suffix string) bool {
	for _, value := range values {
		if strings.HasSuffix(value, suffix) {
			return true
		}
	}
	return false
}

func TestGenerateStagesArrAuthentication(t *testing.T) {
	root := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Addons = []string{"sonarr"}
	gen := newTestGenerator(t, cfg, root)
	if err := gen.Generate(); err != nil {
		t.Fatal(err)
	}
	arrConfig := filepath.Join(root, "configs", "sonarr", "config.xml")
	data, err := os.ReadFile(arrConfig)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"<ApiKey>",
		"<AuthenticationMethod>Forms</AuthenticationMethod>",
		"<AuthenticationRequired>Enabled</AuthenticationRequired>",
	} {
		if !strings.Contains(string(data), expected) {
			t.Fatalf("staged Sonarr config omitted %q:\n%s", expected, data)
		}
	}
}

func TestGenerateUsesPrivateModesForSensitiveFiles(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.AdminUser = "admin"
	cfg.AdminPasswordHash = "$argon2id$test-hash"
	gen := newTestGenerator(t, cfg, tmpDir)

	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	privateFiles := []string{
		".env",
		".sdbx.yaml",
		"configs/authelia/users_database.yml",
	}
	for _, relative := range privateFiles {
		info, err := os.Stat(filepath.Join(tmpDir, relative))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("%s mode = %o, want 600", relative, got)
		}
	}

	secretsInfo, err := os.Stat(filepath.Join(tmpDir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	if got := secretsInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("secrets directory mode = %o, want 700", got)
	}
}

func TestGeneratedOutputsNeverContainSecretCanary(t *testing.T) {
	tmpDir := t.TempDir()
	secretsDir := filepath.Join(tmpDir, "secrets")
	if err := os.Mkdir(secretsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	canary := "SDBX_SECRET_CANARY_8b1f9465"
	for _, name := range []string{"plex_claim_token.txt", "cloudflared_tunnel_token.txt"} {
		if err := os.WriteFile(filepath.Join(secretsDir, name), []byte(canary), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cfg := config.DefaultConfig()
	cfg.Expose.Mode = config.ExposeModeCloudflared
	gen := newTestGenerator(t, cfg, tmpDir)
	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	err := filepath.WalkDir(tmpDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && path == secretsDir {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), canary) {
			t.Errorf("secret canary leaked into generated file %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	envData, err := os.ReadFile(filepath.Join(tmpDir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(envData), "PLEX_CLAIM") ||
		strings.Contains(string(envData), "TUNNEL_TOKEN") {
		t.Fatalf(".env still exposes secret variables:\n%s", envData)
	}
}

func TestCreateDataDirs(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "sdbx-gen-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create generator with relative paths
	cfg := config.DefaultConfig()
	cfg.MediaPath = filepath.Join(tmpDir, "media")
	cfg.DownloadsPath = filepath.Join(tmpDir, "downloads")
	gen := NewGenerator(cfg, tmpDir)

	// Create data directories
	if err := gen.CreateDataDirs(); err != nil {
		t.Fatalf("CreateDataDirs failed: %v", err)
	}

	// Verify directories were created
	expectedDirs := []string{
		filepath.Join(tmpDir, "downloads"),
		filepath.Join(tmpDir, "media/movies"),
		filepath.Join(tmpDir, "media/tv"),
		filepath.Join(tmpDir, "media/music"),
		filepath.Join(tmpDir, "media/books"),
	}

	for _, dir := range expectedDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("Directory %s should have been created", dir)
		}
	}
}

func TestGenerateWithAddons(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "sdbx-gen-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create generator with addons enabled
	cfg := config.DefaultConfig()
	cfg.Addons = []string{"filebrowser", "radarr"}
	gen := newTestGenerator(t, cfg, tmpDir)

	// Generate project
	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Verify config directories for addons were created
	filebrowserDir := filepath.Join(tmpDir, "configs/filebrowser")
	if _, err := os.Stat(filebrowserDir); os.IsNotExist(err) {
		t.Error("File Browser config directory should have been created")
	}

	radarrDir := filepath.Join(tmpDir, "configs/radarr")
	if _, err := os.Stat(radarrDir); os.IsNotExist(err) {
		t.Error("Radarr config directory should have been created")
	}
}

func TestGenerateAllEmbeddedAddonsRuntimeArtifacts(t *testing.T) {
	root := os.Getenv("SDBX_GENERATOR_SMOKE_OUTPUT")
	if root == "" {
		root = t.TempDir()
	} else if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	addons, err := registry.NewEmbeddedSource().GetAddonServices()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Domain = "all-addons.example.test"
	cfg.Expose.Mode = config.ExposeModeLAN
	cfg.Routing.Strategy = config.RoutingStrategySubdomain
	cfg.PlexEnabled = true
	cfg.JellyfinEnabled = true
	cfg.Addons = make([]string, 0, len(addons))
	for _, addon := range addons {
		cfg.Addons = append(cfg.Addons, addon.Metadata.Name)
	}

	gen := newTestGenerator(t, cfg, root)
	if err := gen.Generate(); err != nil {
		t.Fatalf("all-addons generation failed: %v", err)
	}

	composeBody, err := os.ReadFile(filepath.Join(root, "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var compose ComposeFile
	if err := yaml.Unmarshal(composeBody, &compose); err != nil {
		t.Fatalf("parse generated Compose: %v", err)
	}
	for _, addon := range addons {
		if _, exists := compose.Services[addon.Metadata.Name]; !exists {
			t.Errorf("enabled addon %s is absent from generated Compose", addon.Metadata.Name)
		}
	}
	if _, exists := compose.Services["homepage"]; exists {
		t.Fatal("retired Homepage addon is present in generated Compose")
	}
	for _, name := range []string{
		"cobalt_keys",
		"unpackerr_lidarr_api_key",
		"unpackerr_radarr_api_key",
		"unpackerr_sonarr_api_key",
		"unpackerr_whisparr_api_key",
	} {
		if _, exists := compose.Secrets[name]; !exists {
			t.Errorf("generated Compose is missing secret %s", name)
		}
	}
	cobalt := compose.Services["cobalt"]
	for _, expected := range []string{
		"API_AUTH_REQUIRED=1",
		"CORS_WILDCARD=0",
		"CORS_URL=https://cobalt.tools",
	} {
		if !contains(cobalt.Environment, expected) {
			t.Errorf("generated Cobalt environment is missing %q", expected)
		}
	}

	cobaltKeys, err := os.ReadFile(
		filepath.Join(root, "secrets", "cobalt_keys.txt"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := integrate.ValidateCobaltKeys(cobaltKeys); err != nil {
		t.Fatalf("generated Cobalt key map is invalid: %v", err)
	}

	unpackerrEnv, err := os.ReadFile(
		filepath.Join(root, "configs", "unpackerr", "sdbx.env"),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []string{"SONARR", "RADARR", "LIDARR", "WHISPARR"} {
		for _, expected := range []string{
			"UN_" + service + "_0_URL=http://sdbx-",
			"UN_" + service + "_0_API_KEY=filepath:/run/secrets/unpackerr_",
			"UN_" + service + "_0_PATHS_0=/downloads",
		} {
			if !strings.Contains(string(unpackerrEnv), expected) {
				t.Errorf("generated Unpackerr environment is missing %q", expected)
			}
		}
	}
	for _, service := range []string{"sonarr", "radarr", "lidarr", "whisparr"} {
		key, err := os.ReadFile(
			filepath.Join(root, "secrets", "unpackerr_"+service+"_api_key.txt"),
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(strings.TrimSpace(string(key))) == 0 {
			t.Errorf("generated Unpackerr %s API-key copy is empty", service)
		}
		if strings.Contains(string(unpackerrEnv), strings.TrimSpace(string(key))) {
			t.Errorf("generated Unpackerr environment leaks the %s API key", service)
		}
	}
}

func TestGenerateFileContent(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "sdbx-gen-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create generator with test values
	cfg := config.DefaultConfig()
	cfg.Domain = "test.example.com"
	cfg.Timezone = "America/New_York"
	gen := newTestGenerator(t, cfg, tmpDir)

	// Generate project
	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Read .env file and verify it contains config values
	envFile := filepath.Join(tmpDir, ".env")
	content, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("Failed to read .env file: %v", err)
	}

	envContent := string(content)
	if len(envContent) == 0 {
		t.Error(".env file should not be empty")
	}

	// Read compose.yaml and verify it exists and has content
	composeFile := filepath.Join(tmpDir, "compose.yaml")
	composeContent, err := os.ReadFile(composeFile)
	if err != nil {
		t.Fatalf("Failed to read compose.yaml: %v", err)
	}

	if len(composeContent) == 0 {
		t.Error("compose.yaml file should not be empty")
	}
}
