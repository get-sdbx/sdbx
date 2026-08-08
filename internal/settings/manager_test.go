package settings

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

func TestManagerSetDomainRegeneratesRuntimeFiles(t *testing.T) {
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Domain = "old.sdbx.one"
	manager := testManager(t, projectDir, cfg)

	result, err := manager.Set(context.Background(), "domain", "new.sdbx.one")
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	if result.Key != "domain" || result.Value != "new.sdbx.one" || !result.Regenerated {
		t.Fatalf("result = %#v, want domain update with regeneration", result)
	}

	sdbxConfig := readFile(t, filepath.Join(projectDir, ".sdbx.yaml"))
	if !strings.Contains(sdbxConfig, "domain: new.sdbx.one") {
		t.Fatalf(".sdbx.yaml did not contain new domain:\n%s", sdbxConfig)
	}
	routes := readFile(
		t,
		filepath.Join(projectDir, "configs", "traefik", "dynamic", "middlewares.yml"),
	)
	if !strings.Contains(routes, "Host(`") || !strings.Contains(routes, ".new.sdbx.one") {
		t.Fatalf("Traefik routes did not contain new domain:\n%s", routes)
	}
}

func TestManagerSetParsesTypedValues(t *testing.T) {
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	manager := testManager(t, projectDir, cfg)

	if _, err := manager.Set(context.Background(), "puid", "1234"); err != nil {
		t.Fatalf("Set puid failed: %v", err)
	}
	if cfg.PUID != 1234 {
		t.Fatalf("PUID = %d, want 1234", cfg.PUID)
	}

	if _, err := manager.Set(context.Background(), "vpn_provider", "nordvpn"); err != nil {
		t.Fatalf("Set vpn_provider failed: %v", err)
	}
	if _, err := manager.Set(context.Background(), "vpn_enabled", "true"); err != nil {
		t.Fatalf("Set vpn_enabled failed: %v", err)
	}
	if !cfg.VPNEnabled {
		t.Fatal("VPNEnabled = false, want true")
	}
	if _, err := manager.Set(context.Background(), "torrent_peer_port", "51413"); err != nil {
		t.Fatalf("Set torrent_peer_port failed: %v", err)
	}
	if cfg.TorrentPort != 51413 {
		t.Fatalf("TorrentPort = %d, want 51413", cfg.TorrentPort)
	}
	if _, err := manager.Set(
		context.Background(),
		"auth.factor",
		config.AuthFactorTwo,
	); err != nil {
		t.Fatalf("Set auth.factor failed: %v", err)
	}
	if cfg.Auth.Factor != config.AuthFactorTwo {
		t.Fatalf("Auth factor = %q, want two_factor", cfg.Auth.Factor)
	}
	authelia := readFile(
		t,
		filepath.Join(projectDir, "configs", "authelia", "configuration.yml"),
	)
	if !strings.Contains(authelia, `policy: "two_factor"`) {
		t.Fatalf("Authelia policy did not regenerate as two_factor:\n%s", authelia)
	}
}

func TestManagerSetsACMEContactBeforeDirectExposure(t *testing.T) {
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	manager := testManager(t, projectDir, cfg)

	if _, err := manager.Set(
		context.Background(),
		"expose.mode",
		"direct",
	); err == nil || !strings.Contains(err.Error(), "ACME contact email") {
		t.Fatalf("direct exposure without email error = %v", err)
	}
	if cfg.Expose.Mode != config.ExposeModeLAN {
		t.Fatalf("failed direct change was not rolled back: %q", cfg.Expose.Mode)
	}
	if _, err := manager.Set(
		context.Background(),
		"expose.tls.email",
		"ops@example.test",
	); err != nil {
		t.Fatalf("Set ACME contact failed: %v", err)
	}
	if _, err := manager.Set(
		context.Background(),
		"expose.mode",
		"direct",
	); err != nil {
		t.Fatalf("Set direct exposure failed: %v", err)
	}
	if cfg.Expose.TLS.Provider != "acme" {
		t.Fatalf("TLS provider = %q, want acme", cfg.Expose.TLS.Provider)
	}
}

func TestManagerClearsACMEStateOutsideDirectExposure(t *testing.T) {
	for _, mode := range []string{
		config.ExposeModeLAN,
		config.ExposeModeCloudflared,
	} {
		t.Run(mode, func(t *testing.T) {
			projectDir := t.TempDir()
			cfg := config.DefaultConfig()
			cfg.Expose.Mode = config.ExposeModeDirect
			cfg.Expose.TLS.Provider = "acme"
			cfg.Expose.TLS.Email = "ops@example.test"
			manager := testManager(t, projectDir, cfg)

			if _, err := manager.Set(
				context.Background(),
				"expose.mode",
				mode,
			); err != nil {
				t.Fatalf("Set exposure failed: %v", err)
			}
			if cfg.Expose.TLS.Provider != "" {
				t.Fatalf(
					"TLS provider = %q, want empty",
					cfg.Expose.TLS.Provider,
				)
			}
			if cfg.Expose.TLS.Email != "" {
				t.Fatalf("TLS email = %q, want empty", cfg.Expose.TLS.Email)
			}
		})
	}
}

func TestManagerSetRefusesUnacknowledgedVPNDisable(t *testing.T) {
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.VPNEnabled = true
	cfg.VPNProvider = "custom"
	manager := testManager(t, projectDir, cfg)

	for _, value := range []string{"false", "FALSE", "False"} {
		_, err := manager.Set(context.Background(), "vpn_enabled", value)
		if err == nil {
			t.Fatalf("Set vpn_enabled=%q succeeded without acknowledgement", value)
		}
		if !strings.Contains(err.Error(), "explicit acknowledgement") {
			t.Fatalf("Set vpn_enabled=%q error = %q", value, err)
		}
		if !cfg.VPNEnabled {
			t.Fatalf("VPNEnabled changed after rejected value %q", value)
		}
	}
}

func TestManagerSetAllowsAcknowledgedVPNDisable(t *testing.T) {
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.VPNEnabled = true
	cfg.VPNProvider = "custom"
	manager := testManager(t, projectDir, cfg)
	manager.AllowUnprotectedDownloads = true

	if _, err := manager.Set(context.Background(), "vpn_enabled", "FALSE"); err != nil {
		t.Fatalf("acknowledged disable failed: %v", err)
	}
	if cfg.VPNEnabled {
		t.Fatal("VPNEnabled = true after acknowledged disable")
	}
}

func TestManagerSetRejectsInvalidTorrentPeerPortAndRestoresConfig(t *testing.T) {
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	manager := testManager(t, projectDir, cfg)

	for _, value := range []string{"0", "65536", "not-a-port"} {
		_, err := manager.Set(context.Background(), "torrent_peer_port", value)
		if err == nil {
			t.Fatalf("Set torrent_peer_port=%q succeeded", value)
		}
		if cfg.TorrentPort != 6881 {
			t.Fatalf("TorrentPort = %d after rejected value %q, want 6881", cfg.TorrentPort, value)
		}
	}
}

func TestManagerSetRejectsInvalidValuesAndRestoresConfig(t *testing.T) {
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Domain = "valid.sdbx.one"
	manager := testManager(t, projectDir, cfg)

	_, err := manager.Set(context.Background(), "domain", "invalid_domain")
	if err == nil {
		t.Fatal("Set succeeded for invalid domain")
	}
	if cfg.Domain != "valid.sdbx.one" {
		t.Fatalf("Domain = %q, want rollback to valid.sdbx.one", cfg.Domain)
	}
}

func TestManagerSetRequiresVerifiedLock(t *testing.T) {
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Timezone = "Europe/Paris"
	reg, err := registry.New(&registry.SourceConfig{
		APIVersion: registry.APIVersion,
		Kind:       registry.KindSourceConfig,
		Cache: registry.CacheConfig{
			Directory: filepath.Join(t.TempDir(), "cache"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	manager := &Manager{
		ProjectDir: projectDir,
		Config:     cfg,
		Registry:   reg,
	}

	_, err = manager.Set(context.Background(), "timezone", "UTC")
	if err == nil || !strings.Contains(err.Error(), ".sdbx.lock is required") {
		t.Fatalf("Set() error = %v, want lock requirement", err)
	}
	if cfg.Timezone != "Europe/Paris" {
		t.Fatalf("failed unlocked mutation left timezone %q", cfg.Timezone)
	}
}

func TestManagerSetPreservesUserDatabaseAndRefreshesManagedPolicyAndEnv(t *testing.T) {
	projectDir := t.TempDir()
	userDatabase := filepath.Join(projectDir, "configs", "authelia", "users_database.yml")
	if err := os.MkdirAll(filepath.Dir(userDatabase), 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(userDatabase, []byte("custom users database"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	envPath := filepath.Join(projectDir, ".env")
	if err := os.WriteFile(envPath, []byte("PLEX_CLAIM=claim-token\nTUNNEL_TOKEN=tunnel-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	manager := testManager(t, projectDir, config.DefaultConfig())

	if _, err := manager.Set(context.Background(), "timezone", "UTC"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	if got := readFile(t, userDatabase); got != "custom users database" {
		t.Fatalf("user database was overwritten: %q", got)
	}
	env := readFile(t, envPath)
	if strings.Contains(env, "claim-token") || strings.Contains(env, "tunnel-token") {
		t.Fatalf("legacy secret-bearing .env content survived: %q", env)
	}
	if !strings.Contains(env, "SDBX_TIMEZONE=UTC") {
		t.Fatalf("managed .env was not refreshed: %q", env)
	}
	policy := readFile(
		t,
		filepath.Join(projectDir, "configs", "authelia", "configuration.yml"),
	)
	if !strings.Contains(policy, "default_policy: deny") {
		t.Fatalf("managed Authelia policy was not refreshed:\n%s", policy)
	}
}

func TestValuesReturnsCanonicalReadableSettings(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "media.sdbx.one"
	cfg.Expose.Mode = "direct"
	cfg.Expose.TLS.Email = "ops@example.test"
	cfg.Routing.Strategy = "path"
	cfg.Routing.BaseDomain = "box"
	cfg.PUID = 501
	cfg.VPNEnabled = true
	cfg.VPNProvider = "protonvpn"
	cfg.Addons = []string{"sonarr", "radarr"}

	values := Values(cfg)

	tests := map[string]interface{}{
		"domain":              "media.sdbx.one",
		"expose.mode":         "direct",
		"expose.tls.email":    "ops@example.test",
		"routing.strategy":    "path",
		"routing.base_domain": "box",
		"auth.factor":         config.AuthFactorOne,
		"puid":                501,
		"vpn_enabled":         true,
		"vpn_provider":        "protonvpn",
		"torrent_peer_port":   6881,
		"addons":              []string{"sonarr", "radarr"},
	}
	for key, want := range tests {
		if got := values[key]; !reflect.DeepEqual(got, want) {
			t.Fatalf("Values(%q) = %#v, want %#v", key, got, want)
		}
	}
}

func TestFieldsDescribeEditableSettings(t *testing.T) {
	fields := Fields()

	exposure := findField(fields, "expose.mode")
	if exposure == nil {
		t.Fatal("Fields missing expose.mode")
	}
	if exposure.Type != "select" {
		t.Fatalf("expose.mode Type = %q, want select", exposure.Type)
	}
	wantExposureOptions := []string{"lan", "direct", "cloudflared"}
	if !reflect.DeepEqual(exposure.Options, wantExposureOptions) {
		t.Fatalf("expose.mode Options = %#v, want %#v", exposure.Options, wantExposureOptions)
	}
	if !exposure.Editable {
		t.Fatal("expose.mode should be editable")
	}
	authFactor := findField(fields, "auth.factor")
	if authFactor == nil || !authFactor.Editable || authFactor.Type != "select" {
		t.Fatalf("auth.factor metadata = %#v", authFactor)
	}
	if !reflect.DeepEqual(
		authFactor.Options,
		[]string{config.AuthFactorOne, config.AuthFactorTwo},
	) {
		t.Fatalf("auth.factor options = %#v", authFactor.Options)
	}
	if email := findField(fields, "expose.tls.email"); email == nil {
		t.Fatal("Fields missing expose.tls.email")
	} else if !email.Editable || email.Type != "text" {
		t.Fatalf("expose.tls.email metadata = %#v", email)
	}
	for _, key := range []string{
		"config_path",
		"data_path",
		"downloads_path",
		"media_path",
		"secrets_path",
	} {
		field := findField(fields, key)
		if field == nil {
			t.Fatalf("Fields missing %s", key)
		}
		if field.Editable {
			t.Fatalf("%s should be read-only in remote settings metadata", key)
		}
	}

	vpnEnabled := findField(fields, "vpn_enabled")
	if vpnEnabled == nil {
		t.Fatal("Fields missing vpn_enabled")
	}
	if vpnEnabled.Type != "boolean" {
		t.Fatalf("vpn_enabled Type = %q, want boolean", vpnEnabled.Type)
	}
	peerPort := findField(fields, "torrent_peer_port")
	if peerPort == nil {
		t.Fatal("Fields missing torrent_peer_port")
	}
	if peerPort.Type != "number" {
		t.Fatalf("torrent_peer_port Type = %q, want number", peerPort.Type)
	}

	addons := findField(fields, "addons")
	if addons == nil {
		t.Fatal("Fields missing addons")
	}
	if addons.Editable {
		t.Fatal("addons should be read-only in settings metadata")
	}
}

func findField(fields []Field, key string) *Field {
	for i := range fields {
		if fields[i].Key == key {
			return &fields[i]
		}
	}
	return nil
}

func testManager(t *testing.T, projectDir string, cfg *config.Config) *Manager {
	t.Helper()
	cfg.ProjectDir = projectDir
	reg, err := registry.New(&registry.SourceConfig{
		APIVersion: registry.APIVersion,
		Kind:       registry.KindSourceConfig,
		Cache: registry.CacheConfig{
			Directory: filepath.Join(t.TempDir(), "cache"),
		},
	})
	if err != nil {
		t.Fatalf("registry.New failed: %v", err)
	}
	imageResolver := registry.NewOfficialImageDigestResolver(nil)
	lock, _, err := reg.GenerateLockFileWithOptions(
		context.Background(),
		cfg,
		registry.LockOptions{
			CLIVersion:    "test",
			ImageResolver: imageResolver,
		},
	)
	if err != nil {
		t.Fatalf("GenerateLockFileWithOptions failed: %v", err)
	}
	return &Manager{
		ProjectDir:    projectDir,
		Config:        cfg,
		Registry:      reg,
		Lock:          lock,
		CLIVersion:    "test",
		ImageResolver: imageResolver,
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) failed: %v", path, err)
	}
	return string(data)
}
