package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Domain != "sdbx.example.com" {
		t.Errorf("Domain = %s, want sdbx.example.com", cfg.Domain)
	}
	if cfg.Expose.Mode != ExposeModeLAN {
		t.Errorf("Expose.Mode = %s, want lan", cfg.Expose.Mode)
	}
	if cfg.Expose.TLS.Provider != "" {
		t.Errorf("LAN TLS provider = %q, want derived empty value", cfg.Expose.TLS.Provider)
	}
	if cfg.Auth.Factor != AuthFactorOne {
		t.Errorf("Auth.Factor = %q, want %q", cfg.Auth.Factor, AuthFactorOne)
	}
	if cfg.PlexEnabled || cfg.JellyfinEnabled {
		t.Errorf(
			"new project media defaults = plex:%t jellyfin:%t, want explicit selection",
			cfg.PlexEnabled,
			cfg.JellyfinEnabled,
		)
	}
	if cfg.PUID != 1000 {
		t.Errorf("PUID = %d, want 1000", cfg.PUID)
	}
	if cfg.PGID != 1000 {
		t.Errorf("PGID = %d, want 1000", cfg.PGID)
	}
}

func TestTunnelProtocolConfiguration(t *testing.T) {
	for _, protocol := range []string{"", "http2", "quic", "auto", "udp", "HTTP2", "http2\nquic"} {
		t.Run(fmt.Sprintf("protocol=%q", protocol), func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Expose.TunnelProtocol = protocol
			err := cfg.Validate()
			valid := protocol == "" || protocol == "http2" || protocol == "quic" || protocol == "auto"
			if valid && err != nil {
				t.Fatal(err)
			}
			if !valid {
				var validationErr *ValidationError
				if !errors.As(err, &validationErr) || validationErr.Field != "expose.tunnel_protocol" {
					t.Fatalf("Validate = %v, want tunnel protocol validation", err)
				}
				return
			}
			want := protocol
			if want == "" {
				want = "http2"
			}
			if cfg.EffectiveTunnelProtocol() != want {
				t.Fatalf("effective protocol = %q, want %q", cfg.EffectiveTunnelProtocol(), want)
			}
		})
	}
}

func TestLoadTunnelProtocolDefaultsAndRoundTrips(t *testing.T) {
	for _, protocol := range []string{"", "http2", "quic", "auto"} {
		t.Run("protocol="+protocol, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			dir := t.TempDir()
			path := filepath.Join(dir, ".sdbx.yaml")
			data := "domain: media.example.test\nexpose:\n  mode: cloudflared\n"
			want := protocol
			if protocol != "" {
				data += "  tunnel_protocol: " + protocol + "\n"
			} else {
				want = "http2"
			}
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			viper.SetConfigFile(path)
			for _, load := range []func() (*Config, error){Load, func() (*Config, error) { return LoadFile(path) }} {
				cfg, err := load()
				if err != nil {
					t.Fatal(err)
				}
				if cfg.Expose.TunnelProtocol != want {
					t.Fatalf("loaded protocol = %q, want %q", cfg.Expose.TunnelProtocol, want)
				}
				if err := cfg.SaveFile(path); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestValidateRejectsUnsupportedAuthenticationFactor(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Auth.Factor = "password_and_vibes"
	err := cfg.Validate()
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) || validationErr.Field != "auth.factor" {
		t.Fatalf("Validate error = %v, want auth.factor validation", err)
	}
}

func TestSetExposureModeKeepsTLSIntentCoherent(t *testing.T) {
	for _, test := range []struct {
		name         string
		mode         string
		wantProvider string
		wantEmail    string
	}{
		{
			name:         "direct keeps contact and selects acme",
			mode:         ExposeModeDirect,
			wantProvider: "acme",
			wantEmail:    "ops@example.test",
		},
		{
			name:      "lan removes obsolete acme state",
			mode:      ExposeModeLAN,
			wantEmail: "",
		},
		{
			name:      "cloudflared removes obsolete acme state",
			mode:      ExposeModeCloudflared,
			wantEmail: "",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Expose.TLS.Provider = "stale-provider"
			cfg.Expose.TLS.Email = "ops@example.test"

			cfg.SetExposureMode(test.mode)

			if cfg.Expose.Mode != test.mode {
				t.Fatalf("mode = %q, want %q", cfg.Expose.Mode, test.mode)
			}
			if cfg.Expose.TLS.Provider != test.wantProvider {
				t.Fatalf(
					"provider = %q, want %q",
					cfg.Expose.TLS.Provider,
					test.wantProvider,
				)
			}
			if cfg.Expose.TLS.Email != test.wantEmail {
				t.Fatalf(
					"email = %q, want %q",
					cfg.Expose.TLS.Email,
					test.wantEmail,
				)
			}
		})
	}
}

func TestLoadMigratesLegacyImplicitPlexButPreservesExplicitNoMedia(t *testing.T) {
	tests := []struct {
		name         string
		mediaYAML    string
		wantPlex     bool
		wantJellyfin bool
	}{
		{
			name:     "legacy config",
			wantPlex: true,
		},
		{
			name:      "explicit no media",
			mediaYAML: "plex_enabled: false\njellyfin_enabled: false\n",
		},
		{
			name:         "explicit jellyfin",
			mediaYAML:    "plex_enabled: false\njellyfin_enabled: true\n",
			wantJellyfin: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			path := filepath.Join(t.TempDir(), ".sdbx.yaml")
			body := "domain: box.example.test\n" +
				"timezone: UTC\n" +
				"expose:\n  mode: lan\n" +
				"routing:\n  strategy: subdomain\n" +
				test.mediaYAML
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			viper.SetConfigFile(path)
			cfg, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.PlexEnabled != test.wantPlex ||
				cfg.JellyfinEnabled != test.wantJellyfin {
				t.Fatalf(
					"media = plex:%t jellyfin:%t, want plex:%t jellyfin:%t",
					cfg.PlexEnabled,
					cfg.JellyfinEnabled,
					test.wantPlex,
					test.wantJellyfin,
				)
			}
		})
	}
}

func TestLoadFileIsStrictExplicitAndIndependentOfViper(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("domain", "poisoned.example.test")

	projectDir := t.TempDir()
	path := filepath.Join(projectDir, ".sdbx.yaml")
	body := `domain: file.example.test
timezone: UTC
expose:
  mode: lan
routing:
  strategy: subdomain
  base_domain: box
config_path: ./configs
data_path: ./data
downloads_path: ./data/downloads
media_path: ./data/media
secrets_path: ./secrets
plex_enabled: false
jellyfin_enabled: false
puid: 1000
pgid: 1000
umask: "002"
vpn_enabled: false
torrent_peer_port: 6881
addons: []
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Domain != "file.example.test" {
		t.Fatalf("Domain = %q", cfg.Domain)
	}
	if cfg.ProjectDir != projectDir {
		t.Fatalf("ProjectDir = %q, want %q", cfg.ProjectDir, projectDir)
	}

	if err := os.WriteFile(path, []byte(body+"unknown_key: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), "unknown_key") {
		t.Fatalf("strict LoadFile error = %v", err)
	}
}

func TestLoadFileRejectsMultipleDocumentsAndSymlink(t *testing.T) {
	projectDir := t.TempDir()
	path := filepath.Join(projectDir, ".sdbx.yaml")
	cfg := DefaultConfig()
	cfg.Domain = "file.example.test"
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, []byte("---\ndomain: second.example.test\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), "multiple YAML") {
		t.Fatalf("multiple-document error = %v", err)
	}

	target := filepath.Join(projectDir, "real.yaml")
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(projectDir, "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(link); err == nil {
		t.Fatal("LoadFile accepted a symlink")
	}
}

func TestAddonManagement(t *testing.T) {
	cfg := DefaultConfig()

	// Initially no addons
	if len(cfg.Addons) != 0 {
		t.Errorf("Initial addons count = %d, want 0", len(cfg.Addons))
	}

	// Enable addon
	cfg.EnableAddon("sonarr")
	if !cfg.IsAddonEnabled("sonarr") {
		t.Error("sonarr should be enabled")
	}
	if len(cfg.Addons) != 1 {
		t.Errorf("Addons count = %d, want 1", len(cfg.Addons))
	}

	// Enable same addon again (should not duplicate)
	cfg.EnableAddon("sonarr")
	if len(cfg.Addons) != 1 {
		t.Errorf("Addons count = %d after duplicate enable, want 1", len(cfg.Addons))
	}

	// Enable another addon
	cfg.EnableAddon("radarr")
	if !cfg.IsAddonEnabled("radarr") {
		t.Error("radarr should be enabled")
	}
	if len(cfg.Addons) != 2 {
		t.Errorf("Addons count = %d, want 2", len(cfg.Addons))
	}

	// Disable addon
	cfg.DisableAddon("sonarr")
	if cfg.IsAddonEnabled("sonarr") {
		t.Error("sonarr should be disabled")
	}
	if len(cfg.Addons) != 1 {
		t.Errorf("Addons count = %d after disable, want 1", len(cfg.Addons))
	}

	// Radarr should still be enabled.
	if !cfg.IsAddonEnabled("radarr") {
		t.Error("radarr should still be enabled")
	}
}

func TestEnsureDir(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sdbx-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create nested directory
	nested := filepath.Join(tmpDir, "a", "b", "c")
	if err := EnsureDir(nested); err != nil {
		t.Fatalf("EnsureDir failed: %v", err)
	}

	// Verify it exists
	if _, err := os.Stat(nested); os.IsNotExist(err) {
		t.Error("EnsureDir did not create directory")
	}

	// Create again should not fail
	if err := EnsureDir(nested); err != nil {
		t.Errorf("EnsureDir failed on existing dir: %v", err)
	}
}

func TestSaveIsAtomicPrivateAndOmitsTransientSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".sdbx.yaml")
	cfg := DefaultConfig()
	cfg.AdminUser = "private-admin"
	cfg.AdminPasswordHash = "$argon2id$SDBX_SECRET_CANARY"
	cfg.ProjectDir = "/private/project"
	cfg.Addons = []string{"sonarr"}

	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	contents := string(data)
	for _, forbidden := range []string{
		"private-admin",
		"SDBX_SECRET_CANARY",
		"/private/project",
	} {
		if strings.Contains(contents, forbidden) {
			t.Fatalf("transient value %q leaked into saved config:\n%s", forbidden, contents)
		}
	}
	if !strings.Contains(contents, "config_path: ./configs") ||
		!strings.Contains(contents, "- sonarr") {
		t.Fatalf("saved config omitted persisted values:\n%s", contents)
	}
}

func TestValidateRejectsScalarInjection(t *testing.T) {
	tests := []struct {
		name  string
		field string
		set   func(*Config)
	}{
		{
			name:  "VPN country newline",
			field: "vpn_country",
			set: func(cfg *Config) {
				cfg.VPNCountry = "France\nTUNNEL_TOKEN=leak"
			},
		},
		{
			name:  "config path carriage return",
			field: "config_path",
			set: func(cfg *Config) {
				cfg.ConfigPath = "./configs\rmalicious"
			},
		},
		{
			name:  "service path newline",
			field: "services.sonarr.path",
			set: func(cfg *Config) {
				cfg.Services["sonarr"] = ServiceOverride{Path: "/sonarr\nadmin: true"}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig()
			test.set(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("unsafe scalar was accepted")
			}
			validation, ok := err.(*ValidationError)
			if !ok {
				t.Fatalf("error = %T %v, want ValidationError", err, err)
			}
			if validation.Field != test.field {
				t.Fatalf("field = %q, want %q", validation.Field, test.field)
			}
		})
	}
}

func TestValidateRequiresACMEContactForDirectExposure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Expose.Mode = ExposeModeDirect
	cfg.Expose.TLS.Provider = "acme"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("direct exposure without an ACME contact email was accepted")
	}
	validation, ok := err.(*ValidationError)
	if !ok || validation.Field != "expose.tls.email" {
		t.Fatalf("error = %T %v, want expose.tls.email validation", err, err)
	}

	cfg.Expose.TLS.Email = "ops@example.test"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid direct ACME configuration was rejected: %v", err)
	}

	cfg.Expose.TLS.Provider = "custom"
	err = cfg.Validate()
	if err == nil {
		t.Fatal("unsupported direct TLS provider was accepted")
	}
	validation, ok = err.(*ValidationError)
	if !ok || validation.Field != "expose.tls.provider" {
		t.Fatalf("error = %T %v, want expose.tls.provider validation", err, err)
	}
}

func TestValidateRejectsLegacyVPNUsernameInProjectIntent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.VPNUsername = "account-number"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("legacy VPN username was accepted in project intent")
	}
	validation, ok := err.(*ValidationError)
	if !ok || validation.Field != "vpn_username" {
		t.Fatalf("error = %T %v, want vpn_username validation", err, err)
	}
	if !strings.Contains(err.Error(), "gluetun.env") {
		t.Fatalf("migration error omits the private credential destination: %v", err)
	}
}

func TestValidateRejectsUnsafeServiceRoutePaths(t *testing.T) {
	for _, routePath := range []string{
		"relative",
		"/shows`) || Host(`attacker.example",
		"/shows//admin",
		"/shows/../admin",
		"/shows?admin=true",
	} {
		t.Run(routePath, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Services["sonarr"] = ServiceOverride{Path: routePath}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("unsafe route path %q was accepted", routePath)
			}
			validation, ok := err.(*ValidationError)
			if !ok || validation.Field != "services.sonarr.path" {
				t.Fatalf("error = %T %v", err, err)
			}
		})
	}
}

func TestValidateRejectsEscapingOrBroadManagedPaths(t *testing.T) {
	tests := []struct {
		name  string
		field string
		set   func(*Config)
	}{
		{
			name:  "relative escape",
			field: "secrets_path",
			set: func(cfg *Config) {
				cfg.SecretsPath = "../outside"
			},
		},
		{
			name:  "project root alias",
			field: "config_path",
			set: func(cfg *Config) {
				cfg.ConfigPath = "."
			},
		},
	}
	if filepath.IsAbs(string(filepath.Separator)) {
		tests = append(tests, struct {
			name  string
			field string
			set   func(*Config)
		}{
			name:  "filesystem root",
			field: "data_path",
			set: func(cfg *Config) {
				cfg.DataPath = string(filepath.Separator)
			},
		})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig()
			test.set(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("unsafe managed path was accepted")
			}
			validation, ok := err.(*ValidationError)
			if !ok {
				t.Fatalf("error = %T %v, want ValidationError", err, err)
			}
			if validation.Field != test.field {
				t.Fatalf("field = %q, want %q", validation.Field, test.field)
			}
		})
	}
}

func TestProjectDir(t *testing.T) {
	// Save current dir
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)

	// Create temp project
	tmpDir, err := os.MkdirTemp("", "sdbx-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// No project files - should fail
	os.Chdir(tmpDir)
	_, err = ProjectDir()
	if err == nil {
		t.Error("ProjectDir should fail without project files")
	}

	// Create .sdbx.yaml
	os.WriteFile(filepath.Join(tmpDir, ".sdbx.yaml"), []byte("domain: test.com"), 0o644)

	// Now should succeed
	dir, err := ProjectDir()
	if err != nil {
		t.Errorf("ProjectDir failed: %v", err)
	}

	// Resolve symlinks for comparison (macOS /var -> /private/var)
	expectedDir, _ := filepath.EvalSymlinks(tmpDir)
	actualDir, _ := filepath.EvalSymlinks(dir)
	if actualDir != expectedDir {
		t.Errorf("ProjectDir = %s, want %s", actualDir, expectedDir)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		wantErr  bool
		errField string
	}{
		{
			name:    "valid config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "missing domain",
			config: &Config{
				Timezone:      "UTC",
				Expose:        ExposeConfig{Mode: "cloudflared"},
				Routing:       RoutingConfig{Strategy: "subdomain"},
				Auth:          AuthenticationConfig{Factor: AuthFactorOne},
				ConfigPath:    "./config",
				MediaPath:     "./media",
				DownloadsPath: "./downloads",
				PUID:          1000,
				PGID:          1000,
			},
			wantErr:  true,
			errField: "domain",
		},
		{
			name: "invalid domain format",
			config: &Config{
				Domain:        "invalid_domain",
				Timezone:      "UTC",
				Expose:        ExposeConfig{Mode: "cloudflared"},
				Routing:       RoutingConfig{Strategy: "subdomain"},
				Auth:          AuthenticationConfig{Factor: AuthFactorOne},
				ConfigPath:    "./config",
				MediaPath:     "./media",
				DownloadsPath: "./downloads",
				PUID:          1000,
				PGID:          1000,
			},
			wantErr:  true,
			errField: "domain",
		},
		{
			name: "invalid expose mode",
			config: &Config{
				Domain:        "sdbx.example.com",
				Timezone:      "UTC",
				Expose:        ExposeConfig{Mode: "invalid"},
				Routing:       RoutingConfig{Strategy: "subdomain"},
				Auth:          AuthenticationConfig{Factor: AuthFactorOne},
				ConfigPath:    "./config",
				MediaPath:     "./media",
				DownloadsPath: "./downloads",
				PUID:          1000,
				PGID:          1000,
			},
			wantErr:  true,
			errField: "expose.mode",
		},
		{
			name: "invalid routing strategy",
			config: &Config{
				Domain:        "sdbx.example.com",
				Timezone:      "UTC",
				Expose:        ExposeConfig{Mode: "cloudflared"},
				Routing:       RoutingConfig{Strategy: "invalid"},
				Auth:          AuthenticationConfig{Factor: AuthFactorOne},
				ConfigPath:    "./config",
				MediaPath:     "./media",
				DownloadsPath: "./downloads",
				PUID:          1000,
				PGID:          1000,
			},
			wantErr:  true,
			errField: "routing.strategy",
		},
		{
			name: "path routing without base domain",
			config: &Config{
				Domain:        "sdbx.example.com",
				Timezone:      "UTC",
				Expose:        ExposeConfig{Mode: "cloudflared"},
				Routing:       RoutingConfig{Strategy: "path", BaseDomain: ""},
				Auth:          AuthenticationConfig{Factor: AuthFactorOne},
				ConfigPath:    "./config",
				MediaPath:     "./media",
				DownloadsPath: "./downloads",
				PUID:          1000,
				PGID:          1000,
			},
			wantErr:  true,
			errField: "routing.base_domain",
		},
		{
			name: "vpn enabled without provider",
			config: &Config{
				Domain:        "sdbx.example.com",
				Timezone:      "UTC",
				Expose:        ExposeConfig{Mode: "cloudflared"},
				Routing:       RoutingConfig{Strategy: "subdomain"},
				Auth:          AuthenticationConfig{Factor: AuthFactorOne},
				VPNEnabled:    true,
				ConfigPath:    "./config",
				MediaPath:     "./media",
				DownloadsPath: "./downloads",
				PUID:          1000,
				PGID:          1000,
			},
			wantErr:  true,
			errField: "vpn_provider",
		},
		{
			name: "invalid PUID",
			config: &Config{
				Domain:        "sdbx.example.com",
				Timezone:      "UTC",
				Expose:        ExposeConfig{Mode: "cloudflared"},
				Routing:       RoutingConfig{Strategy: "subdomain"},
				Auth:          AuthenticationConfig{Factor: AuthFactorOne},
				ConfigPath:    "./configs",
				DataPath:      "./data",
				MediaPath:     "./media",
				DownloadsPath: "./downloads",
				SecretsPath:   "./secrets",
				PUID:          -1,
				PGID:          1000,
				TorrentPort:   6881,
			},
			wantErr:  true,
			errField: "puid",
		},
		{
			name: "invalid PGID",
			config: &Config{
				Domain:        "sdbx.example.com",
				Timezone:      "UTC",
				Expose:        ExposeConfig{Mode: "cloudflared"},
				Routing:       RoutingConfig{Strategy: "subdomain"},
				Auth:          AuthenticationConfig{Factor: AuthFactorOne},
				ConfigPath:    "./configs",
				DataPath:      "./data",
				MediaPath:     "./media",
				DownloadsPath: "./downloads",
				SecretsPath:   "./secrets",
				PUID:          1000,
				PGID:          70000,
				TorrentPort:   6881,
			},
			wantErr:  true,
			errField: "pgid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil {
				// Check if it's a ValidationError with the correct field
				if valErr, ok := err.(*ValidationError); ok {
					if valErr.Field != tt.errField {
						t.Errorf("Validate() error field = %s, want %s", valErr.Field, tt.errField)
					}
				}
			}
		})
	}
}

func TestValidateRejectsInvalidTorrentPeerPort(t *testing.T) {
	for _, port := range []int{0, -1, 65536} {
		t.Run(fmt.Sprintf("port-%d", port), func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.TorrentPort = port
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate accepted torrent peer port %d", port)
			}
			validation, ok := err.(*ValidationError)
			if !ok {
				t.Fatalf("error = %T %v, want ValidationError", err, err)
			}
			if validation.Field != "torrent_peer_port" {
				t.Fatalf("field = %q, want torrent_peer_port", validation.Field)
			}
		})
	}
}

func TestProjectNotFoundError(t *testing.T) {
	err := &ProjectNotFoundError{StartPath: "/test/path"}
	if !IsProjectNotFoundError(err) {
		t.Error("IsProjectNotFoundError should return true for ProjectNotFoundError")
	}

	if IsProjectNotFoundError(nil) {
		t.Error("IsProjectNotFoundError should return false for nil")
	}

	genericErr := fmt.Errorf("generic error")
	if IsProjectNotFoundError(genericErr) {
		t.Error("IsProjectNotFoundError should return false for generic error")
	}
}

func TestValidationError(t *testing.T) {
	err := NewValidationError("test_field", "test message")
	expectedMsg := "validation error [test_field]: test message"
	if err.Error() != expectedMsg {
		t.Errorf("ValidationError.Error() = %s, want %s", err.Error(), expectedMsg)
	}
}
