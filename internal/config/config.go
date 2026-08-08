// Package config handles configuration loading and management for sdbx.
package config

import (
	"fmt"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/get-sdbx/sdbx/internal/securefs"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

const (
	// Expose modes
	ExposeModeCloudflared = "cloudflared"
	ExposeModeDirect      = "direct"
	ExposeModeLAN         = "lan"

	// Routing strategies
	RoutingStrategyPath      = "path"
	RoutingStrategySubdomain = "subdomain"

	maxConfigFileBytes = 1 << 20
)

// Config holds the sdbx configuration
type Config struct {
	// Core settings
	Domain   string `mapstructure:"domain" yaml:"domain"`
	Timezone string `mapstructure:"timezone" yaml:"timezone"`

	// Exposure configuration
	Expose ExposeConfig `mapstructure:"expose" yaml:"expose"`

	// Routing configuration
	Routing RoutingConfig `mapstructure:"routing" yaml:"routing"`

	// Authentication policy
	Auth AuthenticationConfig `mapstructure:"auth" yaml:"auth"`

	// Paths
	ConfigPath    string `mapstructure:"config_path" yaml:"config_path"`
	DataPath      string `mapstructure:"data_path" yaml:"data_path"`
	DownloadsPath string `mapstructure:"downloads_path" yaml:"downloads_path"`
	MediaPath     string `mapstructure:"media_path" yaml:"media_path"`
	SecretsPath   string `mapstructure:"secrets_path" yaml:"secrets_path"`

	// Media servers are explicit choices. Neither is silently enabled for a
	// new project; legacy configs without both keys migrate to Plex on load.
	PlexEnabled     bool `mapstructure:"plex_enabled" yaml:"plex_enabled"`
	JellyfinEnabled bool `mapstructure:"jellyfin_enabled" yaml:"jellyfin_enabled"`

	// Permissions
	PUID  int    `mapstructure:"puid" yaml:"puid"`
	PGID  int    `mapstructure:"pgid" yaml:"pgid"`
	Umask string `mapstructure:"umask" yaml:"umask"`

	// VPN
	VPNEnabled  bool   `mapstructure:"vpn_enabled" yaml:"vpn_enabled"`
	VPNProvider string `mapstructure:"vpn_provider" yaml:"vpn_provider,omitempty"`
	// VPNUsername is accepted only to produce an actionable migration error
	// for pre-v1 configurations. Provider credentials belong in the private
	// Gluetun environment file and must never be persisted in project intent.
	VPNUsername string `mapstructure:"vpn_username" yaml:"vpn_username,omitempty"`
	VPNCountry  string `mapstructure:"vpn_country" yaml:"vpn_country,omitempty"`
	TorrentPort int    `mapstructure:"torrent_peer_port" yaml:"torrent_peer_port"`

	// Addons
	Addons []string `mapstructure:"addons" yaml:"addons"`

	// Per-service overrides
	Services map[string]ServiceOverride `mapstructure:"services" yaml:"services,omitempty"`

	// Security (Transient, not saved to config)
	AdminUser         string `mapstructure:"-" yaml:"-"`
	AdminPasswordHash string `mapstructure:"-" yaml:"-"`
	// ActiveServices is populated from the verified registry resolution graph
	// for operational commands. It must never be persisted or inferred from a
	// stale hardcoded "core" list.
	ActiveServices map[string]bool `mapstructure:"-" yaml:"-"`

	// ProjectDir is the absolute path to the project directory (the dir
	// containing .sdbx.yaml). Populated at load time so templates in
	// service.yaml can reference {{ .Config.ProjectDir }} when an explicitly
	// trusted local source requires it. Not persisted to disk.
	ProjectDir string `mapstructure:"-" yaml:"-"`

	// Legacy field for backward compatibility (deprecated)
	ExposeMode string `mapstructure:"expose_mode" yaml:"expose_mode,omitempty"`
}

// ExposeConfig defines how services are exposed to the network
type ExposeConfig struct {
	Mode string    `mapstructure:"mode" yaml:"mode"` // "lan" | "direct" | "cloudflared"
	TLS  TLSConfig `mapstructure:"tls" yaml:"tls"`
}

// TLSConfig defines TLS/SSL settings for direct mode
type TLSConfig struct {
	Provider string `mapstructure:"provider" yaml:"provider,omitempty"`   // Derived: "acme" for direct mode
	Email    string `mapstructure:"email" yaml:"email,omitempty"`         // For ACME (Let's Encrypt)
	CertFile string `mapstructure:"cert_file" yaml:"cert_file,omitempty"` // Reserved; not supported in v1
	KeyFile  string `mapstructure:"key_file" yaml:"key_file,omitempty"`   // Reserved; not supported in v1
}

// RoutingConfig defines how services are routed (subdomain vs path)
type RoutingConfig struct {
	Strategy   string `mapstructure:"strategy" yaml:"strategy"`       // "subdomain" | "path"
	BaseDomain string `mapstructure:"base_domain" yaml:"base_domain"` // For path mode: the subdomain to use (e.g., "sdbx" → sdbx.domain.tld)
}

// AuthenticationConfig controls the generated Authelia policy. The
// one-factor default permits initial TOTP enrollment; operators can switch the
// complete ForwardAuth boundary to two factors after enrollment.
type AuthenticationConfig struct {
	Factor string `mapstructure:"factor" yaml:"factor"`
}

const (
	AuthFactorOne = "one_factor"
	AuthFactorTwo = "two_factor"
)

// ServiceOverride allows per-service routing customization
type ServiceOverride struct {
	Routing   string `mapstructure:"routing" yaml:"routing,omitempty"`     // "subdomain" | "path" - override global strategy
	Subdomain string `mapstructure:"subdomain" yaml:"subdomain,omitempty"` // Custom subdomain, for example "requests".
	Path      string `mapstructure:"path" yaml:"path,omitempty"`           // Custom path (e.g., "/tv" for sonarr)
}

// DefaultConfig returns a new Config with default values
func DefaultConfig() *Config {
	return &Config{
		Domain:   "sdbx.example.com",
		Timezone: "Europe/Paris",
		Expose: ExposeConfig{
			Mode: ExposeModeLAN,
			TLS:  TLSConfig{},
		},
		Routing: RoutingConfig{
			Strategy:   "subdomain",
			BaseDomain: "sdbx",
		},
		Auth: AuthenticationConfig{
			Factor: AuthFactorOne,
		},
		ConfigPath:      "./configs",
		DataPath:        "./data",
		DownloadsPath:   "./data/downloads",
		MediaPath:       "./data/media",
		SecretsPath:     "./secrets",
		PlexEnabled:     false,
		JellyfinEnabled: false,
		PUID:            1000,
		PGID:            1000,
		Umask:           "002",
		VPNEnabled:      false,
		VPNProvider:     "",
		VPNCountry:      "",
		TorrentPort:     6881,
		Addons:          []string{},
		Services:        make(map[string]ServiceOverride),
	}
}

// SetExposureMode applies one exposure-mode transition and keeps derived TLS
// intent coherent. ACME state belongs only to direct exposure; retaining the
// contact after switching to LAN or Cloudflare Tunnel unnecessarily preserves
// operator data and misrepresents the active certificate policy.
func (c *Config) SetExposureMode(mode string) {
	c.Expose.Mode = mode
	if mode == ExposeModeDirect {
		c.Expose.TLS.Provider = "acme"
		return
	}
	c.Expose.TLS.Provider = ""
	c.Expose.TLS.Email = ""
}

// Domain validation regex - matches valid domain names
var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
var identifierRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
var adminUserRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var umaskRegex = regexp.MustCompile(`^0?[0-7]{3}$`)
var routePathRegex = regexp.MustCompile(`^/(?:[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)?$`)

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Required fields
	if c.Domain == "" {
		return NewValidationError("domain", "domain is required")
	}

	// Domain format validation
	if !domainRegex.MatchString(c.Domain) {
		return NewValidationError("domain", "invalid domain format")
	}

	// Timezone validation
	if c.Timezone == "" {
		return NewValidationError("timezone", "timezone is required")
	}
	if _, err := time.LoadLocation(c.Timezone); err != nil {
		return NewValidationError("timezone", "must be a valid IANA time zone")
	}

	// Expose mode validation
	validExposeModes := []string{"lan", "direct", "cloudflared"}
	if !contains(validExposeModes, c.Expose.Mode) {
		return NewValidationError("expose.mode",
			fmt.Sprintf("must be one of: %s", strings.Join(validExposeModes, ", ")))
	}
	if c.Expose.Mode == ExposeModeDirect {
		if c.Expose.TLS.Provider != "acme" {
			return NewValidationError(
				"expose.tls.provider",
				"must be acme when expose.mode is direct",
			)
		}
		if strings.TrimSpace(c.Expose.TLS.Email) == "" {
			return NewValidationError(
				"expose.tls.email",
				"ACME contact email is required when expose.mode is direct",
			)
		}
	} else if c.Expose.TLS.Provider != "" {
		return NewValidationError(
			"expose.tls.provider",
			"must be empty unless expose.mode is direct",
		)
	}
	if c.Expose.TLS.CertFile != "" || c.Expose.TLS.KeyFile != "" {
		return NewValidationError(
			"expose.tls",
			"custom certificate files are not supported in v1",
		)
	}

	// Routing strategy validation
	validRoutingStrategies := []string{"subdomain", "path"}
	if !contains(validRoutingStrategies, c.Routing.Strategy) {
		return NewValidationError("routing.strategy",
			fmt.Sprintf("must be one of: %s", strings.Join(validRoutingStrategies, ", ")))
	}

	// Path routing requires base domain
	if c.Routing.Strategy == RoutingStrategyPath && c.Routing.BaseDomain == "" {
		return NewValidationError("routing.base_domain",
			"base_domain is required when using path routing")
	}
	if c.Routing.BaseDomain != "" && !identifierRegex.MatchString(c.Routing.BaseDomain) {
		return NewValidationError("routing.base_domain", "must be a valid DNS label")
	}
	if c.Auth.Factor != AuthFactorOne && c.Auth.Factor != AuthFactorTwo {
		return NewValidationError(
			"auth.factor",
			"must be one_factor or two_factor",
		)
	}

	// VPN validation
	if c.VPNEnabled && c.VPNProvider == "" {
		return NewValidationError("vpn_provider",
			"vpn_provider is required when VPN is enabled")
	}
	if strings.TrimSpace(c.VPNUsername) != "" {
		return NewValidationError(
			"vpn_username",
			"is no longer supported; move provider credentials to configs/gluetun/gluetun.env and remove this key",
		)
	}
	if c.TorrentPort < 1 || c.TorrentPort > 65535 {
		return NewValidationError("torrent_peer_port", "must be between 1 and 65535")
	}

	// Path validation (basic check - non-empty)
	if c.ConfigPath == "" {
		return NewValidationError("config_path", "config_path cannot be empty")
	}
	if c.DataPath == "" {
		return NewValidationError("data_path", "data_path cannot be empty")
	}
	if c.MediaPath == "" {
		return NewValidationError("media_path", "media_path cannot be empty")
	}
	if c.DownloadsPath == "" {
		return NewValidationError("downloads_path", "downloads_path cannot be empty")
	}
	if c.SecretsPath == "" {
		return NewValidationError("secrets_path", "secrets_path cannot be empty")
	}
	for _, managedPath := range []struct {
		field string
		value string
	}{
		{"config_path", c.ConfigPath},
		{"data_path", c.DataPath},
		{"downloads_path", c.DownloadsPath},
		{"media_path", c.MediaPath},
		{"secrets_path", c.SecretsPath},
	} {
		if err := validateManagedPath(managedPath.field, managedPath.value); err != nil {
			return err
		}
	}

	// PUID/PGID validation
	if c.PUID < 0 || c.PUID > 65535 {
		return NewValidationError("puid", "must be between 0 and 65535")
	}
	if c.PGID < 0 || c.PGID > 65535 {
		return NewValidationError("pgid", "must be between 0 and 65535")
	}
	if !umaskRegex.MatchString(c.Umask) {
		return NewValidationError("umask", "must be a three- or four-digit octal mask")
	}

	scalars := []struct {
		field string
		value string
	}{
		{"domain", c.Domain},
		{"timezone", c.Timezone},
		{"config_path", c.ConfigPath},
		{"data_path", c.DataPath},
		{"downloads_path", c.DownloadsPath},
		{"media_path", c.MediaPath},
		{"secrets_path", c.SecretsPath},
		{"vpn_provider", c.VPNProvider},
		{"vpn_country", c.VPNCountry},
		{"expose.tls.provider", c.Expose.TLS.Provider},
		{"expose.tls.email", c.Expose.TLS.Email},
		{"expose.tls.cert_file", c.Expose.TLS.CertFile},
		{"expose.tls.key_file", c.Expose.TLS.KeyFile},
		{"routing.base_domain", c.Routing.BaseDomain},
		{"auth.factor", c.Auth.Factor},
		{"admin_user", c.AdminUser},
		{"admin_password_hash", c.AdminPasswordHash},
	}
	for _, scalar := range scalars {
		if err := validateSafeScalar(scalar.field, scalar.value); err != nil {
			return err
		}
	}
	if c.Expose.TLS.Email != "" {
		address, err := mail.ParseAddress(c.Expose.TLS.Email)
		if err != nil || address.Address != c.Expose.TLS.Email {
			return NewValidationError("expose.tls.email", "must be a plain email address")
		}
	}
	if c.AdminUser != "" && !adminUserRegex.MatchString(c.AdminUser) {
		return NewValidationError("admin_user", "contains unsupported characters")
	}
	if c.AdminPasswordHash != "" && !strings.HasPrefix(c.AdminPasswordHash, "$argon2id$") {
		return NewValidationError("admin_password_hash", "must be an Argon2id hash")
	}
	if c.VPNProvider != "" && !identifierRegex.MatchString(c.VPNProvider) {
		return NewValidationError("vpn_provider", "contains unsupported characters")
	}

	seenAddons := make(map[string]struct{}, len(c.Addons))
	for _, addon := range c.Addons {
		if !identifierRegex.MatchString(addon) {
			return NewValidationError("addons", fmt.Sprintf("invalid service name %q", addon))
		}
		if _, exists := seenAddons[addon]; exists {
			return NewValidationError("addons", fmt.Sprintf("duplicate service %q", addon))
		}
		seenAddons[addon] = struct{}{}
	}
	for name, override := range c.Services {
		if !identifierRegex.MatchString(name) {
			return NewValidationError("services", fmt.Sprintf("invalid service name %q", name))
		}
		for _, scalar := range []struct {
			field string
			value string
		}{
			{"services." + name + ".routing", override.Routing},
			{"services." + name + ".subdomain", override.Subdomain},
			{"services." + name + ".path", override.Path},
		} {
			if err := validateSafeScalar(scalar.field, scalar.value); err != nil {
				return err
			}
		}
		if override.Routing != "" &&
			override.Routing != RoutingStrategyPath &&
			override.Routing != RoutingStrategySubdomain {
			return NewValidationError("services."+name+".routing", "must be path or subdomain")
		}
		if override.Subdomain != "" && !identifierRegex.MatchString(override.Subdomain) {
			return NewValidationError("services."+name+".subdomain", "must be a valid DNS label")
		}
		if override.Path != "" && !isSafeRoutePath(override.Path) {
			return NewValidationError(
				"services."+name+".path",
				"must be a clean absolute URL path using letters, digits, dot, underscore, tilde, or hyphen",
			)
		}
	}

	return nil
}

func isSafeRoutePath(value string) bool {
	if !routePathRegex.MatchString(value) {
		return false
	}
	for _, segment := range strings.Split(strings.TrimPrefix(value, "/"), "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validateSafeScalar(field, value string) error {
	if !utf8.ValidString(value) {
		return NewValidationError(field, "must be valid UTF-8")
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return NewValidationError(field, "must not contain control characters")
		}
	}
	return nil
}

func validateManagedPath(field, value string) error {
	clean := filepath.Clean(value)
	if clean == "." {
		return NewValidationError(field, "must name a dedicated directory")
	}
	if filepath.IsAbs(clean) {
		if filepath.Dir(clean) == clean {
			return NewValidationError(field, "must not be a filesystem root")
		}
		return nil
	}
	parentPrefix := ".." + string(filepath.Separator)
	if clean == ".." || strings.HasPrefix(clean, parentPrefix) {
		return NewValidationError(field, "relative path must stay inside the project directory")
	}
	return nil
}

// contains checks if a string slice contains a value
func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// Load loads configuration from file and environment
func Load() (*Config, error) {
	cfg := DefaultConfig()

	// Set defaults in viper
	viper.SetDefault("domain", cfg.Domain)
	viper.SetDefault("timezone", cfg.Timezone)
	viper.SetDefault("expose.mode", cfg.Expose.Mode)
	viper.SetDefault("expose.tls.provider", cfg.Expose.TLS.Provider)
	viper.SetDefault("routing.strategy", cfg.Routing.Strategy)
	viper.SetDefault("routing.base_domain", cfg.Routing.BaseDomain)
	viper.SetDefault("auth.factor", cfg.Auth.Factor)
	viper.SetDefault("config_path", cfg.ConfigPath)
	viper.SetDefault("data_path", cfg.DataPath)
	viper.SetDefault("downloads_path", cfg.DownloadsPath)
	viper.SetDefault("media_path", cfg.MediaPath)
	viper.SetDefault("secrets_path", cfg.SecretsPath)
	viper.SetDefault("plex_enabled", cfg.PlexEnabled)
	viper.SetDefault("jellyfin_enabled", cfg.JellyfinEnabled)
	viper.SetDefault("puid", cfg.PUID)
	viper.SetDefault("pgid", cfg.PGID)
	viper.SetDefault("umask", cfg.Umask)
	viper.SetDefault("vpn_provider", cfg.VPNProvider)
	viper.SetDefault("vpn_country", cfg.VPNCountry)
	viper.SetDefault("torrent_peer_port", cfg.TorrentPort)
	viper.SetDefault("addons", cfg.Addons)

	// Try to read config file
	if err := viper.ReadInConfig(); err != nil {
		// Config file is optional
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	// Unmarshal into struct
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}
	if viper.ConfigFileUsed() != "" &&
		!viper.InConfig("plex_enabled") &&
		!viper.InConfig("jellyfin_enabled") {
		// Pre-v1 projects always resolved Plex. Preserve that behavior while
		// making every new project choose explicitly.
		cfg.PlexEnabled = true
	}

	// Legacy migration: if expose_mode is set but expose.mode is not, migrate
	if cfg.ExposeMode != "" && cfg.Expose.Mode == "" {
		cfg.Expose.Mode = cfg.ExposeMode
	}
	normalizeLegacyTLS(cfg)

	// Initialize Services map if nil
	if cfg.Services == nil {
		cfg.Services = make(map[string]ServiceOverride)
	}

	// Populate ProjectDir from the resolved project root for service templates.
	if dir, err := ProjectDir(); err == nil {
		cfg.ProjectDir = dir
	}

	return cfg, nil
}

// LoadFile loads one explicit project configuration without consulting Viper,
// process environment overrides, or the current working directory. Daemons
// and long-running management processes use it to avoid global mutable state.
func LoadFile(path string) (*Config, error) {
	data, err := securefs.ReadRegularFile(path, maxConfigFileBytes)
	if err != nil {
		return nil, fmt.Errorf("read project configuration: %w", err)
	}
	return Parse(data, filepath.Dir(filepath.Clean(path)))
}

// Parse decodes one explicit project configuration without consulting Viper,
// process environment overrides, or the current working directory.
func Parse(data []byte, projectDir string) (*Config, error) {
	if len(data) > maxConfigFileBytes {
		return nil, fmt.Errorf(
			"project configuration exceeds %d bytes",
			maxConfigFileBytes,
		)
	}
	if projectDir == "" {
		return nil, fmt.Errorf("project directory is required")
	}
	cfg := DefaultConfig()
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("decode project configuration: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf(
				"decode project configuration: multiple YAML documents are not allowed",
			)
		}
		return nil, fmt.Errorf("decode project configuration: %w", err)
	}

	var present map[string]any
	if err := yaml.Unmarshal(data, &present); err != nil {
		return nil, fmt.Errorf("inspect project configuration: %w", err)
	}
	_, hasPlex := present["plex_enabled"]
	_, hasJellyfin := present["jellyfin_enabled"]
	if !hasPlex && !hasJellyfin {
		cfg.PlexEnabled = true
	}
	if cfg.ExposeMode != "" && cfg.Expose.Mode == "" {
		cfg.Expose.Mode = cfg.ExposeMode
	}
	normalizeLegacyTLS(cfg)
	if cfg.Services == nil {
		cfg.Services = make(map[string]ServiceOverride)
	}
	cfg.ProjectDir = filepath.Clean(projectDir)
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate project configuration: %w", err)
	}
	return cfg, nil
}

// Save saves the configuration to a file
func (c *Config) Save(path string) error {
	if err := c.SaveFile(path); err != nil {
		return err
	}
	// Preserve the existing package contract: callers that save and then load
	// in the same process expect Viper to read the file that was just written.
	viper.SetConfigFile(path)
	return nil
}

// SaveFile saves configuration without changing the process-global Viper
// target. Generators use it for private transaction stages that are removed
// after promotion.
func (c *Config) SaveFile(path string) error {
	if c == nil {
		return fmt.Errorf("cannot save nil configuration")
	}
	if err := c.Validate(); err != nil {
		return fmt.Errorf("validate configuration before save: %w", err)
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal configuration: %w", err)
	}
	if err := securefs.WriteFileAtomicPreserveDir(path, data, 0o755, 0o600); err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	return nil
}

// ProjectDir returns the base project directory
func ProjectDir() (string, error) {
	// Look for .sdbx.yaml or compose.yaml in current or parent dirs
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	startPath := dir

	for {
		if _, err := os.Stat(filepath.Join(dir, ".sdbx.yaml")); err == nil {
			return dir, nil
		}
		if _, err := os.Stat(filepath.Join(dir, "compose.yaml")); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", &ProjectNotFoundError{StartPath: startPath}
}

// EnsureDir creates a directory if it doesn't exist
func EnsureDir(path string) error {
	return securefs.EnsureDir(path, 0o755)
}

// IsAddonEnabled checks if an addon is enabled
func (c *Config) IsAddonEnabled(addon string) bool {
	for _, a := range c.Addons {
		if a == addon {
			return true
		}
	}
	return false
}

// EnableAddon adds an addon to the enabled list
func (c *Config) EnableAddon(addon string) {
	if !c.IsAddonEnabled(addon) {
		c.Addons = append(c.Addons, addon)
	}
}

// DisableAddon removes an addon from the enabled list
func (c *Config) DisableAddon(addon string) {
	newAddons := make([]string, 0, len(c.Addons))
	for _, a := range c.Addons {
		if a != addon {
			newAddons = append(newAddons, a)
		}
	}
	c.Addons = newAddons
}

// NeedsTLS returns true if the exposure mode requires TLS configuration
func (c *Config) NeedsTLS() bool {
	return c.Expose.Mode == ExposeModeDirect
}

// IsCloudflared returns true if using Cloudflare Tunnel mode
func (c *Config) IsCloudflared() bool {
	return c.Expose.Mode == ExposeModeCloudflared
}

// IsLANMode returns true if in LAN (no-TLS) mode
func (c *Config) IsLANMode() bool {
	return c.Expose.Mode == ExposeModeLAN
}

func normalizeLegacyTLS(cfg *Config) {
	if cfg == nil {
		return
	}
	if cfg.Expose.Mode == ExposeModeDirect && cfg.Expose.TLS.Provider == "" {
		cfg.Expose.TLS.Provider = "acme"
	}
	if cfg.Expose.Mode != ExposeModeDirect && cfg.Expose.TLS.Provider == "acme" {
		cfg.Expose.TLS.Provider = ""
	}
}
