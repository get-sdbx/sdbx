// Package settings coordinates typed project configuration changes.
package settings

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/generator"
	"github.com/get-sdbx/sdbx/internal/registry"
)

type Manager struct {
	ProjectDir    string
	Config        *config.Config
	Registry      *registry.Registry
	Lock          *registry.LockFile
	CLIVersion    string
	ImageResolver registry.ImageDigestResolver
	// AllowUnprotectedDownloads is an explicit one-operation acknowledgement
	// that disabling the VPN exposes torrent traffic through the host network.
	AllowUnprotectedDownloads bool
}

type Result struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Regenerated bool   `json:"regenerated"`
}

type Group struct {
	Name string
	Keys []string
}

type Field struct {
	Key         string   `json:"key"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	Group       string   `json:"group"`
	Type        string   `json:"type"`
	Options     []string `json:"options,omitempty"`
	Editable    bool     `json:"editable"`
}

func Fields() []Field {
	return []Field{
		{
			Key:         "domain",
			Label:       "Domain",
			Description: "Base DNS domain used to derive routed service URLs.",
			Group:       "Core",
			Type:        "text",
			Editable:    true,
		},
		{
			Key:         "expose.mode",
			Label:       "Exposure",
			Description: "Ingress boundary: trusted LAN, direct public HTTPS, or a remote-managed Cloudflare Tunnel.",
			Group:       "Core",
			Type:        "select",
			Options:     []string{"lan", "direct", "cloudflared"},
			Editable:    true,
		},
		{
			Key:         "expose.tunnel_protocol",
			Label:       "Cloudflare Tunnel protocol",
			Description: "Cloudflare exposure only: http2 uses TCP for reliable HTTP delivery; quic uses UDP; auto prefers QUIC with connection-failure fallback.",
			Group:       "Core",
			Type:        "select",
			Options:     []string{config.TunnelProtocolHTTP2, config.TunnelProtocolQUIC, config.TunnelProtocolAuto},
			Editable:    true,
		},
		{
			Key:         "expose.tls.email",
			Label:       "ACME contact email",
			Description: "Plain contact address required before direct-mode ACME certificates can be issued.",
			Group:       "Core",
			Type:        "text",
			Editable:    true,
		},
		{
			Key:         "timezone",
			Label:       "Timezone",
			Description: "IANA timezone propagated to supported containers.",
			Group:       "Core",
			Type:        "text",
			Editable:    true,
		},
		{
			Key:         "plex_enabled",
			Label:       "Plex enabled",
			Description: "Include Plex in the active service graph.",
			Group:       "Media servers",
			Type:        "boolean",
			Editable:    true,
		},
		{
			Key:         "jellyfin_enabled",
			Label:       "Jellyfin enabled",
			Description: "Include Jellyfin in the active service graph.",
			Group:       "Media servers",
			Type:        "boolean",
			Editable:    true,
		},
		{
			Key: "plex.hardware_device", Label: "Plex GPU render device", Group: "Plex", Type: "text", Editable: true,
			Description: "Optional /dev/dri/renderD device for hardware transcoding. The host must already provide the device; empty disables GPU access.",
		},
		{
			Key: "plex.amd_vaapi", Label: "Plex AMD driver compatibility", Group: "Plex", Type: "boolean", Editable: true,
			Description: "Opt in to the pinned community AMD VA-API compatibility package on Linux amd64. Requires a GPU render device.",
		},
		{
			Key: "plex.lan_address", Label: "Plex private listen address", Group: "Plex", Type: "text", Editable: true,
			Description: "Bind Plex's native authenticated HTTP port to a private or loopback IP. Empty disables the listener; routed HTTPS remains available.",
		},
		{
			Key: "plex.lan_port", Label: "Plex private listen port", Group: "Plex", Type: "number", Editable: true,
			Description: "Host TCP port for the private Plex listener; defaults to 32400. Requires a private listen address.",
		},
		{
			Key:         "routing.strategy",
			Label:       "Routing",
			Description: "Default routed-service URL strategy.",
			Group:       "Routing",
			Type:        "select",
			Options:     []string{"subdomain", "path"},
			Editable:    true,
		},
		{
			Key:         "routing.base_domain",
			Label:       "Base domain",
			Description: "DNS label placed before the base domain for shared path routing.",
			Group:       "Routing",
			Type:        "text",
			Editable:    true,
		},
		{
			Key:         "auth.factor",
			Label:       "Authelia access factor",
			Description: "Authentication factor required by every generated Authelia ForwardAuth route; enroll TOTP before selecting two_factor.",
			Group:       "Authentication",
			Type:        "select",
			Options:     []string{config.AuthFactorOne, config.AuthFactorTwo},
			Editable:    true,
		},
		{
			Key:         "config_path",
			Label:       "Config path",
			Description: "Root for SDBX-managed policy and application configuration.",
			Group:       "Paths",
			Type:        "text",
			Editable:    false,
		},
		{
			Key:         "data_path",
			Label:       "Data path",
			Description: "General persistent application-data root.",
			Group:       "Paths",
			Type:        "text",
			Editable:    false,
		},
		{
			Key:         "downloads_path",
			Label:       "Downloads",
			Description: "Persistent incomplete and completed download root.",
			Group:       "Paths",
			Type:        "text",
			Editable:    false,
		},
		{
			Key:         "media_path",
			Label:       "Media",
			Description: "Persistent media-library root.",
			Group:       "Paths",
			Type:        "text",
			Editable:    false,
		},
		{
			Key:         "secrets_path",
			Label:       "Secrets path",
			Description: "Restricted root for generated and operator-supplied secret files.",
			Group:       "Paths",
			Type:        "text",
			Editable:    false,
		},
		{
			Key:         "puid",
			Label:       "PUID",
			Description: "Linux user ID used by compatible application containers.",
			Group:       "Permissions",
			Type:        "number",
			Editable:    true,
		},
		{
			Key:         "pgid",
			Label:       "PGID",
			Description: "Linux group ID used by compatible application containers.",
			Group:       "Permissions",
			Type:        "number",
			Editable:    true,
		},
		{
			Key:         "umask",
			Label:       "Umask",
			Description: "Three- or four-digit octal creation mask passed to compatible containers.",
			Group:       "Permissions",
			Type:        "text",
			Editable:    true,
		},
		{
			Key:         "vpn_enabled",
			Label:       "VPN enabled",
			Description: "Route qBittorrent through Gluetun; disabling requires explicit exposure acknowledgement.",
			Group:       "VPN",
			Type:        "boolean",
			Editable:    true,
		},
		{
			Key:         "vpn_provider",
			Label:       "VPN provider",
			Description: "Gluetun provider identifier; credentials remain in the private provider file.",
			Group:       "VPN",
			Type:        "text",
			Editable:    true,
		},
		{
			Key:         "vpn_country",
			Label:       "VPN country",
			Description: "Optional Gluetun server-country selector.",
			Group:       "VPN",
			Type:        "text",
			Editable:    true,
		},
		{
			Key:         "torrent_peer_port",
			Label:       "Torrent peer port",
			Description: "TCP and UDP peer port owned by qBittorrent or Gluetun.",
			Group:       "VPN",
			Type:        "number",
			Editable:    true,
		},
		{
			Key:         "addons",
			Label:       "Addons",
			Description: "Resolved addon names; mutate them with addon or preset commands.",
			Group:       "Addons",
			Type:        "list",
			Editable:    false,
		},
	}
}

func ValidKeys() []string {
	return []string{
		"domain",
		"timezone",
		"plex_enabled",
		"jellyfin_enabled",
		"plex.hardware_device",
		"plex.amd_vaapi",
		"plex.lan_address",
		"plex.lan_port",
		"expose_mode",
		"expose.mode",
		"expose.tunnel_protocol",
		"expose.tls.email",
		"routing_strategy",
		"routing.strategy",
		"routing_base_domain",
		"routing.base_domain",
		"auth.factor",
		"config_path",
		"data_path",
		"downloads_path",
		"media_path",
		"secrets_path",
		"puid",
		"pgid",
		"umask",
		"vpn_enabled",
		"vpn_provider",
		"vpn_country",
		"torrent_peer_port",
	}
}

func ReadGroups() []Group {
	return []Group{
		{Name: "Core", Keys: []string{"domain", "expose.mode", "expose.tunnel_protocol", "expose.tls.email", "timezone"}},
		{Name: "Media servers", Keys: []string{"plex_enabled", "jellyfin_enabled"}},
		{Name: "Plex", Keys: []string{"plex.hardware_device", "plex.amd_vaapi", "plex.lan_address", "plex.lan_port"}},
		{Name: "Routing", Keys: []string{"routing.strategy", "routing.base_domain"}},
		{Name: "Authentication", Keys: []string{"auth.factor"}},
		{Name: "Paths", Keys: []string{"config_path", "data_path", "downloads_path", "media_path", "secrets_path"}},
		{Name: "Permissions", Keys: []string{"puid", "pgid", "umask"}},
		{Name: "VPN", Keys: []string{"vpn_enabled", "vpn_provider", "vpn_country", "torrent_peer_port"}},
		{Name: "Addons", Keys: []string{"addons"}},
	}
}

func Values(cfg *config.Config) map[string]interface{} {
	if cfg == nil {
		return map[string]interface{}{}
	}
	addons := append([]string(nil), cfg.Addons...)
	return map[string]interface{}{
		"domain":                 cfg.Domain,
		"timezone":               cfg.Timezone,
		"plex_enabled":           cfg.PlexEnabled,
		"jellyfin_enabled":       cfg.JellyfinEnabled,
		"plex.hardware_device":   cfg.Plex.HardwareDevice,
		"plex.amd_vaapi":         cfg.Plex.AMDVAAPI,
		"plex.lan_address":       cfg.Plex.LANAddress,
		"plex.lan_port":          cfg.Plex.EffectiveLANPort(),
		"expose.mode":            cfg.Expose.Mode,
		"expose.tunnel_protocol": cfg.EffectiveTunnelProtocol(),
		"expose.tls.email":       cfg.Expose.TLS.Email,
		"routing.strategy":       cfg.Routing.Strategy,
		"routing.base_domain":    cfg.Routing.BaseDomain,
		"auth.factor":            cfg.Auth.Factor,
		"config_path":            cfg.ConfigPath,
		"data_path":              cfg.DataPath,
		"downloads_path":         cfg.DownloadsPath,
		"media_path":             cfg.MediaPath,
		"secrets_path":           cfg.SecretsPath,
		"puid":                   cfg.PUID,
		"pgid":                   cfg.PGID,
		"umask":                  cfg.Umask,
		"vpn_enabled":            cfg.VPNEnabled,
		"vpn_provider":           cfg.VPNProvider,
		"vpn_country":            cfg.VPNCountry,
		"torrent_peer_port":      cfg.TorrentPort,
		"addons":                 addons,
	}
}

func Value(cfg *config.Config, key string) (interface{}, bool) {
	values := Values(cfg)
	value, ok := values[key]
	return value, ok
}

func (m *Manager) Set(ctx context.Context, key, value string) (*Result, error) {
	if m.ProjectDir == "" {
		return nil, fmt.Errorf("project directory is required")
	}
	if m.Config == nil {
		return nil, fmt.Errorf("config is required")
	}
	if m.Registry == nil {
		return nil, fmt.Errorf("registry is required")
	}

	previous := cloneConfig(m.Config)
	if key == "vpn_enabled" {
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return nil, fmt.Errorf("vpn_enabled must be a boolean")
		}
		if !enabled && !m.AllowUnprotectedDownloads {
			return nil, fmt.Errorf(
				"refusing to disable VPN without explicit acknowledgement that torrent traffic will use the host public IP",
			)
		}
	}
	if err := apply(m.Config, key, value); err != nil {
		return nil, err
	}
	if err := m.Config.Validate(); err != nil {
		*m.Config = *previous
		return nil, err
	}

	if err := m.regenerate(ctx); err != nil {
		*m.Config = *previous
		return nil, fmt.Errorf("failed to regenerate project files: %w", err)
	}

	return &Result{Key: key, Value: value, Regenerated: true}, nil
}

func (m *Manager) regenerate(ctx context.Context) error {
	if m.Lock == nil {
		return fmt.Errorf(".sdbx.lock is required for project mutations")
	}
	if m.CLIVersion == "" || m.ImageResolver == nil {
		return fmt.Errorf("locked project mutation requires CLI version and image resolver")
	}
	updated, err := generator.RegenerateRuntimeWithUpdatedLock(
		ctx,
		m.Config,
		m.ProjectDir,
		m.Registry,
		m.Lock,
		m.CLIVersion,
		m.ImageResolver,
	)
	if err != nil {
		return err
	}
	m.Lock = updated
	return nil
}

func apply(cfg *config.Config, key, value string) error {
	switch key {
	case "domain":
		cfg.Domain = value
	case "timezone":
		cfg.Timezone = value
	case "plex_enabled":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("plex_enabled must be a boolean")
		}
		cfg.PlexEnabled = parsed
	case "jellyfin_enabled":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("jellyfin_enabled must be a boolean")
		}
		cfg.JellyfinEnabled = parsed
	case "plex.hardware_device":
		cfg.Plex.HardwareDevice = value
	case "plex.amd_vaapi":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("plex.amd_vaapi must be a boolean")
		}
		cfg.Plex.AMDVAAPI = parsed
	case "plex.lan_address":
		cfg.Plex.LANAddress = value
	case "plex.lan_port":
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("plex.lan_port must be an integer")
		}
		cfg.Plex.LANPort = parsed
	case "expose_mode", "expose.mode":
		cfg.SetExposureMode(value)
	case "expose.tls.email":
		cfg.Expose.TLS.Email = strings.TrimSpace(value)
	case "expose.tunnel_protocol":
		cfg.Expose.TunnelProtocol = value
	case "routing_strategy", "routing.strategy":
		cfg.Routing.Strategy = value
	case "routing_base_domain", "routing.base_domain":
		cfg.Routing.BaseDomain = value
	case "auth.factor":
		cfg.Auth.Factor = value
	case "config_path":
		cfg.ConfigPath = value
	case "data_path":
		cfg.DataPath = value
	case "downloads_path":
		cfg.DownloadsPath = value
	case "media_path":
		cfg.MediaPath = value
	case "secrets_path":
		cfg.SecretsPath = value
	case "puid":
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("puid must be an integer")
		}
		cfg.PUID = parsed
	case "pgid":
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("pgid must be an integer")
		}
		cfg.PGID = parsed
	case "umask":
		cfg.Umask = value
	case "vpn_enabled":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("vpn_enabled must be a boolean")
		}
		cfg.VPNEnabled = parsed
	case "vpn_provider":
		cfg.VPNProvider = value
	case "vpn_country":
		cfg.VPNCountry = value
	case "torrent_peer_port":
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("torrent_peer_port must be an integer")
		}
		cfg.TorrentPort = parsed
	default:
		return fmt.Errorf("invalid configuration key: %s", key)
	}
	return nil
}

func cloneConfig(cfg *config.Config) *config.Config {
	clone := *cfg
	clone.Addons = append([]string(nil), cfg.Addons...)
	if cfg.Services != nil {
		clone.Services = make(map[string]config.ServiceOverride, len(cfg.Services))
		for key, value := range cfg.Services {
			clone.Services[key] = value
		}
	}
	return &clone
}
