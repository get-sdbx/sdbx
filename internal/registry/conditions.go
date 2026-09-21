package registry

import (
	"strings"

	"github.com/get-sdbx/sdbx/internal/config"
)

const (
	conditionVPNEnabled       = "{{ .Config.VPNEnabled }}"
	conditionVPNDisabled      = "{{ not .Config.VPNEnabled }}"
	conditionExposeLAN        = `{{ eq .Config.Expose.Mode "lan" }}`
	conditionExposeNotLAN     = `{{ ne .Config.Expose.Mode "lan" }}`
	conditionExposeDirect     = `{{ eq .Config.Expose.Mode "direct" }}`
	conditionExposeNotDirect  = `{{ ne .Config.Expose.Mode "direct" }}`
	conditionExposeTunnel     = `{{ eq .Config.Expose.Mode "cloudflared" }}`
	conditionExposeNotTunnel  = `{{ ne .Config.Expose.Mode "cloudflared" }}`
	conditionExposeHostPorts  = `{{ or (eq .Config.Expose.Mode "lan") (eq .Config.Expose.Mode "direct") }}`
	conditionRoutingPath      = `{{ eq .Config.Routing.Strategy "path" }}`
	conditionRoutingSubdomain = `{{ eq .Config.Routing.Strategy "subdomain" }}`
	conditionPlexHardware     = `{{ ne .Config.Plex.HardwareDevice "" }}`
	conditionPlexLAN          = `{{ ne .Config.Plex.LANBinding "" }}`
	conditionPlexAMDVAAPI     = `{{ .Config.Plex.AMDVAAPI }}`
	conditionPlexAdvertise    = `{{ ne .Config.Plex.AdvertiseURLs "" }}`
)

var supportedCatalogConditions = map[string]struct{}{
	conditionVPNEnabled:       {},
	conditionVPNDisabled:      {},
	conditionExposeLAN:        {},
	conditionExposeNotLAN:     {},
	conditionExposeDirect:     {},
	conditionExposeNotDirect:  {},
	conditionExposeTunnel:     {},
	conditionExposeNotTunnel:  {},
	conditionExposeHostPorts:  {},
	conditionRoutingPath:      {},
	conditionRoutingSubdomain: {},
	conditionPlexHardware:     {},
	conditionPlexLAN:          {},
	conditionPlexAMDVAAPI:     {},
	conditionPlexAdvertise:    {},
}

var supportedDependencyConditions = map[string]struct{}{
	conditionVPNEnabled:      {},
	conditionVPNDisabled:     {},
	conditionExposeLAN:       {},
	conditionExposeNotLAN:    {},
	conditionExposeDirect:    {},
	conditionExposeNotDirect: {},
	conditionExposeTunnel:    {},
	conditionExposeNotTunnel: {},
	conditionExposeHostPorts: {},
}

var supportedRequireConfig = map[string]struct{}{
	"vpn_enabled":      {},
	"cloudflared":      {},
	"plex_enabled":     {},
	"jellyfin_enabled": {},
}

var supportedDependencyStartupConditions = map[string]struct{}{
	"":                               {},
	"service_started":                {},
	"service_healthy":                {},
	"service_completed_successfully": {},
}

func canonicalCatalogCondition(condition string) string {
	return strings.TrimSpace(condition)
}

func isSupportedCatalogCondition(condition string) bool {
	_, ok := supportedCatalogConditions[canonicalCatalogCondition(condition)]
	return ok
}

func isSupportedDependencyCondition(condition string) bool {
	_, ok := supportedDependencyConditions[canonicalCatalogCondition(condition)]
	return ok
}

// MatchesActivationConditions evaluates the one validated service activation
// selector shared by resolution and generation. Invalid or ambiguous selectors
// fail closed even when a caller bypasses definition validation.
func MatchesActivationConditions(conditions Conditions, cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	selectors := 0
	if conditions.Always {
		selectors++
	}
	if conditions.RequireAddon {
		selectors++
	}
	if conditions.RequireConfig != "" {
		selectors++
	}
	if selectors != 1 {
		return false
	}
	if conditions.Always || conditions.RequireAddon {
		return true
	}
	switch conditions.RequireConfig {
	case "vpn_enabled":
		return cfg.VPNEnabled
	case "cloudflared":
		return cfg.Expose.Mode == config.ExposeModeCloudflared
	case "plex_enabled":
		return cfg.PlexEnabled
	case "jellyfin_enabled":
		return cfg.JellyfinEnabled
	default:
		return false
	}
}

func evaluateDependencyCondition(condition string, cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	switch canonicalCatalogCondition(condition) {
	case conditionVPNEnabled:
		return cfg.VPNEnabled
	case conditionVPNDisabled:
		return !cfg.VPNEnabled
	case conditionExposeLAN:
		return cfg.Expose.Mode == config.ExposeModeLAN
	case conditionExposeNotLAN:
		return cfg.Expose.Mode != config.ExposeModeLAN
	case conditionExposeDirect:
		return cfg.Expose.Mode == config.ExposeModeDirect
	case conditionExposeNotDirect:
		return cfg.Expose.Mode != config.ExposeModeDirect
	case conditionExposeTunnel:
		return cfg.Expose.Mode == config.ExposeModeCloudflared
	case conditionExposeNotTunnel:
		return cfg.Expose.Mode != config.ExposeModeCloudflared
	case conditionExposeHostPorts:
		return cfg.Expose.Mode == config.ExposeModeLAN ||
			cfg.Expose.Mode == config.ExposeModeDirect
	default:
		return false
	}
}
