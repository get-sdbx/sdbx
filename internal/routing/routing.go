package routing

import (
	"fmt"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

// Strategy returns the effective routing strategy for a service. Catalog
// definitions may force subdomain routing when an application cannot operate
// safely behind a path prefix.
func Strategy(cfg *config.Config, definition *registry.ServiceDefinition) string {
	if definition.Routing.ForceSubdomain {
		return config.RoutingStrategySubdomain
	}
	if override, ok := cfg.Services[definition.Metadata.Name]; ok && override.Routing != "" {
		return override.Routing
	}
	return cfg.Routing.Strategy
}

// Subdomain returns the configured service subdomain or its catalog default.
func Subdomain(cfg *config.Config, definition *registry.ServiceDefinition) string {
	if override, ok := cfg.Services[definition.Metadata.Name]; ok && override.Subdomain != "" {
		return override.Subdomain
	}
	return definition.Routing.Subdomain
}

// Path returns the configured service path or its catalog default.
func Path(cfg *config.Config, definition *registry.ServiceDefinition) string {
	if override, ok := cfg.Services[definition.Metadata.Name]; ok && override.Path != "" {
		return override.Path
	}
	return definition.Routing.Path
}

// Hostname returns the public hostname for a routed service.
func Hostname(cfg *config.Config, definition *registry.ServiceDefinition) string {
	if Strategy(cfg, definition) == config.RoutingStrategySubdomain {
		return fmt.Sprintf("%s.%s", Subdomain(cfg, definition), cfg.Domain)
	}
	return SharedHostname(cfg)
}

// SharedHostname returns the canonical host used by path-routed services.
func SharedHostname(cfg *config.Config) string {
	if cfg.Routing.BaseDomain == "" {
		return cfg.Domain
	}
	return fmt.Sprintf("%s.%s", cfg.Routing.BaseDomain, cfg.Domain)
}

// URL returns the canonical HTTPS URL for a routed service.
func URL(cfg *config.Config, definition *registry.ServiceDefinition) string {
	hostname := Hostname(cfg, definition)
	if Strategy(cfg, definition) == config.RoutingStrategyPath {
		return "https://" + hostname + Path(cfg, definition)
	}
	return "https://" + hostname
}

// Rule returns the Traefik router rule for a routed service.
func Rule(cfg *config.Config, definition *registry.ServiceDefinition) string {
	hostname := Hostname(cfg, definition)
	if Strategy(cfg, definition) == config.RoutingStrategyPath {
		return fmt.Sprintf(
			"Host(`%s`) && PathPrefix(`%s`)",
			hostname,
			Path(cfg, definition),
		)
	}
	return fmt.Sprintf("Host(`%s`)", hostname)
}
