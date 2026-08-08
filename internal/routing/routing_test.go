package routing

import (
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

func testDefinition() *registry.ServiceDefinition {
	return &registry.ServiceDefinition{
		Metadata: registry.ServiceMetadata{Name: "sonarr"},
		Routing: registry.RoutingConfig{
			Enabled:   true,
			Subdomain: "tv",
			Path:      "/sonarr",
		},
	}
}

func TestCatalogDefaults(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "example.test"
	definition := testDefinition()

	if got := Strategy(cfg, definition); got != config.RoutingStrategySubdomain {
		t.Fatalf("Strategy = %q", got)
	}
	if got := URL(cfg, definition); got != "https://tv.example.test" {
		t.Fatalf("URL = %q", got)
	}
	if got := Rule(cfg, definition); got != "Host(`tv.example.test`)" {
		t.Fatalf("Rule = %q", got)
	}
}

func TestSubdomainOverride(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "example.test"
	cfg.Services["sonarr"] = config.ServiceOverride{Subdomain: "shows"}
	definition := testDefinition()

	if got := URL(cfg, definition); got != "https://shows.example.test" {
		t.Fatalf("URL = %q", got)
	}
}

func TestPathOverrideCanOverrideGlobalSubdomain(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "example.test"
	cfg.Routing.BaseDomain = "media"
	cfg.Services["sonarr"] = config.ServiceOverride{
		Routing: config.RoutingStrategyPath,
		Path:    "/shows",
	}
	definition := testDefinition()

	if got := URL(cfg, definition); got != "https://media.example.test/shows" {
		t.Fatalf("URL = %q", got)
	}
	if got := Rule(cfg, definition); got != "Host(`media.example.test`) && PathPrefix(`/shows`)" {
		t.Fatalf("Rule = %q", got)
	}
}

func TestForcedSubdomainWinsOverPathOverride(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "example.test"
	cfg.Services["sonarr"] = config.ServiceOverride{
		Routing:   config.RoutingStrategyPath,
		Subdomain: "forced",
		Path:      "/ignored",
	}
	definition := testDefinition()
	definition.Routing.ForceSubdomain = true

	if got := Strategy(cfg, definition); got != config.RoutingStrategySubdomain {
		t.Fatalf("Strategy = %q", got)
	}
	if got := URL(cfg, definition); got != "https://forced.example.test" {
		t.Fatalf("URL = %q", got)
	}
}

func TestPathRouteWithoutBaseDomainUsesRootDomain(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "example.test"
	cfg.Routing.BaseDomain = ""
	cfg.Services["sonarr"] = config.ServiceOverride{
		Routing: config.RoutingStrategyPath,
		Path:    "/shows",
	}
	definition := testDefinition()

	if got := URL(cfg, definition); got != "https://example.test/shows" {
		t.Fatalf("URL = %q", got)
	}
}

func TestSharedHostname(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "example.test"
	cfg.Routing.BaseDomain = "sdbx"
	if got := SharedHostname(cfg); got != "sdbx.example.test" {
		t.Fatalf("SharedHostname() = %q", got)
	}

	cfg.Routing.BaseDomain = ""
	if got := SharedHostname(cfg); got != "example.test" {
		t.Fatalf("SharedHostname() without base domain = %q", got)
	}
}
