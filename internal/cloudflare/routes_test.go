package cloudflare

import (
	"reflect"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

func TestBuildPlanDerivesUniqueRemoteRoutes(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "media.example.test"
	cfg.Expose.Mode = config.ExposeModeCloudflared
	cfg.Routing.Strategy = config.RoutingStrategyPath
	cfg.Routing.BaseDomain = "box"

	graph := &registry.ResolutionGraph{
		Order: []string{"authelia", "sonarr", "worker", "disabled"},
		Services: map[string]*registry.ResolvedService{
			"authelia": resolvedRoute(
				"authelia",
				"auth",
				"/auth",
				true,
				true,
			),
			"sonarr": resolvedRoute(
				"sonarr",
				"sonarr",
				"/sonarr",
				false,
				true,
			),
			"worker": {
				Enabled: true,
				FinalDefinition: &registry.ServiceDefinition{
					Metadata: registry.ServiceMetadata{Name: "worker"},
				},
			},
			"disabled": resolvedRoute(
				"disabled",
				"disabled",
				"/disabled",
				false,
				false,
			),
		},
	}

	plan, err := BuildPlan(cfg, graph)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Management != ManagementMode {
		t.Fatalf("Management = %q, want %q", plan.Management, ManagementMode)
	}
	wantRoutes := []Route{
		{Hostname: "auth.media.example.test", Service: OriginService},
		{Hostname: "box.media.example.test", Service: OriginService},
	}
	if !reflect.DeepEqual(plan.Routes, wantRoutes) {
		t.Fatalf("Routes = %#v, want %#v", plan.Routes, wantRoutes)
	}
	wantURLs := []string{
		"https://auth.media.example.test",
		"https://box.media.example.test",
		"https://box.media.example.test/sonarr",
	}
	if !reflect.DeepEqual(plan.URLs, wantURLs) {
		t.Fatalf("URLs = %#v, want %#v", plan.URLs, wantURLs)
	}
}

func TestBuildPlanRejectsNonCloudflareMode(t *testing.T) {
	cfg := config.DefaultConfig()
	_, err := BuildPlan(cfg, &registry.ResolutionGraph{})
	if err == nil || !strings.Contains(err.Error(), "expose.mode=cloudflared") {
		t.Fatalf("error = %v, want exposure-mode guidance", err)
	}
}

func resolvedRoute(
	name, subdomain, path string,
	forceSubdomain, enabled bool,
) *registry.ResolvedService {
	return &registry.ResolvedService{
		Enabled: enabled,
		FinalDefinition: &registry.ServiceDefinition{
			Metadata: registry.ServiceMetadata{Name: name},
			Routing: registry.RoutingConfig{
				Enabled:        true,
				Subdomain:      subdomain,
				Path:           path,
				ForceSubdomain: forceSubdomain,
			},
		},
	}
}
