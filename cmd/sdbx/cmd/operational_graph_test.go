package cmd

import (
	"context"
	"reflect"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/docker"
	"github.com/get-sdbx/sdbx/internal/registry"
)

func verifiedGraphFixture(
	t *testing.T,
	cfg *config.Config,
) *verifiedProject {
	t.Helper()
	reg, err := registry.New(&registry.SourceConfig{
		APIVersion: registry.APIVersion,
		Kind:       registry.KindSourceConfig,
	})
	if err != nil {
		t.Fatal(err)
	}
	graph, err := reg.Resolve(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Errors) > 0 {
		t.Fatal(graph.Errors[0])
	}
	cfg.ActiveServices = make(map[string]bool)
	for _, name := range graph.Order {
		resolved := graph.Services[name]
		if resolved != nil && resolved.Enabled && resolved.FinalDefinition != nil {
			cfg.ActiveServices[name] = true
		}
	}
	return &verifiedProject{
		Project: &projectContext{
			Dir:      t.TempDir(),
			Config:   cfg,
			Registry: reg,
		},
		Graph: graph,
	}
}

func TestBuildStatusReportIncludesStoppedAndMissingLockedServices(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "box.example.test"
	verified := verifiedGraphFixture(t, cfg)
	containers := []docker.Service{
		{
			Name:    "sdbx-authelia",
			Service: "authelia",
			Status:  "running",
			Health:  "healthy",
			Running: true,
			Image:   "authelia@sha256:test",
		},
		{
			Name:     "sdbx-qbittorrent",
			Service:  "qbittorrent",
			Status:   "exited",
			Running:  false,
			ExitCode: 2,
		},
	}
	report := buildStatusReport(verified, containers)
	if report.Total != 3 || report.Running != 1 || report.Stopped != 2 {
		t.Fatalf("summary = %+v", report)
	}
	byName := make(map[string]serviceStatus)
	for _, service := range report.Services {
		byName[service.Name] = service
	}
	if byName["authelia"].Route != "https://auth.box.example.test" {
		t.Fatalf("Authelia route = %q", byName["authelia"].Route)
	}
	if byName["qbittorrent"].Route != "https://qbt.box.example.test" ||
		byName["qbittorrent"].Status != "exited" ||
		byName["qbittorrent"].ExitCode != 2 {
		t.Fatalf("qBittorrent status = %+v", byName["qbittorrent"])
	}
	if byName["traefik"].Present || byName["traefik"].Status != "missing" {
		t.Fatalf("missing Traefik status = %+v", byName["traefik"])
	}
	if _, advertised := byName["plex"]; advertised {
		t.Fatal("status advertised disabled Plex")
	}
}

func TestGraphOpenRoutesAdvertisesOnlyActiveRoutedServices(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "box.example.test"
	verified := verifiedGraphFixture(t, cfg)
	routes, aliases := graphOpenRoutes(verified)
	names := make([]string, 0, len(routes))
	for _, route := range routes {
		names = append(names, route.Name)
	}
	if !reflect.DeepEqual(names, []string{"authelia", "qbittorrent"}) {
		t.Fatalf("routes = %v", names)
	}
	if aliases["auth"].URL != "https://auth.box.example.test" {
		t.Fatalf("auth alias = %+v", aliases["auth"])
	}
	if aliases["qbt"].URL != "https://qbt.box.example.test" {
		t.Fatalf("qbt alias = %+v", aliases["qbt"])
	}
	for _, disabled := range []string{"plex", "jellyfin", "filebrowser", "radarr"} {
		if _, advertised := aliases[disabled]; advertised {
			t.Fatalf("disabled service %q was advertised", disabled)
		}
	}
}

func TestResolvedQBTPublicHostnameHonorsServiceOverride(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "box.example.test"
	cfg.Services["qbittorrent"] = config.ServiceOverride{
		Subdomain: "downloads",
	}
	verified := verifiedGraphFixture(t, cfg)
	if got := resolvedQBTPublicHostname(verified); got != "downloads.box.example.test" {
		t.Fatalf("qBittorrent hostname = %q", got)
	}
}

func TestMatchContainerToGraphUsesActiveCatalogNames(t *testing.T) {
	verified := verifiedGraphFixture(t, config.DefaultConfig())
	if actual := matchContainerToGraph("sdbx-qbittorrent", verified.Graph); actual != "qbittorrent" {
		t.Fatalf("container match = %q", actual)
	}
	if actual := matchContainerToGraph("unrelated-container", verified.Graph); actual != "" {
		t.Fatalf("unrelated container matched %q", actual)
	}
}
