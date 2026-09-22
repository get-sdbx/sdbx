package generator

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	sdbxcloudflare "github.com/get-sdbx/sdbx/internal/cloudflare"
	"github.com/get-sdbx/sdbx/internal/commandexec"
	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
	"gopkg.in/yaml.v3"
)

func TestAutheliaRulesComeFromResolvedGraph(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "media.example.test"
	cfg.Routing.Strategy = config.RoutingStrategyPath
	cfg.Routing.BaseDomain = "box"
	cfg.JellyfinEnabled = true
	cfg.Addons = []string{"filebrowser", "sonarr"}

	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	graph, err := reg.Resolve(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := NewIntegrationsGenerator(cfg).GenerateAutheliaAccessRules(graph)
	if err != nil {
		t.Fatal(err)
	}

	byResource := map[string]AutheliaAccessRule{}
	byDomain := map[string]AutheliaAccessRule{}
	for _, rule := range rules {
		resource := ""
		if len(rule.Resources) > 0 {
			resource = rule.Resources[0]
		}
		byResource[resource] = rule
		byDomain[rule.Domain] = rule
		if rule.Domain == "jellyfin.media.example.test" {
			t.Fatal("native-auth Jellyfin received an Authelia rule")
		}
	}

	sonarr, ok := byResource[`^/sonarr([/?].*)?$`]
	if !ok {
		t.Fatalf("Sonarr resource rule missing: %#v", rules)
	}
	if sonarr.Domain != "box.media.example.test" ||
		len(sonarr.Subject) != 1 ||
		sonarr.Subject[0] != "group:admins" {
		t.Fatalf("Sonarr rule = %#v", sonarr)
	}
	qbt := byDomain["qbt.media.example.test"]
	if qbt.Policy != "one_factor" || len(qbt.Subject) != 1 {
		t.Fatalf("qBittorrent admin rule = %#v", qbt)
	}
}

func TestAutheliaRulesUseTypedTwoFactorPolicy(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "media.example.test"
	cfg.Auth.Factor = config.AuthFactorTwo
	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	graph, err := reg.Resolve(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := NewIntegrationsGenerator(cfg).GenerateAutheliaAccessRules(graph)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatal("two-factor graph generated no Authelia rules")
	}
	for _, rule := range rules {
		if rule.Policy != config.AuthFactorTwo {
			t.Fatalf("rule policy = %q, want two_factor: %#v", rule.Policy, rule)
		}
	}
}

func TestServiceRouteOverrideReachesEveryGeneratedConsumer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "media.example.test"
	cfg.Expose.Mode = config.ExposeModeCloudflared
	cfg.Addons = []string{"filebrowser", "sonarr"}
	cfg.Services["filebrowser"] = config.ServiceOverride{
		Routing: config.RoutingStrategyPath,
		Path:    "/files",
	}
	cfg.Services["sonarr"] = config.ServiceOverride{
		Routing: config.RoutingStrategyPath,
		Path:    "/shows",
	}

	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	graph, err := reg.Resolve(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Errors) > 0 {
		t.Fatalf("resolution errors = %#v", graph.Errors)
	}

	compose, err := NewComposeGenerator(cfg, reg).Generate(graph)
	if err != nil {
		t.Fatal(err)
	}
	filebrowser := compose.Services["filebrowser"]
	if len(filebrowser.Labels) != 0 {
		t.Fatalf("File Browser retained Docker-provider labels: %#v", filebrowser.Labels)
	}
	if filebrowser.Command != "--baseurl /files" {
		t.Fatalf("File Browser base URL command = %q", filebrowser.Command)
	}
	if !contains(compose.Services["sonarr"].Environment, "SONARR__SERVER__URLBASE=/shows") {
		t.Fatalf(
			"Sonarr environment = %#v, missing effective path",
			compose.Services["sonarr"].Environment,
		)
	}

	integrations := NewIntegrationsGenerator(cfg)
	dynamicBody, err := integrations.GenerateTraefikDynamic(graph)
	if err != nil {
		t.Fatal(err)
	}
	var dynamic TraefikDynamicConfig
	if err := yaml.Unmarshal(dynamicBody, &dynamic); err != nil {
		t.Fatalf("invalid Traefik dynamic YAML: %v\n%s", err, dynamicBody)
	}
	filebrowserRouter := dynamic.HTTP.Routers["filebrowser"]
	if filebrowserRouter.Rule !=
		"Host(`sdbx.media.example.test`) && PathPrefix(`/files`)" ||
		len(filebrowserRouter.EntryPoints) != 1 ||
		filebrowserRouter.EntryPoints[0] != "tunnel" ||
		!contains(filebrowserRouter.Middlewares, "security-headers") ||
		!contains(filebrowserRouter.Middlewares, "authelia") {
		t.Fatalf("File Browser file-provider router = %#v", filebrowserRouter)
	}
	filebrowserServers := dynamic.HTTP.Services["filebrowser"].LoadBalancer.Servers
	if len(filebrowserServers) != 1 ||
		filebrowserServers[0].URL != "http://filebrowser:80" {
		t.Fatalf("File Browser backend = %#v", filebrowserServers)
	}
	if strings.Contains(string(dynamicBody), "strip-filebrowser:") {
		t.Fatalf("File Browser must consume its base path instead of stripping it:\n%s", dynamicBody)
	}

	cloudflarePlan, err := sdbxcloudflare.BuildPlan(cfg, graph)
	if err != nil {
		t.Fatal(err)
	}
	foundCloudflareHost := false
	for _, route := range cloudflarePlan.Routes {
		if route.Hostname == "sdbx.media.example.test" {
			foundCloudflareHost = true
			break
		}
	}
	if !foundCloudflareHost {
		t.Fatalf(
			"Cloudflare route override host missing: %#v",
			cloudflarePlan,
		)
	}

	rules, err := integrations.GenerateAutheliaAccessRules(graph)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rule := range rules {
		if rule.Domain == "sdbx.media.example.test" &&
			len(rule.Resources) == 1 &&
			rule.Resources[0] == `^/files([/?].*)?$` {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Authelia override rule missing: %#v", rules)
	}
}

func TestMigratedLegacyServicesKeepSharedPathRoutes(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "example.test"
	cfg.Expose.Mode = config.ExposeModeCloudflared
	cfg.Routing.Strategy = config.RoutingStrategyPath
	cfg.Routing.BaseDomain = "sdbx"
	cfg.PlexEnabled = false
	cfg.JellyfinEnabled = false
	cfg.Addons = []string{"bazarr", "stash", "tautulli"}

	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	graph, err := reg.Resolve(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Errors) > 0 {
		t.Fatalf("resolution errors = %#v", graph.Errors)
	}

	compose, err := NewComposeGenerator(cfg, reg).Generate(graph)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(
		compose.Services["bazarr"].Environment,
		"BAZARR__SERVER__URLBASE=/bazarr",
	) {
		t.Fatalf("Bazarr environment = %#v", compose.Services["bazarr"].Environment)
	}
	if !contains(
		compose.Services["tautulli"].Environment,
		"TAUTULLI_URLBASE=/tautulli",
	) {
		t.Fatalf("Tautulli environment = %#v", compose.Services["tautulli"].Environment)
	}

	dynamicBody, err := NewIntegrationsGenerator(cfg).GenerateTraefikDynamic(graph)
	if err != nil {
		t.Fatal(err)
	}
	var dynamic TraefikDynamicConfig
	if err := yaml.Unmarshal(dynamicBody, &dynamic); err != nil {
		t.Fatalf("invalid Traefik dynamic YAML: %v\n%s", err, dynamicBody)
	}
	for _, service := range []string{"bazarr", "stash", "tautulli"} {
		router := dynamic.HTTP.Routers[service]
		wantRule := fmt.Sprintf(
			"Host(`sdbx.example.test`) && PathPrefix(`/%s`)",
			service,
		)
		if router.Rule != wantRule || !contains(router.Middlewares, "authelia") {
			t.Fatalf("%s router = %#v, want rule %q with Authelia", service, router, wantRule)
		}
	}
	dashboardRouter := dynamic.HTTP.Routers["dashboard"]
	if dashboardRouter.Rule != "Host(`sdbx.example.test`) && (Path(`/`) || PathPrefix(`/api/`) || PathPrefix(`/static/`))" ||
		dashboardRouter.Service != "dashboard" ||
		!slices.Equal(dashboardRouter.Middlewares, []string{
			"tunnel-forwarded-scheme",
			"security-headers",
			"authelia",
		}) {
		t.Fatalf("dashboard router = %#v", dashboardRouter)
	}
	dashboard := dynamic.HTTP.Services["dashboard"].LoadBalancer
	if dashboard.ServersTransport != "console-mtls" ||
		len(dashboard.Servers) != 1 ||
		dashboard.Servers[0].URL != "https://host.docker.internal:18777" {
		t.Fatalf("dashboard service = %#v", dashboard)
	}
	transport := dynamic.HTTP.ServersTransport["console-mtls"]
	if transport.ServerName != "sdbx-console.internal" ||
		transport.MinVersion != "VersionTLS13" ||
		transport.MaxVersion != "VersionTLS13" ||
		len(transport.Certificates) != 1 ||
		transport.Certificates[0].CertFile != "/run/secrets/console_proxy_client_cert" ||
		transport.Certificates[0].KeyFile != "/run/secrets/console_proxy_client_key" ||
		len(transport.RootCAs) != 1 {
		t.Fatalf("dashboard mTLS transport = %#v", transport)
	}
	if !contains(dynamic.HTTP.Routers["stash"].Middlewares, "strip-stash") {
		t.Fatalf("Stash router = %#v, missing prefix stripping", dynamic.HTTP.Routers["stash"])
	}
	wantStashMiddlewares := []string{
		"tunnel-forwarded-scheme",
		"security-headers",
		"authelia",
		"strip-stash",
	}
	if !slices.Equal(
		dynamic.HTTP.Routers["stash"].Middlewares,
		wantStashMiddlewares,
	) {
		t.Fatalf(
			"Stash middlewares = %#v, want ForwardAuth before path stripping",
			dynamic.HTTP.Routers["stash"].Middlewares,
		)
	}
	for _, service := range []string{"bazarr", "tautulli"} {
		if contains(dynamic.HTTP.Routers[service].Middlewares, "strip-"+service) {
			t.Fatalf("%s must consume its native URL base: %#v", service, dynamic.HTTP.Routers[service])
		}
	}

	cloudflarePlan, err := sdbxcloudflare.BuildPlan(cfg, graph)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []string{"bazarr", "stash", "tautulli"} {
		wantURL := fmt.Sprintf("https://sdbx.example.test/%s", service)
		if !contains(cloudflarePlan.URLs, wantURL) {
			t.Fatalf("Cloudflare URLs = %#v, missing %q", cloudflarePlan.URLs, wantURL)
		}
		for _, route := range cloudflarePlan.Routes {
			if route.Hostname == service+".example.test" {
				t.Fatalf("Cloudflare plan introduced %s subdomain: %#v", service, cloudflarePlan.Routes)
			}
		}
	}
}

func TestTraefikForwardAuthUsesCurrentBoundedEndpoint(t *testing.T) {
	cfg := config.DefaultConfig()
	graph := &registry.ResolutionGraph{}
	body, err := NewIntegrationsGenerator(cfg).GenerateTraefikDynamic(graph)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "http://authelia:9091/api/authz/forward-auth") {
		t.Fatalf("modern ForwardAuth endpoint missing:\n%s", body)
	}
	if !strings.Contains(text, "maxResponseBodySize: 8192") {
		t.Fatalf("ForwardAuth body bound missing:\n%s", body)
	}
	if !strings.Contains(text, "trustForwardHeader: true") {
		t.Fatalf("ForwardAuth must consume EntryPoint-sanitized headers:\n%s", body)
	}
	if strings.Contains(text, "/api/verify") {
		t.Fatalf("legacy ForwardAuth endpoint survived:\n%s", body)
	}
}

func TestTraefikRejectsDuplicateEffectiveRoutes(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "media.example.test"
	cfg.Routing.Strategy = config.RoutingStrategyPath
	cfg.Routing.BaseDomain = "box"

	protected := routedTestDefinition("protected", "/same", registry.AuthModeProtected)
	public := routedTestDefinition("public", "/same", registry.AuthModePublic)
	graph := &registry.ResolutionGraph{
		Order: []string{"protected", "public"},
		Services: map[string]*registry.ResolvedService{
			"protected": {
				Name:            "protected",
				FinalDefinition: protected,
				Enabled:         true,
			},
			"public": {
				Name:            "public",
				FinalDefinition: public,
				Enabled:         true,
			},
		},
	}

	_, err := NewIntegrationsGenerator(cfg).GenerateTraefikDynamic(graph)
	if err == nil ||
		!strings.Contains(err.Error(), `"protected" and "public"`) ||
		!strings.Contains(err.Error(), "same Traefik route") {
		t.Fatalf("duplicate effective route error = %v", err)
	}
}

func routedTestDefinition(
	name string,
	routePath string,
	authMode registry.AuthMode,
) *registry.ServiceDefinition {
	return &registry.ServiceDefinition{
		Metadata: registry.ServiceMetadata{Name: name},
		Spec: registry.ServiceSpec{
			Networking: registry.NetworkSpec{
				Networks: []registry.NetworkRef{{Name: registry.NetworkApplication}},
			},
		},
		Routing: registry.RoutingConfig{
			Enabled: true,
			Port:    8080,
			Path:    routePath,
			Auth:    registry.AuthConfig{Mode: authMode},
			Traefik: registry.TraefikConfig{Network: registry.NetworkApplication},
		},
		Conditions: registry.Conditions{Always: true},
	}
}

func TestGeneratedAutheliaUsesModernSessionAndLANUsesTLS(t *testing.T) {
	outputDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Domain = "media.example.test"
	cfg.Expose.Mode = config.ExposeModeLAN
	cfg.Routing.Strategy = config.RoutingStrategyPath
	cfg.Routing.BaseDomain = "box"
	cfg.JellyfinEnabled = true
	cfg.Addons = []string{"filebrowser", "sonarr"}

	gen := newTestGenerator(t, cfg, outputDir)
	if err := gen.Generate(); err != nil {
		t.Fatal(err)
	}

	autheliaBody, err := os.ReadFile(
		filepath.Join(outputDir, "configs", "authelia", "configuration.yml"),
	)
	if err != nil {
		t.Fatal(err)
	}
	var authelia map[string]any
	if err := yaml.Unmarshal(autheliaBody, &authelia); err != nil {
		t.Fatalf("invalid Authelia YAML: %v\n%s", err, autheliaBody)
	}
	server := authelia["server"].(map[string]any)
	if server["address"] != "tcp://0.0.0.0:9091/auth" {
		t.Fatalf("server.address = %#v", server["address"])
	}
	if disabled, ok := server["disable_healthcheck"].(bool); !ok || !disabled {
		t.Fatalf(
			"server.disable_healthcheck = %#v, want true for read-only root filesystem",
			server["disable_healthcheck"],
		)
	}
	webauthn := authelia["webauthn"].(map[string]any)
	metadata := webauthn["metadata"].(map[string]any)
	if enabled, ok := metadata["enabled"].(bool); !ok || enabled {
		t.Fatalf("webauthn.metadata.enabled = %#v, want false", metadata["enabled"])
	}
	session := authelia["session"].(map[string]any)
	if _, legacy := session["domain"]; legacy {
		t.Fatal("legacy session.domain survived")
	}
	cookies := session["cookies"].([]any)
	cookie := cookies[0].(map[string]any)
	if cookie["authelia_url"] != "https://box.media.example.test/auth" {
		t.Fatalf("authelia_url = %#v", cookie["authelia_url"])
	}
	rules := authelia["access_control"].(map[string]any)["rules"].([]any)
	if len(rules) == 0 {
		t.Fatal("resolved access rules are empty")
	}
	composeBody, err := os.ReadFile(filepath.Join(outputDir, "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var compose ComposeFile
	if err := yaml.Unmarshal(composeBody, &compose); err != nil {
		t.Fatalf("invalid Compose YAML: %v\n%s", err, composeBody)
	}
	for _, serviceName := range []string{"qbittorrent", "jellyfin"} {
		if labels := compose.Services[serviceName].Labels; len(labels) != 0 {
			t.Fatalf("%s retained Docker-provider labels: %#v", serviceName, labels)
		}
	}
	traefikService := compose.Services["traefik"]
	for _, port := range []string{"80:80", "443:443"} {
		if !contains(traefikService.Ports, port) {
			t.Fatalf("LAN Traefik ports = %#v, missing %q", traefikService.Ports, port)
		}
	}
	for _, volume := range traefikService.Volumes {
		if strings.Contains(volume, "acme.json") {
			t.Fatalf("LAN mode mounted mutable ACME state: %#v", traefikService.Volumes)
		}
	}

	traefikBody, err := os.ReadFile(
		filepath.Join(outputDir, "configs", "traefik", "traefik.yml"),
	)
	if err != nil {
		t.Fatal(err)
	}
	var traefik map[string]any
	if err := yaml.Unmarshal(traefikBody, &traefik); err != nil {
		t.Fatalf("invalid Traefik YAML: %v\n%s", err, traefikBody)
	}
	entrypoints := traefik["entryPoints"].(map[string]any)
	websecure := entrypoints["websecure"].(map[string]any)
	if _, ok := websecure["http"].(map[string]any)["tls"]; !ok {
		t.Fatal("LAN websecure entrypoint does not enable TLS")
	}
	if strings.Contains(string(traefikBody), "insecure: true") {
		t.Fatal("Traefik trusts forwarded headers from arbitrary clients")
	}
	global := traefik["global"].(map[string]any)
	if global["checkNewVersion"] != false || global["sendAnonymousUsage"] != false {
		t.Fatalf("Traefik telemetry policy = %#v", global)
	}
	api := traefik["api"].(map[string]any)
	if api["dashboard"] != false || api["insecure"] != false {
		t.Fatalf("Traefik API policy = %#v", api)
	}
	if websecure["http"].(map[string]any)["maxHeaderBytes"] != 32768 {
		t.Fatalf("Traefik header bound = %#v", websecure["http"])
	}
	accessLog := traefik["accessLog"].(map[string]any)
	fields := accessLog["fields"].(map[string]any)
	queryParameters := fields["queryParameters"].(map[string]any)
	if queryParameters["defaultMode"] != "drop" {
		t.Fatalf("Traefik query logging policy = %#v", queryParameters)
	}

	dynamicBody, err := os.ReadFile(
		filepath.Join(outputDir, "configs", "traefik", "dynamic", "middlewares.yml"),
	)
	if err != nil {
		t.Fatal(err)
	}
	var dynamic map[string]any
	if err := yaml.Unmarshal(dynamicBody, &dynamic); err != nil {
		t.Fatalf("invalid Traefik dynamic YAML: %v\n%s", err, dynamicBody)
	}
	middlewares := dynamic["http"].(map[string]any)["middlewares"].(map[string]any)
	headers := middlewares["security-headers"].(map[string]any)["headers"].(map[string]any)
	if headers["contentTypeNosniff"] != true || headers["referrerPolicy"] != "same-origin" {
		t.Fatalf("security headers = %#v", headers)
	}
	if _, present := headers["stsSeconds"]; present {
		t.Fatalf("LAN self-signed TLS must not set HSTS: %#v", headers)
	}
	routers := dynamic["http"].(map[string]any)["routers"].(map[string]any)
	qbittorrentRouter := routers["qbittorrent"].(map[string]any)
	if entryPoints := qbittorrentRouter["entryPoints"].([]any); len(entryPoints) != 1 || entryPoints[0] != "websecure" {
		t.Fatalf("qBittorrent entrypoints = %#v", entryPoints)
	}
	if _, present := qbittorrentRouter["tls"]; !present {
		t.Fatal("LAN qBittorrent router does not enable TLS")
	}
	qbittorrentMiddlewares := qbittorrentRouter["middlewares"].([]any)
	if !anySliceContains(qbittorrentMiddlewares, "security-headers") ||
		!anySliceContains(qbittorrentMiddlewares, "authelia") {
		t.Fatalf("qBittorrent middlewares = %#v", qbittorrentMiddlewares)
	}
	jellyfinRouter := routers["jellyfin"].(map[string]any)
	jellyfinMiddlewares := jellyfinRouter["middlewares"].([]any)
	if !anySliceContains(jellyfinMiddlewares, "security-headers") ||
		!anySliceContains(jellyfinMiddlewares, "strip-jellyfin") ||
		anySliceContains(jellyfinMiddlewares, "authelia") {
		t.Fatalf("native-auth Jellyfin middlewares = %#v", jellyfinMiddlewares)
	}
	tlsDefault := dynamic["tls"].(map[string]any)["options"].(map[string]any)["default"].(map[string]any)
	if tlsDefault["minVersion"] != "VersionTLS12" || tlsDefault["sniStrict"] != false {
		t.Fatalf("LAN TLS must allow its default certificate with TLS 1.2+: %#v", tlsDefault)
	}
}

func TestDirectTraefikRendersConfiguredACMEEmail(t *testing.T) {
	outputDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Domain = "media.example.test"
	cfg.Expose.Mode = config.ExposeModeDirect
	cfg.Expose.TLS.Provider = "acme"
	cfg.Expose.TLS.Email = "ops@example.test"

	gen := newTestGenerator(t, cfg, outputDir)
	if err := gen.Generate(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(
		filepath.Join(outputDir, "configs", "traefik", "traefik.yml"),
	)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, `email: "ops@example.test"`) {
		t.Fatalf("configured ACME email missing:\n%s", body)
	}
	if strings.Contains(text, "${TRAEFIK_ACME_EMAIL}") {
		t.Fatal("Traefik config contains a non-functional shell-style placeholder")
	}

	acmePath := filepath.Join(outputDir, "configs", "traefik", "acme.json")
	acmeInfo, err := os.Lstat(acmePath)
	if err != nil {
		t.Fatalf("ACME state was not created: %v", err)
	}
	if !acmeInfo.Mode().IsRegular() || acmeInfo.Mode().Perm() != 0o600 {
		t.Fatalf("ACME state mode = %s, want regular 0600", acmeInfo.Mode())
	}
	composeBody, err := os.ReadFile(filepath.Join(outputDir, "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(
		string(composeBody),
		"./configs/traefik/acme.json:/acme.json",
	) {
		t.Fatalf("Traefik ACME state is not persisted:\n%s", composeBody)
	}
	const acmeCanary = `{"preserve":"certificate-state"}`
	if err := os.WriteFile(acmePath, []byte(acmeCanary), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := gen.GenerateRuntimeFiles(); err != nil {
		t.Fatal(err)
	}
	preserved, err := os.ReadFile(acmePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(preserved) != acmeCanary {
		t.Fatalf("ACME state was overwritten: %q", preserved)
	}

	dynamicBody, err := os.ReadFile(
		filepath.Join(outputDir, "configs", "traefik", "dynamic", "middlewares.yml"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dynamicBody), "stsSeconds: 31536000") {
		t.Fatalf("public TLS routes are missing HSTS:\n%s", dynamicBody)
	}
	var dynamic TraefikDynamicConfig
	if err := yaml.Unmarshal(dynamicBody, &dynamic); err != nil {
		t.Fatal(err)
	}
	if policy := dynamic.TLS.Options["default"]; !policy.SNIStrict || policy.MinVersion != "VersionTLS12" {
		t.Fatalf("direct ACME TLS must retain strict SNI and TLS 1.2+: %#v", policy)
	}
}

func TestDirectGenerationRejectsSymlinkedACMEState(t *testing.T) {
	outputDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Domain = "media.example.test"
	cfg.Expose.Mode = config.ExposeModeDirect
	cfg.Expose.TLS.Provider = "acme"
	cfg.Expose.TLS.Email = "ops@example.test"

	traefikDir := filepath.Join(outputDir, "configs", "traefik")
	if err := os.MkdirAll(traefikDir, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(outputDir, "victim.json")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(traefikDir, "acme.json")); err != nil {
		t.Fatal(err)
	}

	gen := newTestGenerator(t, cfg, outputDir)
	err := gen.Generate()
	if err == nil || !strings.Contains(err.Error(), "must be a regular file") {
		t.Fatalf("Generate error = %v, want ACME symlink rejection", err)
	}
	body, readErr := os.ReadFile(victim)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(body) != "keep" {
		t.Fatalf("ACME symlink victim was modified: %q", body)
	}
}

func TestCloudflaredUsesDedicatedTunnelEntrypoint(t *testing.T) {
	outputDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Domain = "media.example.test"
	cfg.Expose.Mode = config.ExposeModeCloudflared

	gen := newTestGenerator(t, cfg, outputDir)
	if err := gen.Generate(); err != nil {
		t.Fatal(err)
	}

	composeBody, err := os.ReadFile(filepath.Join(outputDir, "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var compose ComposeFile
	if err := yaml.Unmarshal(composeBody, &compose); err != nil {
		t.Fatalf("invalid Compose YAML: %v\n%s", err, composeBody)
	}
	if labels := compose.Services["qbittorrent"].Labels; len(labels) != 0 {
		t.Fatalf("qBittorrent retained Docker-provider labels: %#v", labels)
	}
	traefikService := compose.Services["traefik"]
	for _, port := range traefikService.Ports {
		if strings.Contains(port, "8081") {
			t.Fatalf("container-only tunnel entrypoint was host-published: %#v", traefikService.Ports)
		}
	}

	cloudflaredService := compose.Services["cloudflared"]
	for _, mount := range cloudflaredService.Volumes {
		if strings.Contains(mount, "/etc/cloudflared") {
			t.Fatalf(
				"remote-managed Cloudflared mounted local config: %#v",
				cloudflaredService.Volumes,
			)
		}
	}

	traefikBody, err := os.ReadFile(
		filepath.Join(outputDir, "configs", "traefik", "traefik.yml"),
	)
	if err != nil {
		t.Fatal(err)
	}
	var traefik map[string]any
	if err := yaml.Unmarshal(traefikBody, &traefik); err != nil {
		t.Fatalf("invalid Traefik YAML: %v\n%s", err, traefikBody)
	}
	entrypoints := traefik["entryPoints"].(map[string]any)
	tunnel := entrypoints["tunnel"].(map[string]any)
	if tunnel["address"] != ":8081" {
		t.Fatalf("tunnel.address = %#v", tunnel["address"])
	}
	assertNoTrustedForwardedHeaderSources(t, "tunnel", tunnel)
	if web, ok := entrypoints["web"].(map[string]any); ok {
		assertNoTrustedForwardedHeaderSources(t, "web", web)
	}
	providers := traefik["providers"].(map[string]any)
	if _, present := providers["docker"]; present {
		t.Fatal("Traefik Docker provider survived")
	}
	dynamicBody, err := os.ReadFile(
		filepath.Join(outputDir, "configs", "traefik", "dynamic", "middlewares.yml"),
	)
	if err != nil {
		t.Fatal(err)
	}
	var dynamic TraefikDynamicConfig
	if err := yaml.Unmarshal(dynamicBody, &dynamic); err != nil {
		t.Fatalf("invalid Traefik dynamic YAML: %v\n%s", err, dynamicBody)
	}
	qbittorrentRouter := dynamic.HTTP.Routers["qbittorrent"]
	if len(qbittorrentRouter.EntryPoints) != 1 ||
		qbittorrentRouter.EntryPoints[0] != "tunnel" ||
		qbittorrentRouter.TLS != nil {
		t.Fatalf("qBittorrent tunnel router = %#v", qbittorrentRouter)
	}
	forwardedScheme := dynamic.HTTP.Middlewares["tunnel-forwarded-scheme"].Headers
	if forwardedScheme == nil ||
		forwardedScheme.CustomRequestHeaders["X-Forwarded-Proto"] != "https" ||
		forwardedScheme.CustomRequestHeaders["X-Forwarded-Port"] != "443" {
		t.Fatalf("tunnel forwarding middleware = %#v", forwardedScheme)
	}
	securityHeaders := dynamic.HTTP.Middlewares["security-headers"].Headers
	if securityHeaders == nil ||
		securityHeaders.STSSeconds != 31536000 ||
		!securityHeaders.ForceSTSHeader {
		t.Fatalf("tunnel HSTS middleware = %#v", securityHeaders)
	}
	if len(qbittorrentRouter.Middlewares) < 2 ||
		qbittorrentRouter.Middlewares[0] != "tunnel-forwarded-scheme" ||
		qbittorrentRouter.Middlewares[len(qbittorrentRouter.Middlewares)-1] != "authelia" {
		t.Fatalf("qBittorrent middleware order = %#v", qbittorrentRouter.Middlewares)
	}
	if strings.Contains(string(traefikBody), "insecure: true") {
		t.Fatalf("Traefik static config trusts forwarded headers:\n%s", traefikBody)
	}
}

func assertNoTrustedForwardedHeaderSources(
	t *testing.T,
	name string,
	entrypoint map[string]any,
) {
	t.Helper()
	forwarded, ok := entrypoint["forwardedHeaders"].(map[string]any)
	if !ok {
		t.Fatalf("%s.forwardedHeaders = %#v", name, entrypoint["forwardedHeaders"])
	}
	trusted, ok := forwarded["trustedIPs"].([]any)
	if !ok || len(trusted) != 0 {
		t.Fatalf("%s trusted forwarded-header sources = %#v", name, trusted)
	}
	if insecure, present := forwarded["insecure"]; present && insecure != false {
		t.Fatalf("%s forwardedHeaders.insecure = %#v", name, insecure)
	}
}

func TestLiveTraefikSanitizesUntrustedForwardedHeaders(t *testing.T) {
	if os.Getenv("SDBX_LIVE_CONTAINER_TEST") != "1" {
		t.Skip("set SDBX_LIVE_CONTAINER_TEST=1 to validate with the configured Traefik image")
	}

	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	authRequests := make(chan http.Header, 1)
	authServer := &http.Server{
		ReadHeaderTimeout: 2 * time.Second,
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			authRequests <- request.Header.Clone()
			writer.WriteHeader(http.StatusUnauthorized)
		}),
	}
	go func() {
		_ = authServer.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = authServer.Close()
	})

	definition, err := registry.NewLoader().LoadServiceDefinition(
		filepath.Join("..", "..", "services", "core", "traefik", "service.yaml"),
	)
	if err != nil {
		t.Fatal(err)
	}
	image := definition.Spec.Image.Repository + ":" + definition.Spec.Image.Tag
	authPort := listener.Addr().(*net.TCPAddr).Port
	configDir := t.TempDir()
	staticPath := filepath.Join(configDir, "traefik.yml")
	dynamicPath := filepath.Join(configDir, "dynamic.yml")
	staticBody := []byte(`entryPoints:
  web:
    address: ":8080"
    forwardedHeaders:
      trustedIPs: []
providers:
  file:
    filename: /etc/traefik/dynamic.yml
log:
  level: ERROR
`)
	dynamicBody := []byte(fmt.Sprintf(`http:
  middlewares:
    auth:
      forwardAuth:
        address: "http://host.docker.internal:%d/auth"
        trustForwardHeader: true
        maxResponseBodySize: 8192
  routers:
    test:
      entryPoints: [web]
      rule: "Host(`+"`service.example.test`"+`)"
      middlewares: [auth]
      service: unreachable
  services:
    unreachable:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:65535"
`, authPort))
	if err := os.WriteFile(staticPath, staticBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dynamicPath, dynamicBody, 0o600); err != nil {
		t.Fatal(err)
	}

	containerName := "sdbx-forwardauth-test-" + strconv.Itoa(os.Getpid())
	runCtx, cancelRun := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancelRun()
	output, err := commandexec.CombinedOutput(
		runCtx,
		1<<20,
		nil,
		"docker",
		"run",
		"--detach",
		"--rm",
		"--name",
		containerName,
		"--publish",
		"127.0.0.1::8080",
		"--volume",
		staticPath+":/etc/traefik/traefik.yml:ro",
		"--volume",
		dynamicPath+":/etc/traefik/dynamic.yml:ro",
		image,
	)
	if err != nil {
		t.Fatalf("start Traefik %s: %v\n%s", image, err, output)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		_, _ = commandexec.CombinedOutput(
			cleanupCtx,
			1<<20,
			nil,
			"docker",
			"stop",
			"--time",
			"1",
			containerName,
		)
	})

	var published string
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		portCtx, portCancel := context.WithTimeout(context.Background(), 2*time.Second)
		output, portErr := commandexec.CombinedOutput(
			portCtx,
			1<<20,
			nil,
			"docker",
			"port",
			containerName,
			"8080/tcp",
		)
		portCancel()
		if portErr == nil && strings.TrimSpace(string(output)) != "" {
			published = strings.TrimSpace(string(output))
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if published == "" {
		t.Fatal("Traefik did not publish its test entrypoint")
	}

	client := &http.Client{Timeout: 2 * time.Second}
	var response *http.Response
	lastStatus := ""
	requestDeadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(requestDeadline) {
		request, requestErr := http.NewRequest(
			http.MethodGet,
			"http://"+published+"/safe?value=1",
			nil,
		)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Host = "service.example.test"
		request.Header.Set("X-Forwarded-Host", "attacker.example.test")
		request.Header.Set("X-Forwarded-Uri", "/admin")
		request.Header.Set("X-Forwarded-Method", http.MethodDelete)
		request.Header.Set("X-Forwarded-Proto", "javascript")
		request.Header.Set("X-Forwarded-For", "203.0.113.66")

		response, err = client.Do(request)
		if err == nil {
			lastStatus = response.Status
			_ = response.Body.Close()
			if response.StatusCode == http.StatusUnauthorized {
				break
			}
			response = nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	if response == nil {
		t.Fatalf("Traefik did not load the ForwardAuth router: status=%q error=%v", lastStatus, err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Traefik response = %s", response.Status)
	}

	select {
	case headers := <-authRequests:
		if headers.Get("X-Forwarded-Host") != "service.example.test" {
			t.Fatalf("sanitized X-Forwarded-Host = %q", headers.Get("X-Forwarded-Host"))
		}
		if headers.Get("X-Forwarded-Uri") != "/safe?value=1" {
			t.Fatalf("sanitized X-Forwarded-Uri = %q", headers.Get("X-Forwarded-Uri"))
		}
		if headers.Get("X-Forwarded-Method") != http.MethodGet {
			t.Fatalf("sanitized X-Forwarded-Method = %q", headers.Get("X-Forwarded-Method"))
		}
		if headers.Get("X-Forwarded-Proto") != "http" {
			t.Fatalf("sanitized X-Forwarded-Proto = %q", headers.Get("X-Forwarded-Proto"))
		}
		if strings.Contains(headers.Get("X-Forwarded-For"), "203.0.113.66") {
			t.Fatalf("spoofed X-Forwarded-For survived: %q", headers.Get("X-Forwarded-For"))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ForwardAuth request was not observed")
	}
}

func TestTraefikFileProviderTargetsVPNNetworkNamespace(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "media.example.test"
	cfg.VPNEnabled = true

	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	graph, err := reg.Resolve(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	body, err := NewIntegrationsGenerator(cfg).GenerateTraefikDynamic(graph)
	if err != nil {
		t.Fatal(err)
	}
	var dynamic TraefikDynamicConfig
	if err := yaml.Unmarshal(body, &dynamic); err != nil {
		t.Fatalf("invalid Traefik dynamic YAML: %v\n%s", err, body)
	}
	servers := dynamic.HTTP.Services["qbittorrent"].LoadBalancer.Servers
	if len(servers) != 1 || servers[0].URL != "http://gluetun:8080" {
		t.Fatalf("VPN qBittorrent backend = %#v", servers)
	}
}

func anySliceContains(values []any, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func TestLiveGeneratedAutheliaConfig(t *testing.T) {
	if os.Getenv("SDBX_LIVE_CONTAINER_TEST") != "1" {
		t.Skip("set SDBX_LIVE_CONTAINER_TEST=1 to validate with the local Authelia image")
	}

	outputDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Domain = "media.example.test"
	cfg.Expose.Mode = config.ExposeModeLAN
	cfg.Routing.Strategy = config.RoutingStrategyPath
	cfg.Routing.BaseDomain = "box"
	cfg.AdminUser = "admin"
	cfg.AdminPasswordHash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$O8V0VQ2YskjN+L1JmKAg3hpqoSUgNjoWW9AnWQcm5H0"

	gen := newTestGenerator(t, cfg, outputDir)
	if err := gen.Generate(); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(
		"docker",
		"run",
		"--rm",
		"--read-only",
		"--cap-drop",
		"ALL",
		"--tmpfs",
		"/tmp:rw,noexec,nosuid,nodev,size=32m",
		"--volume",
		filepath.Join(outputDir, "configs", "authelia")+":/config:ro",
		"--volume",
		filepath.Join(outputDir, "data", "authelia")+":/data",
		"--volume",
		filepath.Join(outputDir, "secrets")+":/run/secrets:ro",
		"--env",
		"AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE=/run/secrets/authelia_jwt_secret.txt",
		"--env",
		"AUTHELIA_SESSION_SECRET_FILE=/run/secrets/authelia_session_secret.txt",
		"--env",
		"AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE=/run/secrets/authelia_storage_encryption_key.txt",
		"authelia/authelia:latest",
		"authelia",
		"config",
		"validate",
		"--config",
		"/config/configuration.yml",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Authelia rejected generated configuration: %v\n%s", err, output)
	}
}

func TestLiveGeneratedTraefikV3Config(t *testing.T) {
	if os.Getenv("SDBX_LIVE_CONTAINER_TEST") != "1" {
		t.Skip("set SDBX_LIVE_CONTAINER_TEST=1 to validate with the local Traefik image")
	}

	outputDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Domain = "media.example.test"
	cfg.Expose.Mode = config.ExposeModeLAN
	cfg.Routing.Strategy = config.RoutingStrategyPath
	cfg.Routing.BaseDomain = "box"
	cfg.AdminUser = "admin"
	cfg.AdminPasswordHash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$O8V0VQ2YskjN+L1JmKAg3hpqoSUgNjoWW9AnWQcm5H0"

	gen := newTestGenerator(t, cfg, outputDir)
	if err := gen.Generate(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cidFile := filepath.Join(t.TempDir(), "container.cid")
	t.Cleanup(func() {
		containerID, readErr := os.ReadFile(cidFile)
		if readErr != nil {
			return
		}
		_ = exec.Command(
			"docker",
			"rm",
			"--force",
			strings.TrimSpace(string(containerID)),
		).Run()
	})
	command := exec.CommandContext(
		ctx,
		"docker",
		"run",
		"--rm",
		"--read-only",
		"--cap-drop",
		"ALL",
		"--tmpfs",
		"/tmp:rw,noexec,nosuid,nodev,size=16m",
		"--cidfile",
		cidFile,
		"--volume",
		filepath.Join(outputDir, "configs", "traefik", "traefik.yml")+
			":/etc/traefik/traefik.yml:ro",
		"--volume",
		filepath.Join(outputDir, "configs", "traefik", "dynamic")+
			":/etc/traefik/dynamic:ro",
		"traefik:v3.7.10",
		"--configFile=/etc/traefik/traefik.yml",
	)
	output, err := command.CombinedOutput()
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("Traefik exited instead of serving generated configuration: %v\n%s", err, output)
	}
}

func TestLiveGeneratedRoutingMatrix(t *testing.T) {
	if os.Getenv("SDBX_LIVE_CONTAINER_TEST") != "1" {
		t.Skip("set SDBX_LIVE_CONTAINER_TEST=1 to validate the routing matrix")
	}

	for _, mode := range []string{
		config.ExposeModeLAN,
		config.ExposeModeDirect,
		config.ExposeModeCloudflared,
	} {
		for _, strategy := range []string{
			config.RoutingStrategySubdomain,
			config.RoutingStrategyPath,
		} {
			t.Run(mode+"/"+strategy, func(t *testing.T) {
				outputDir := t.TempDir()
				cfg := config.DefaultConfig()
				cfg.Domain = "media.example.test"
				cfg.Expose.Mode = mode
				if mode == config.ExposeModeDirect {
					cfg.Expose.TLS.Provider = "acme"
				}
				cfg.Expose.TLS.Email = "ops@example.test"
				cfg.Routing.Strategy = strategy
				cfg.Routing.BaseDomain = "box"
				cfg.AdminUser = "admin"
				cfg.AdminPasswordHash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$O8V0VQ2YskjN+L1JmKAg3hpqoSUgNjoWW9AnWQcm5H0"
				cfg.PlexEnabled = true
				cfg.JellyfinEnabled = true
				cfg.Addons = []string{
					"filebrowser",
					"nzbhydra2",
					"prowlarr",
					"sonarr",
				}
				cfg.VPNEnabled = true
				cfg.VPNProvider = "mullvad"

				gen := newTestGenerator(t, cfg, outputDir)
				if err := gen.Generate(); err != nil {
					t.Fatal(err)
				}

				command := exec.Command(
					"docker",
					"compose",
					"--project-directory",
					outputDir,
					"--file",
					filepath.Join(outputDir, "compose.yaml"),
					"config",
					"--quiet",
				)
				output, err := command.CombinedOutput()
				if err != nil {
					t.Fatalf("Docker Compose rejected generated profile: %v\n%s", err, output)
				}
			})
		}
	}
}
