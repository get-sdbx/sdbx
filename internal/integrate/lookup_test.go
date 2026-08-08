package integrate

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

func TestQBittorrentDockerURLTracksVPNNamespace(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.VPNEnabled = false
	if got := QBittorrentDockerURL(cfg); got != "http://sdbx-qbittorrent:8080" {
		t.Fatalf("non-VPN URL = %q", got)
	}
	cfg.VPNEnabled = true
	if got := QBittorrentDockerURL(cfg); got != "http://sdbx-gluetun:8080" {
		t.Fatalf("VPN URL = %q", got)
	}
}

func TestArrConfigReadersRejectSymlinksAndOversizedFiles(t *testing.T) {
	root := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ConfigPath = root
	configPath := arrConfigXMLPath(cfg, "sonarr")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}

	oversized := make([]byte, maxManagedConfigSize+1)
	if err := os.WriteFile(configPath, oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadArrAPIKey(cfg, "sonarr"); err == nil {
		t.Fatal("ReadArrAPIKey accepted oversized config.xml")
	}
	if _, err := ReadArrUrlBase(cfg, "sonarr"); err == nil {
		t.Fatal("ReadArrUrlBase accepted oversized config.xml")
	}

	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(root, "victim.xml")
	if err := os.WriteFile(victim, []byte("<Config><ApiKey>victim</ApiKey></Config>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, configPath); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadArrAPIKey(cfg, "sonarr"); err == nil {
		t.Fatal("ReadArrAPIKey followed a symlink")
	}
}

func TestArrConfigReadersParseNormalConfiguration(t *testing.T) {
	root := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ConfigPath = root
	configPath := arrConfigXMLPath(cfg, "sonarr")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		configPath,
		[]byte("<Config><ApiKey> synthetic-api-key </ApiKey><UrlBase>sonarr///</UrlBase></Config>"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	apiKey, err := ReadArrAPIKey(cfg, "sonarr")
	if err != nil {
		t.Fatalf("ReadArrAPIKey failed: %v", err)
	}
	if apiKey != "synthetic-api-key" {
		t.Fatalf("API key = %q", apiKey)
	}
	urlBase, err := ReadArrUrlBase(cfg, "sonarr")
	if err != nil {
		t.Fatalf("ReadArrUrlBase failed: %v", err)
	}
	if urlBase != "/sonarr" {
		t.Fatalf("URL base = %q, want /sonarr", urlBase)
	}
}

func TestArrConfigReadersTreatMissingConfigurationAsNotProvisioned(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigPath = t.TempDir()
	apiKey, err := ReadArrAPIKey(cfg, "sonarr")
	if err != nil || apiKey != "" {
		t.Fatalf("missing API key = %q, err = %v", apiKey, err)
	}
	urlBase, err := ReadArrUrlBase(cfg, "sonarr")
	if err != nil || urlBase != "" {
		t.Fatalf("missing URL base = %q, err = %v", urlBase, err)
	}
}

func TestIsServiceEnabledRequiresVerifiedActiveGraph(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.PlexEnabled = true
	cfg.VPNEnabled = true
	cfg.Addons = []string{"sonarr"}
	for _, name := range []string{"plex", "gluetun", "sonarr", "qbittorrent"} {
		if IsServiceEnabled(cfg, name) {
			t.Fatalf("%s was inferred without a verified graph", name)
		}
	}
	cfg.ActiveServices = map[string]bool{
		"qbittorrent": true,
		"sonarr":      true,
	}
	if !IsServiceEnabled(cfg, "qbittorrent") || !IsServiceEnabled(cfg, "sonarr") {
		t.Fatalf("active services were not recognized: %v", cfg.ActiveServices)
	}
	if IsServiceEnabled(cfg, "plex") || IsServiceEnabled(cfg, "gluetun") {
		t.Fatalf("inactive conditional services were inferred: %v", cfg.ActiveServices)
	}
}

func TestEnabledArrsUsesDeterministicVerifiedGraphOrder(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ActiveServices = map[string]bool{
		"bazarr":      true,
		"prowlarr":    true,
		"sonarr":      true,
		"filebrowser": true,
	}
	actual := EnabledArrs(cfg)
	expected := []string{"prowlarr", "sonarr"}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("enabled arrs = %v, want %v", actual, expected)
	}
}

func TestLoadServicesFromConfigUsesOnlyVerifiedGraphServices(t *testing.T) {
	root := t.TempDir()
	configRoot := filepath.Join(root, "configs")
	secretsRoot := filepath.Join(root, "secrets")
	for _, name := range []string{"sonarr", "radarr"} {
		path := filepath.Join(configRoot, name, "config.xml")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			path,
			[]byte("<Config><ApiKey>"+name+"-key</ApiKey></Config>"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(secretsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(secretsRoot, "qbittorrent_password.txt"),
		[]byte("qbt-password"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.ConfigPath = configRoot
	cfg.SecretsPath = secretsRoot
	cfg.Addons = []string{"sonarr", "radarr"}
	cfg.ActiveServices = map[string]bool{
		"sonarr":      true,
		"qbittorrent": true,
	}
	services, err := LoadServicesFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := services["sonarr"]; !ok {
		t.Fatalf("active Sonarr omitted: %v", services)
	}
	if _, ok := services["qbittorrent"]; !ok {
		t.Fatalf("active qBittorrent omitted: %v", services)
	}
	if _, ok := services["radarr"]; ok {
		t.Fatalf("inactive Radarr was loaded: %v", services)
	}
}

func TestLoadServicesFromGraphUsesCanonicalPathRouting(t *testing.T) {
	root := t.TempDir()
	configRoot := filepath.Join(root, "configs")
	path := filepath.Join(configRoot, "sonarr", "config.xml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		path,
		[]byte("<Config><ApiKey>synthetic-key</ApiKey></Config>"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.ConfigPath = configRoot
	cfg.Routing.Strategy = config.RoutingStrategyPath
	cfg.Services = map[string]config.ServiceOverride{
		"sonarr": {Path: "/shows"},
	}
	cfg.ActiveServices = map[string]bool{"sonarr": true}
	definition := &registry.ServiceDefinition{
		Metadata: registry.ServiceMetadata{Name: "sonarr"},
		Routing: registry.RoutingConfig{
			Enabled: true,
			Path:    "/sonarr",
			PathRouting: registry.PathRoutingConfig{
				URLBaseEnvVar: "SONARR__SERVER__URLBASE",
			},
		},
	}
	graph := &registry.ResolutionGraph{
		Services: map[string]*registry.ResolvedService{
			"sonarr": {
				Name:            "sonarr",
				Enabled:         true,
				FinalDefinition: definition,
			},
		},
	}
	services, err := LoadServicesFromGraph(cfg, graph)
	if err != nil {
		t.Fatal(err)
	}
	if got := services["sonarr"].URL; got != "http://sdbx-sonarr:8989/shows" {
		t.Fatalf("Sonarr integration URL = %q", got)
	}
}
