package integrate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
	"gopkg.in/yaml.v3"
)

const (
	testDecluttarrArrKey   = "11111111111111111111111111111111"
	testDecluttarrPassword = "synthetic-qbt-password"
)

func TestReconcileDecluttarrConfigPreservesPolicyAndIsIdempotent(t *testing.T) {
	cfg := seedDecluttarrProject(t)
	path := decluttarrConfigPath(cfg)
	original := decluttarrManagedMarker + `general:
  test_run: false
  timer: 42
jobs:
  remove_stalled:
    max_strikes: 7
instances:
  sonarr:
    - base_url: http://legacy-sonarr:8989
      api_key: legacy-key
      timeout: 30
download_clients:
  qbittorrent:
    # The sdbx_proxy subnet is whitelisted in qBT, so no credentials needed.
    - base_url: http://legacy-qbt:8080
      username: legacy
      password: legacy
      name: primary
`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	graph := testManagedArrGraph("sonarr")
	result, err := ReconcileDecluttarrConfig(cfg, graph, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "updated" {
		t.Fatalf("action = %q", result.Action)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(body, []byte(decluttarrManagedMarker)) {
		t.Fatal("managed marker was not preserved")
	}
	var document map[string]any
	if err := yaml.Unmarshal(
		bytes.TrimPrefix(body, []byte(decluttarrManagedMarker)),
		&document,
	); err != nil {
		t.Fatal(err)
	}
	general := document["general"].(map[string]any)
	if general["test_run"] != true || general["timer"] != 42 {
		t.Fatalf("general policy = %#v", general)
	}
	jobs := document["jobs"].(map[string]any)
	if jobs["remove_stalled"] == nil {
		t.Fatalf("jobs policy was not preserved: %#v", jobs)
	}
	sonarr := document["instances"].(map[string]any)["sonarr"].([]any)[0].(map[string]any)
	if sonarr["base_url"] != "http://sdbx-sonarr:8989/sonarr" ||
		sonarr["api_key"] != testDecluttarrArrKey ||
		sonarr["timeout"] != 30 {
		t.Fatalf("Sonarr instance = %#v", sonarr)
	}
	qbittorrent := document["download_clients"].(map[string]any)["qbittorrent"].([]any)[0].(map[string]any)
	if qbittorrent["base_url"] != "http://sdbx-gluetun:8080" ||
		qbittorrent["username"] != "admin" ||
		qbittorrent["password"] != testDecluttarrPassword ||
		qbittorrent["name"] != "primary" {
		t.Fatalf("qBittorrent instance = %#v", qbittorrent)
	}
	if strings.Contains(string(body), "whitelisted in qBT") ||
		strings.Contains(string(body), "no credentials needed") ||
		!strings.Contains(
			string(body),
			"SDBX-managed authentication is required",
		) {
		t.Fatalf("qBittorrent managed comment is stale:\n%s", body)
	}
	for _, nonSecret := range []string{result.Action, result.Reason} {
		if strings.Contains(nonSecret, testDecluttarrPassword) ||
			strings.Contains(nonSecret, testDecluttarrArrKey) {
			t.Fatal("integration result exposed a credential")
		}
	}

	first := append([]byte(nil), body...)
	result, err = ReconcileDecluttarrConfig(cfg, graph, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "kept" {
		t.Fatalf("second action = %q", result.Action)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("idempotent reconciliation changed the managed file")
	}
}

func TestReconcileDecluttarrConfigHonorsRemovedMarker(t *testing.T) {
	cfg := seedDecluttarrProject(t)
	path := decluttarrConfigPath(cfg)
	operatorOwned := []byte("general:\n  test_run: false\n")
	if err := os.WriteFile(path, operatorOwned, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := ReconcileDecluttarrConfig(cfg, testManagedArrGraph("sonarr"), false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "skipped" {
		t.Fatalf("action = %q", result.Action)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(operatorOwned, after) {
		t.Fatal("operator-owned file was modified")
	}
}

func TestReconcileDecluttarrConfigCreatesSafeTestRunConfig(t *testing.T) {
	cfg := seedDecluttarrProject(t)
	path := decluttarrConfigPath(cfg)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	result, err := ReconcileDecluttarrConfig(cfg, testManagedArrGraph("sonarr"), false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "created" {
		t.Fatalf("action = %q", result.Action)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "test_run: true") {
		t.Fatal("created config is not fail-safe")
	}
	if strings.Contains(string(body), "jobs:") {
		t.Fatal("created config enabled cleanup jobs implicitly")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}

func TestReconcileDecluttarrConfigDryRunDoesNotWrite(t *testing.T) {
	cfg := seedDecluttarrProject(t)
	path := decluttarrConfigPath(cfg)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	result, err := ReconcileDecluttarrConfig(cfg, testManagedArrGraph("sonarr"), true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "would_created" {
		t.Fatalf("action = %q", result.Action)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("dry run wrote managed config: %v", err)
	}
}

func TestReconcileDecluttarrConfigRejectsSymlink(t *testing.T) {
	cfg := seedDecluttarrProject(t)
	path := decluttarrConfigPath(cfg)
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(
		outside,
		[]byte(decluttarrManagedMarker+"general: {}\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := ReconcileDecluttarrConfig(cfg, testManagedArrGraph("sonarr"), false); err == nil {
		t.Fatal("symlinked managed config was accepted")
	}
}

func seedDecluttarrProject(t *testing.T) *config.Config {
	t.Helper()
	root := t.TempDir()
	configRoot := filepath.Join(root, "configs")
	secretsRoot := filepath.Join(root, "secrets")
	for _, directory := range []string{
		configRoot,
		filepath.Join(configRoot, "decluttarr"),
		filepath.Join(configRoot, "sonarr"),
		secretsRoot,
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(configRoot, "sonarr", "config.xml"),
		[]byte("<Config><ApiKey>"+testDecluttarrArrKey+"</ApiKey></Config>"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(secretsRoot, "qbittorrent_password.txt"),
		[]byte(testDecluttarrPassword+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	return &config.Config{
		ConfigPath:  configRoot,
		SecretsPath: secretsRoot,
		PUID:        os.Getuid(),
		PGID:        os.Getgid(),
		VPNEnabled:  true,
		ActiveServices: map[string]bool{
			"decluttarr":  true,
			"qbittorrent": true,
			"sonarr":      true,
		},
		Routing: config.RoutingConfig{Strategy: config.RoutingStrategyPath},
	}
}

func testManagedArrGraph(names ...string) *registry.ResolutionGraph {
	graph := &registry.ResolutionGraph{
		Services: make(map[string]*registry.ResolvedService, len(names)),
	}
	for _, name := range names {
		graph.Services[name] = &registry.ResolvedService{
			Name:    name,
			Enabled: true,
			FinalDefinition: &registry.ServiceDefinition{
				Metadata: registry.ServiceMetadata{Name: name},
				Routing: registry.RoutingConfig{
					Enabled: true,
					Path:    "/" + name,
					PathRouting: registry.PathRoutingConfig{
						URLBaseEnvVar: strings.ToUpper(name) + "__SERVER__URLBASE",
					},
				},
			},
		}
	}
	return graph
}
