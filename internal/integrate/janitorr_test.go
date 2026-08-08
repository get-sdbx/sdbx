package integrate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"gopkg.in/yaml.v3"
)

func TestReconcileJanitorrConfigRefreshesManagedArrClients(t *testing.T) {
	cfg := seedJanitorrProject(t)
	path := janitorrConfigPath(cfg)
	managedMarker := "# managed-by: sdbx-generate\n"
	original := managedMarker + `application:
  dry-run: true
  run-once: false
clients:
  sonarr:
    enabled: true
    url: http://legacy-sonarr:8989
    api-key: legacy-key
    delete-empty-shows: false
`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	graph := testManagedArrGraph("sonarr")
	result, err := ReconcileJanitorrConfig(cfg, graph, false)
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
	if !bytes.HasPrefix(body, []byte(managedMarker)) {
		t.Fatal("managed marker was not preserved")
	}
	var document map[string]any
	if err := yaml.Unmarshal(
		bytes.TrimPrefix(body, []byte(managedMarker)),
		&document,
	); err != nil {
		t.Fatal(err)
	}
	application := document["application"].(map[string]any)
	if application["dry-run"] != true || application["run-once"] != false {
		t.Fatalf("application policy changed: %#v", application)
	}
	sonarr := document["clients"].(map[string]any)["sonarr"].(map[string]any)
	if sonarr["url"] != "http://sdbx-sonarr:8989/sonarr" ||
		sonarr["api-key"] != testDecluttarrArrKey ||
		sonarr["enabled"] != true ||
		sonarr["delete-empty-shows"] != false {
		t.Fatalf("Sonarr client = %#v", sonarr)
	}

	first := append([]byte(nil), body...)
	result, err = ReconcileJanitorrConfig(cfg, graph, false)
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

func TestReconcileJanitorrConfigHonorsRemovedMarker(t *testing.T) {
	cfg := seedJanitorrProject(t)
	path := janitorrConfigPath(cfg)
	operatorOwned := []byte("application:\n  dry-run: false\n")
	if err := os.WriteFile(path, operatorOwned, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := ReconcileJanitorrConfig(cfg, testManagedArrGraph("sonarr"), false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "skipped" || !strings.Contains(result.Reason, "marker") {
		t.Fatalf("result = %#v", result)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(operatorOwned, after) {
		t.Fatal("operator-owned file was modified")
	}
}

func TestReconcileJanitorrConfigRejectsUnknownManagedMarker(t *testing.T) {
	cfg := seedJanitorrProject(t)
	path := janitorrConfigPath(cfg)
	operatorOwned := []byte("# managed-by: sdbx-other\napplication:\n  dry-run: false\n")
	if err := os.WriteFile(path, operatorOwned, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := ReconcileJanitorrConfig(cfg, testManagedArrGraph("sonarr"), false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "skipped" {
		t.Fatalf("result = %#v", result)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(operatorOwned, after) {
		t.Fatal("unknown managed marker was accepted")
	}
}

func seedJanitorrProject(t *testing.T) *config.Config {
	t.Helper()
	root := t.TempDir()
	configRoot := filepath.Join(root, "configs")
	for _, directory := range []string{
		filepath.Join(configRoot, "janitorr"),
		filepath.Join(configRoot, "sonarr"),
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
	return &config.Config{
		ConfigPath: configRoot,
		PUID:       os.Getuid(),
		PGID:       os.Getgid(),
		ActiveServices: map[string]bool{
			"janitorr": true,
			"sonarr":   true,
		},
		Routing: config.RoutingConfig{Strategy: config.RoutingStrategyPath},
	}
}
