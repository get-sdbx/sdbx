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

func TestReconcileRecyclarrConfigAdoptsStarterAndPreservesPolicy(t *testing.T) {
	cfg := seedManagedAddonProject(t)
	path := filepath.Join(cfg.ConfigPath, filepath.FromSlash(recyclarrConfigName))
	starter := `# An empty starter config to use with Recyclarr.
# This file WILL NOT WORK until configured.
sonarr:
  series:
    base_url: http://localhost:8989
    api_key: replace-me
    custom_formats:
      - trash_ids:
          - synthetic-format
`
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(starter), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := ReconcileRecyclarrConfig(
		cfg,
		testManagedArrGraph("sonarr", "radarr"),
		false,
	)
	if err != nil || result.Action != "updated" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(body, []byte(addonManagedMarker)) {
		t.Fatal("starter was not adopted as managed config")
	}
	if !bytes.Contains(body, []byte("synthetic-format")) ||
		!bytes.Contains(body, []byte("http://sdbx-sonarr:8989/sonarr")) ||
		!bytes.Contains(body, []byte("http://sdbx-radarr:7878/radarr")) {
		t.Fatalf("managed config did not preserve policy and URLs:\n%s", body)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info.Mode().Perm(), err)
	}
	result, err = ReconcileRecyclarrConfig(
		cfg,
		testManagedArrGraph("sonarr", "radarr"),
		false,
	)
	if err != nil || result.Action != "kept" {
		t.Fatalf("second result=%#v err=%v", result, err)
	}
}

func TestReconcileRecyclarrConfigPreservesUnmarkedOperatorFile(t *testing.T) {
	cfg := seedManagedAddonProject(t)
	path := filepath.Join(cfg.ConfigPath, filepath.FromSlash(recyclarrConfigName))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("sonarr:\n  custom:\n    base_url: http://operator.example.test\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := ReconcileRecyclarrConfig(
		cfg,
		testManagedArrGraph("sonarr", "radarr"),
		false,
	)
	if err != nil || result.Action != "skipped" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(original, after) {
		t.Fatal("operator-owned Recyclarr config was modified")
	}
}

func TestReconcileQbitManageConfigAdoptsEmptyStarterFailSafe(t *testing.T) {
	cfg := seedManagedAddonProject(t)
	path := filepath.Join(cfg.ConfigPath, filepath.FromSlash(qbitManageConfigName))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		path,
		[]byte("settings:\n  force_auto_tmm: false\nwebhooks: {}\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	result, err := ReconcileQbitManageConfig(cfg, false)
	if err != nil || result.Action != "updated" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(bytes.TrimPrefix(body, []byte(addonManagedMarker)), &document); err != nil {
		t.Fatal(err)
	}
	commands := document["commands"].(map[string]any)
	for name, value := range commands {
		if name == "dry_run" {
			if value != true {
				t.Fatalf("dry_run=%#v", value)
			}
		} else if value != false {
			t.Fatalf("destructive command %s=%#v", name, value)
		}
	}
	qbt := document["qbt"].(map[string]any)
	if qbt["host"] != "http://sdbx-gluetun:8080" ||
		qbt["user"] != "admin" || qbt["pass"] != testDecluttarrPassword {
		t.Fatalf("qBT connection is incomplete: %#v", qbt)
	}
	directory := document["directory"].(map[string]any)
	if directory["root_dir"] != "/downloads" {
		t.Fatal("qbit-manage download path differs from qBittorrent")
	}
	if directory["remote_dir"] != "/data/downloads" {
		t.Fatal("qbit-manage local download mount is not mapped")
	}
	if directory["recycle_bin"] != "/data/downloads/.RecycleBin" ||
		directory["torrents_dir"] != nil {
		t.Fatalf("qbit-manage startup defaults are not stable: %#v", directory)
	}
	for _, path := range []string{
		"/downloads/tv", "/downloads/movies", "/downloads/music", "/downloads/other",
	} {
		if !strings.Contains(string(body), path) {
			t.Fatalf("managed category path %q is absent", path)
		}
	}
	result, err = ReconcileQbitManageConfig(cfg, false)
	if err != nil || result.Action != "kept" {
		t.Fatalf("second result=%#v err=%v", result, err)
	}
}

func seedManagedAddonProject(t *testing.T) *config.Config {
	t.Helper()
	root := t.TempDir()
	configRoot := filepath.Join(root, "configs")
	secretsRoot := filepath.Join(root, "secrets")
	for _, directory := range []string{
		filepath.Join(configRoot, "sonarr"),
		filepath.Join(configRoot, "radarr"),
		secretsRoot,
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"sonarr", "radarr"} {
		if err := os.WriteFile(
			filepath.Join(configRoot, name, "config.xml"),
			[]byte("<Config><ApiKey>"+testDecluttarrArrKey+"</ApiKey></Config>"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
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
		Routing:     config.RoutingConfig{Strategy: config.RoutingStrategyPath},
		ActiveServices: map[string]bool{
			"sonarr":      true,
			"radarr":      true,
			"recyclarr":   true,
			"qbit-manage": true,
			"qbittorrent": true,
		},
	}
}
