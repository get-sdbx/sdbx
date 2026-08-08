package addons

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

func TestManagerEnableRegeneratesRuntimeFiles(t *testing.T) {
	projectDir := t.TempDir()
	manager := testManager(t, projectDir, config.DefaultConfig())

	result, err := manager.Enable(context.Background(), "sonarr")
	if err != nil {
		t.Fatalf("Enable failed: %v", err)
	}
	if !result.Changed || !result.Regenerated {
		t.Fatalf("result = %#v, want changed and regenerated", result)
	}

	compose := readFile(t, filepath.Join(projectDir, "compose.yaml"))
	if !strings.Contains(compose, "sdbx-sonarr") {
		t.Fatalf("compose.yaml did not include enabled addon:\n%s", compose)
	}
	sdbxConfig := readFile(t, filepath.Join(projectDir, ".sdbx.yaml"))
	if !strings.Contains(sdbxConfig, "- sonarr") {
		t.Fatalf(".sdbx.yaml did not include enabled addon:\n%s", sdbxConfig)
	}
}

func TestManagerDisableRegeneratesRuntimeFiles(t *testing.T) {
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Addons = []string{"sonarr"}
	if err := os.WriteFile(filepath.Join(projectDir, "compose.yaml"), []byte("services:\n  sonarr:\n    container_name: sdbx-sonarr\n"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	manager := testManager(t, projectDir, cfg)

	result, err := manager.Disable(context.Background(), "sonarr")
	if err != nil {
		t.Fatalf("Disable failed: %v", err)
	}
	if !result.Changed || !result.Regenerated {
		t.Fatalf("result = %#v, want changed and regenerated", result)
	}

	compose := readFile(t, filepath.Join(projectDir, "compose.yaml"))
	if strings.Contains(compose, "sdbx-sonarr") {
		t.Fatalf("compose.yaml still included disabled addon:\n%s", compose)
	}
	sdbxConfig := readFile(t, filepath.Join(projectDir, ".sdbx.yaml"))
	if strings.Contains(sdbxConfig, "- sonarr") {
		t.Fatalf(".sdbx.yaml still included disabled addon:\n%s", sdbxConfig)
	}
}

func TestManagerPreservesUserDatabaseAndRefreshesManagedPolicyAndEnv(t *testing.T) {
	projectDir := t.TempDir()
	userDatabase := filepath.Join(projectDir, "configs", "authelia", "users_database.yml")
	if err := os.MkdirAll(filepath.Dir(userDatabase), 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(userDatabase, []byte("custom users database"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	envPath := filepath.Join(projectDir, ".env")
	if err := os.WriteFile(envPath, []byte("PLEX_CLAIM=claim-token\nTUNNEL_TOKEN=tunnel-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	manager := testManager(t, projectDir, config.DefaultConfig())

	if _, err := manager.Enable(context.Background(), "sonarr"); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	if got := readFile(t, userDatabase); got != "custom users database" {
		t.Fatalf("user database was overwritten: %q", got)
	}
	env := readFile(t, envPath)
	if strings.Contains(env, "claim-token") || strings.Contains(env, "tunnel-token") {
		t.Fatalf("legacy secret-bearing .env content survived: %q", env)
	}
	if !strings.Contains(env, "SDBX_DOMAIN=sdbx.example.com") {
		t.Fatalf("managed .env was not refreshed: %q", env)
	}
	policy := readFile(
		t,
		filepath.Join(projectDir, "configs", "authelia", "configuration.yml"),
	)
	if !strings.Contains(policy, "sonarr.sdbx.example.com") ||
		!strings.Contains(policy, "default_policy: deny") {
		t.Fatalf("managed Authelia policy was not refreshed:\n%s", policy)
	}
}

func TestManagerRestoresConfigWhenRegenerationFails(t *testing.T) {
	projectFile := filepath.Join(t.TempDir(), "project-file")
	if err := os.WriteFile(projectFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	cfg := config.DefaultConfig()
	manager := testManager(t, projectFile, cfg)

	_, err := manager.Enable(context.Background(), "sonarr")
	if err == nil {
		t.Fatal("Enable succeeded with invalid project directory")
	}
	if cfg.IsAddonEnabled("sonarr") {
		t.Fatal("addon remained enabled after regeneration failure")
	}
}

func TestManagerNoopsWhenStateAlreadyMatches(t *testing.T) {
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Addons = []string{"sonarr"}
	manager := testManager(t, projectDir, cfg)

	result, err := manager.Enable(context.Background(), "sonarr")
	if err != nil {
		t.Fatalf("Enable failed: %v", err)
	}
	if result.Changed || result.Regenerated {
		t.Fatalf("result = %#v, want no change and no regeneration", result)
	}
	if _, err := os.Stat(filepath.Join(projectDir, "compose.yaml")); !os.IsNotExist(err) {
		t.Fatalf("compose.yaml should not be generated for noop, stat err=%v", err)
	}
}

func testManager(t *testing.T, projectDir string, cfg *config.Config) *Manager {
	t.Helper()
	reg, err := registry.New(&registry.SourceConfig{
		APIVersion: registry.APIVersion,
		Kind:       registry.KindSourceConfig,
		Cache: registry.CacheConfig{
			Directory: filepath.Join(t.TempDir(), "cache"),
		},
	})
	if err != nil {
		t.Fatalf("registry.New failed: %v", err)
	}
	return &Manager{
		ProjectDir: projectDir,
		Config:     cfg,
		Registry:   reg,
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) failed: %v", path, err)
	}
	return string(data)
}
