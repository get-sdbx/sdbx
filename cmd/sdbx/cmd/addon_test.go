package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
	"github.com/spf13/viper"
)

func TestAddonList(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.EnableAddon("filebrowser")
	cfg.EnableAddon("prowlarr")
	setupAddonCommandProject(t, cfg)
	output := captureAddonOutput(t, func() error {
		return runAddonList(addonListCmd, nil)
	})

	// Verify output contains addon names
	if !strings.Contains(output, "filebrowser") {
		t.Error("Output should contain 'filebrowser'")
	}
	if !strings.Contains(output, "prowlarr") {
		t.Error("Output should contain 'prowlarr'")
	}
	if !strings.Contains(output, "enabled") {
		t.Error("Output should contain 'enabled'")
	}
}

func TestAddonListJSON(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.EnableAddon("prowlarr")
	setupAddonCommandProject(t, cfg)
	jsonOut = true
	output := captureAddonOutput(t, func() error {
		return runAddonList(addonListCmd, nil)
	})

	// Parse JSON output
	var result []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("Failed to parse JSON output: %v\nOutput: %s", err, output)
	}

	// Verify JSON structure - without --all flag, only enabled addons are shown
	// In this test, only Prowlarr is enabled.
	if len(result) != 1 {
		t.Errorf("JSON result length = %d, want 1 (only enabled addons)", len(result))
	}

	// Find Prowlarr in results.
	foundProwlarr := false
	for _, addon := range result {
		if addon["name"] == "prowlarr" {
			foundProwlarr = true
			if addon["enabled"] != true {
				t.Error("prowlarr should be enabled in JSON output")
			}
		}
	}
	if !foundProwlarr {
		t.Error("prowlarr not found in JSON output")
	}
}

func TestAddonSearchReturnsMatchingAddon(t *testing.T) {
	setupAddonCommandProject(t, config.DefaultConfig())
	output := captureAddonOutput(t, func() error {
		return runAddonSearch(addonSearchCmd, []string{"sonarr"})
	})

	for _, expected := range []string{"Search Results for 'sonarr'", "sonarr", "TV Shows automation"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("search output missing %q:\n%s", expected, output)
		}
	}
}

func TestAddonSearchExcludesCoreServices(t *testing.T) {
	setupAddonCommandProject(t, config.DefaultConfig())
	output := captureAddonOutput(t, func() error {
		return runAddonSearch(addonSearchCmd, []string{"traefik"})
	})

	if !strings.Contains(output, "No addons found") {
		t.Fatalf("core-only search did not return the empty-addon state:\n%s", output)
	}
}

func TestAddonSearchJSONHonorsCategory(t *testing.T) {
	setupAddonCommandProject(t, config.DefaultConfig())
	jsonOut = true
	addonCategory = "media"
	output := captureAddonOutput(t, func() error {
		return runAddonSearch(addonSearchCmd, nil)
	})

	var result []registry.ServiceInfo
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("parse JSON output: %v\nOutput: %s", err, output)
	}
	if len(result) == 0 {
		t.Fatal("media addon search returned no results")
	}
	for _, addon := range result {
		if !addon.IsAddon || addon.Category != registry.CategoryMedia {
			t.Fatalf("category-filtered search returned %+v", addon)
		}
	}
}

func TestAddonHumanOutputEscapesUntrustedCatalogMetadata(t *testing.T) {
	setupAddonCommandProject(t, config.DefaultConfig())
	installTerminalControlAddonSource(t)
	addonListAll = true

	listOutput := captureAddonOutput(t, func() error {
		return runAddonList(addonListCmd, nil)
	})
	searchOutput := captureAddonOutput(t, func() error {
		return runAddonSearch(addonSearchCmd, []string{"terminal-test"})
	})
	infoOutput := captureAddonOutput(t, func() error {
		return runAddonInfo(addonInfoCmd, []string{"terminal-test"})
	})
	output := listOutput + searchOutput + infoOutput

	for _, unsafe := range []string{"\x1b[2J", "\x1b[31m", "\x1b]8;;", "\u202E"} {
		if strings.Contains(output, unsafe) {
			t.Fatalf("human addon output contains unsafe metadata %q:\n%s", unsafe, output)
		}
	}
	for _, escaped := range []string{`\x1B[2J`, `\x1B[31m`, `\x1B]8;;`, `\n`, `\r`, `\u202E`} {
		if !strings.Contains(output, escaped) {
			t.Fatalf("human addon output is missing escaped metadata %q:\n%s", escaped, output)
		}
	}
}

func TestAddonJSONPreservesStructuredUntrustedCatalogMetadata(t *testing.T) {
	setupAddonCommandProject(t, config.DefaultConfig())
	installTerminalControlAddonSource(t)
	jsonOut = true

	output := captureAddonOutput(t, func() error {
		return runAddonSearch(addonSearchCmd, []string{"terminal-test"})
	})
	var result []registry.ServiceInfo
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("parse JSON output: %v\n%s", err, output)
	}
	if len(result) != 1 {
		t.Fatalf("JSON result count = %d, want 1", len(result))
	}
	description := result[0].Description
	for _, preserved := range []string{"\x1b[2J", "\n", "\r", "\u202E"} {
		if !strings.Contains(description, preserved) {
			t.Fatalf("structured description did not preserve %q: %q", preserved, description)
		}
	}
}

func TestAddonInfoJSONReportsEnabledLockedAddon(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.EnableAddon("sonarr")
	setupAddonCommandProject(t, cfg)
	jsonOut = true
	output := captureAddonOutput(t, func() error {
		return runAddonInfo(addonInfoCmd, []string{"sonarr"})
	})

	var result struct {
		Name     string `json:"name"`
		Source   string `json:"source"`
		Image    string `json:"image"`
		Category string `json:"category"`
		Port     int    `json:"port"`
		Enabled  bool   `json:"enabled"`
	}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("parse JSON output: %v\nOutput: %s", err, output)
	}
	if result.Name != "sonarr" ||
		result.Source != "embedded" ||
		result.Image != "linuxserver/sonarr:latest" ||
		result.Category != "media" ||
		result.Port != 8989 ||
		!result.Enabled {
		t.Fatalf("addon info = %+v", result)
	}
}

func TestAddonInfoRejectsCoreService(t *testing.T) {
	setupAddonCommandProject(t, config.DefaultConfig())
	err := runAddonInfo(addonInfoCmd, []string{"traefik"})
	if err == nil || !strings.Contains(err.Error(), "core service, not an addon") {
		t.Fatalf("core service info error = %v", err)
	}
}

func TestAddonInfoRejectsUnknownAddon(t *testing.T) {
	setupAddonCommandProject(t, config.DefaultConfig())
	err := runAddonInfo(addonInfoCmd, []string{"does-not-exist"})
	if err == nil || !strings.Contains(err.Error(), "addon not found") {
		t.Fatalf("unknown addon info error = %v", err)
	}
}

func TestAddonEnable(t *testing.T) {
	cfg := config.DefaultConfig()
	projectDir := setupAddonCommandProject(t, cfg)
	output := captureAddonOutput(t, func() error {
		return runAddonEnable(addonEnableCmd, []string{"nzbhydra2"})
	})

	// Verify output
	if !strings.Contains(output, "Enabled") || !strings.Contains(output, "nzbhydra2") {
		t.Errorf("Output should confirm addon enabled: %s", output)
	}

	// Verify config was saved
	cfgPath := filepath.Join(projectDir, ".sdbx.yaml")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		t.Error("Config file should exist after enabling addon")
	}

	loadedCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if !loadedCfg.IsAddonEnabled("nzbhydra2") {
		t.Error("nzbhydra2 should be enabled in saved config")
	}
}

func TestAddonEnableInvalid(t *testing.T) {
	setupAddonCommandProject(t, config.DefaultConfig())

	// Try to enable invalid addon
	err := runAddonEnable(addonEnableCmd, []string{"nonexistent"})
	if err == nil {
		t.Error("runAddonEnable should fail for invalid addon")
	}
	if !strings.Contains(err.Error(), "addon not found") {
		t.Errorf("Error should mention addon not found: %v", err)
	}
}

func TestAddonEnableRegeneratesRuntimeFiles(t *testing.T) {
	projectDir := setupAddonCommandProject(t, config.DefaultConfig())

	if err := runAddonEnable(addonEnableCmd, []string{"sonarr"}); err != nil {
		t.Fatalf("runAddonEnable failed: %v", err)
	}

	compose := readCommandTestFile(t, filepath.Join(projectDir, "compose.yaml"))
	if !strings.Contains(compose, "sdbx-sonarr") {
		t.Fatalf("compose.yaml did not include enabled addon:\n%s", compose)
	}
	sdbxConfig := readCommandTestFile(t, filepath.Join(projectDir, ".sdbx.yaml"))
	if !strings.Contains(sdbxConfig, "- sonarr") {
		t.Fatalf(".sdbx.yaml did not include enabled addon:\n%s", sdbxConfig)
	}
}

func TestAddonDisableRegeneratesRuntimeFiles(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Addons = []string{"sonarr"}
	projectDir := setupAddonCommandProject(t, cfg)
	if err := os.WriteFile(filepath.Join(projectDir, "compose.yaml"), []byte("services:\n  sonarr:\n    container_name: sdbx-sonarr\n"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := runAddonDisable(addonDisableCmd, []string{"sonarr"}); err != nil {
		t.Fatalf("runAddonDisable failed: %v", err)
	}

	compose := readCommandTestFile(t, filepath.Join(projectDir, "compose.yaml"))
	if strings.Contains(compose, "sdbx-sonarr") {
		t.Fatalf("compose.yaml still included disabled addon:\n%s", compose)
	}
	sdbxConfig := readCommandTestFile(t, filepath.Join(projectDir, ".sdbx.yaml"))
	if strings.Contains(sdbxConfig, "- sonarr") {
		t.Fatalf(".sdbx.yaml still included disabled addon:\n%s", sdbxConfig)
	}
}

func TestAddonEnableAlreadyEnabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.EnableAddon("prowlarr")
	setupAddonCommandProject(t, cfg)
	output := captureAddonOutput(t, func() error {
		return runAddonEnable(addonEnableCmd, []string{"prowlarr"})
	})

	// Verify output mentions already enabled
	if !strings.Contains(output, "already enabled") {
		t.Errorf("Output should mention already enabled: %s", output)
	}
}

func TestAddonDisable(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.EnableAddon("prowlarr")
	projectDir := setupAddonCommandProject(t, cfg)
	output := captureAddonOutput(t, func() error {
		return runAddonDisable(addonDisableCmd, []string{"prowlarr"})
	})

	// Verify output
	if !strings.Contains(output, "Disabled") || !strings.Contains(output, "prowlarr") {
		t.Errorf("Output should confirm addon disabled: %s", output)
	}

	// Load config and verify addon is disabled
	loadedCfg, err := config.LoadFile(filepath.Join(projectDir, ".sdbx.yaml"))
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if loadedCfg.IsAddonEnabled("prowlarr") {
		t.Error("prowlarr should be disabled in saved config")
	}
}

func TestAddonDisableNotEnabled(t *testing.T) {
	setupAddonCommandProject(t, config.DefaultConfig())
	output := captureAddonOutput(t, func() error {
		return runAddonDisable(addonDisableCmd, []string{"prowlarr"})
	})

	// Verify output mentions not enabled
	if !strings.Contains(output, "not enabled") {
		t.Errorf("Output should mention not enabled: %s", output)
	}
}

func setupAddonCommandProject(t *testing.T, cfg *config.Config) string {
	t.Helper()

	viper.Reset()
	cfgFile = ""
	noTUI = false
	jsonOut = false
	addonListAll = false
	addonCategory = ""

	homeDir := t.TempDir()
	sourceDir := filepath.Join(homeDir, ".config", "sdbx")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	sourceConfig := strings.Join([]string{
		"apiVersion: sdbx.one/v1",
		"kind: SourceConfig",
		"sources: []",
		"cache:",
		"  directory: " + filepath.Join(homeDir, "cache"),
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(sourceDir, "sources.yaml"), []byte(sourceConfig), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	t.Setenv("HOME", homeDir)

	projectDir := t.TempDir()
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	if err := os.Chdir(projectDir); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalDir)
		viper.Reset()
	})

	if err := cfg.Save(".sdbx.yaml"); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatalf("NewDefaultRegistry failed: %v", err)
	}
	lock, _, err := reg.GenerateLockFileWithOptions(
		context.Background(),
		cfg,
		registry.LockOptions{
			CLIVersion:    Version,
			ImageResolver: commandTestImageResolver{},
		},
	)
	if err != nil {
		t.Fatalf("GenerateLockFileWithOptions failed: %v", err)
	}
	if err := registry.NewLoader().SaveLockFile(filepath.Join(projectDir, ".sdbx.lock"), lock); err != nil {
		t.Fatalf("SaveLockFile failed: %v", err)
	}
	oldFactory := imageDigestResolverFactory
	imageDigestResolverFactory = func() registry.ImageDigestResolver {
		return commandTestImageResolver{}
	}
	t.Cleanup(func() {
		imageDigestResolverFactory = oldFactory
	})
	return projectDir
}

type commandTestImageResolver struct{}

func (commandTestImageResolver) Resolve(
	_ context.Context,
	repository, tag string,
) (registry.ResolvedImage, error) {
	sum := sha256.Sum256([]byte(repository + ":" + tag))
	digest := fmt.Sprintf("sha256:%x", sum[:])
	return registry.ResolvedImage{
		Digest: digest,
		PlatformDigests: map[string]string{
			"linux/amd64": digest,
			"linux/arm64": digest,
		},
	}, nil
}

func readCommandTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) failed: %v", path, err)
	}
	return string(data)
}

func captureAddonOutput(t *testing.T, run func() error) string {
	t.Helper()
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = original }()

	runErr := run()
	if closeErr := writer.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	var output bytes.Buffer
	if _, err := io.Copy(&output, reader); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if runErr != nil {
		t.Fatal(runErr)
	}
	return output.String()
}

func installTerminalControlAddonSource(t *testing.T) {
	t.Helper()
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	catalogDir := filepath.Join(t.TempDir(), "catalog")
	serviceDir := filepath.Join(catalogDir, "addons", "terminal-test")
	if err := os.MkdirAll(serviceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	definition := `apiVersion: sdbx.one/v1
kind: Service
applicationAuth:
  mode: none
metadata:
  name: terminal-test
  version: "1.0.0\u001b[31m"
  category: utility
  description: "Catalog\u001b[2J line\nnext\rreturn\u202Eevil"
  homepage: "https://example.test/\u001b]8;;spoof\u0007"
  documentation: "https://docs.example.test/\u202Espoof"
permissions:
  - network:app
  - route:admin-only
spec:
  image:
    repository: library/alpine
    tag: latest
  container:
    name_template: "sdbx-{{ .Name }}"
    restart: unless-stopped
  networking:
    mode: bridge
    networks:
      - name: app
routing:
  enabled: true
  port: 8080
  subdomain: terminal-test
  path: /terminal-test
  auth:
    mode: admin-only
  traefik:
    network: app
conditions:
  requireAddon: true
`
	if err := os.WriteFile(
		filepath.Join(serviceDir, "service.yaml"),
		[]byte(definition),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	sourceConfig := fmt.Sprintf(`apiVersion: sdbx.one/v1
kind: SourceConfig
metadata:
  version: 2
sources:
  - name: community
    type: local
    path: %s
    priority: 100
    enabled: true
    trust:
      allowCatalogPermissions:
        - network:app
        - route:admin-only
      allowedRegistries:
        - docker.io
cache:
  directory: %s
`, catalogDir, filepath.Join(homeDir, "cache"))
	if err := os.WriteFile(
		filepath.Join(homeDir, ".config", "sdbx", "sources.yaml"),
		[]byte(sourceConfig),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}
