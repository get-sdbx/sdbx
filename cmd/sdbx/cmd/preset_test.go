package cmd

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/addons"
	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry/presets"
)

func TestPresetListJSONExposesCuratedBuiltinSet(t *testing.T) {
	setupAddonCommandProject(t, config.DefaultConfig())
	jsonOut = true
	output := captureAddonOutput(t, func() error {
		return runPresetList(presetListCmd, nil)
	})

	var result []presets.Preset
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("parse JSON output: %v\nOutput: %s", err, output)
	}
	if len(result) != 4 {
		t.Fatalf("preset count = %d, want 4", len(result))
	}
	for _, expected := range []string{"minimal", "media-plex", "media-jellyfin", "power-user"} {
		found := false
		for _, preset := range result {
			if preset.Name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("preset list is missing %q: %+v", expected, result)
		}
	}
}

func TestPresetShowReportsCuratedAddonSet(t *testing.T) {
	setupAddonCommandProject(t, config.DefaultConfig())
	output := captureAddonOutput(t, func() error {
		return runPresetShow(presetShowCmd, []string{"power-user"})
	})

	for _, expected := range []string{"Power user", "sonarr", "prowlarr", "nzbhydra2", "filebrowser"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("preset output missing %q:\n%s", expected, output)
		}
	}
}

func TestPresetShowRejectsUnknownPreset(t *testing.T) {
	setupAddonCommandProject(t, config.DefaultConfig())
	err := runPresetShow(presetShowCmd, []string{"does-not-exist"})
	if err == nil || !strings.Contains(err.Error(), "preset not found") {
		t.Fatalf("unknown preset error = %v", err)
	}
}

func TestPresetApplyEnablesAndRegeneratesOnce(t *testing.T) {
	projectDir := setupAddonCommandProject(t, config.DefaultConfig())
	jsonOut = true
	output := captureAddonOutput(t, func() error {
		return runPresetApply(presetApplyCmd, []string{"minimal"})
	})

	var result struct {
		Preset   string              `json:"preset"`
		Results  []addons.BulkResult `json:"results"`
		Success  bool                `json:"success"`
		Warnings []string            `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("parse JSON output: %v\nOutput: %s", err, output)
	}
	if result.Preset != "minimal" ||
		!result.Success ||
		len(result.Results) != 1 ||
		result.Results[0].Name != "filebrowser" ||
		result.Results[0].Action != "enabled" ||
		len(result.Warnings) != 0 {
		t.Fatalf("preset apply result = %+v", result)
	}

	cfg, err := config.LoadFile(filepath.Join(projectDir, ".sdbx.yaml"))
	if err != nil {
		t.Fatalf("load regenerated config: %v", err)
	}
	if !cfg.IsAddonEnabled("filebrowser") {
		t.Fatal("minimal preset did not persist filebrowser")
	}
	compose := readCommandTestFile(t, filepath.Join(projectDir, "compose.yaml"))
	if !strings.Contains(compose, "sdbx-filebrowser") {
		t.Fatalf("compose.yaml does not include filebrowser:\n%s", compose)
	}
}

func TestPresetApplyRejectsUnknownPresetWithoutMutation(t *testing.T) {
	projectDir := setupAddonCommandProject(t, config.DefaultConfig())
	err := runPresetApply(presetApplyCmd, []string{"does-not-exist"})
	if err == nil || !strings.Contains(err.Error(), "preset not found") {
		t.Fatalf("unknown preset error = %v", err)
	}
	cfg, loadErr := config.LoadFile(filepath.Join(projectDir, ".sdbx.yaml"))
	if loadErr != nil {
		t.Fatalf("load config: %v", loadErr)
	}
	if len(cfg.Addons) != 0 {
		t.Fatalf("unknown preset mutated addons: %v", cfg.Addons)
	}
}
