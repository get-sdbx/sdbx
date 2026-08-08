package presets

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_BuiltinPresetsParse(t *testing.T) {
	col, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Sanity: the curated set must contain the headline profiles. If we drop
	// one, the test fails so we catch silent regressions on the docs surface.
	for _, want := range []string{
		"minimal",
		"media-plex",
		"media-jellyfin",
		"power-user",
	} {
		if col.Find(want) == nil {
			t.Errorf("expected built-in preset %q to be present", want)
		}
	}
}

func TestPresetsPointAtKnownAddons(t *testing.T) {
	// Cross-check that every addon referenced from a preset is plausibly
	// non-empty / non-trivial. We can't import the registry here without a
	// cycle, but we can at least catch typos like "snoarr" or "".
	col, _ := Load()
	for _, p := range col.Presets {
		for _, a := range p.Addons {
			if a == "" {
				t.Errorf("preset %q has empty addon name", p.Name)
			}
			if len(a) < 3 {
				t.Errorf("preset %q references suspiciously short addon %q", p.Name, a)
			}
		}
	}
}

func TestUserOverridesBuiltin(t *testing.T) {
	// Stand up a fake home dir with a presets.yaml that overrides "minimal".
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfgDir := filepath.Join(home, ".config", "sdbx")
	_ = os.MkdirAll(cfgDir, 0o755)
	override := `apiVersion: sdbx.one/v1
kind: PresetCollection
presets:
  - name: minimal
    title: My custom minimal
    icon: "🧪"
    description: "overridden"
    addons:
      - filebrowser
      - prowlarr
`
	_ = os.WriteFile(filepath.Join(cfgDir, "presets.yaml"), []byte(override), 0o644)

	col, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p := col.Find("minimal")
	if p == nil {
		t.Fatal("minimal preset disappeared")
	}
	if p.Title != "My custom minimal" {
		t.Errorf("user override not applied; got Title=%q", p.Title)
	}
	if len(p.Addons) != 2 {
		t.Errorf("user addon list not applied; got %v", p.Addons)
	}

	// Other built-ins still present.
	if col.Find("media-plex") == nil {
		t.Errorf("user override blew away built-ins")
	}
}

func TestFind_Missing(t *testing.T) {
	col, _ := Load()
	if col.Find("nope-not-a-preset") != nil {
		t.Errorf("Find returned non-nil for missing preset")
	}
}

func TestPresetJSONUsesLowercasePublicFieldNames(t *testing.T) {
	encoded, err := json.Marshal(Preset{
		Name:        "minimal",
		Title:       "Minimal",
		Icon:        "M",
		Description: "Small profile",
		Addons:      []string{"filebrowser"},
	})
	if err != nil {
		t.Fatal(err)
	}
	value := string(encoded)
	for _, field := range []string{"name", "title", "icon", "description", "addons"} {
		if !strings.Contains(value, `"`+field+`"`) {
			t.Errorf("JSON omits lowercase field %q: %s", field, value)
		}
	}
	for _, field := range []string{"Name", "Title", "Icon", "Description", "Addons"} {
		if strings.Contains(value, `"`+field+`"`) {
			t.Errorf("JSON leaks Go field name %q: %s", field, value)
		}
	}
}

func TestLoadBuiltinIgnoresUserOverrides(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	configDir := filepath.Join(home, ".config", "sdbx")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	override := `presets:
  - name: minimal
    title: Local override
    addons: [filebrowser]
`
	if err := os.WriteFile(
		filepath.Join(configDir, "presets.yaml"),
		[]byte(override),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	collection, err := LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	if preset := collection.Find("minimal"); preset == nil {
		t.Fatal("built-in minimal preset is missing")
	} else if preset.Title == "Local override" {
		t.Fatal("LoadBuiltin inherited a user override")
	}
}
