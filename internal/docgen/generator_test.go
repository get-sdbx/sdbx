package docgen

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestGenerateAllIsDeterministicAndComplete(t *testing.T) {
	first, err := GenerateAll()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateAll()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("GenerateAll output is not deterministic")
	}

	expected := []string{
		"docs/configuration.md",
		"docs/reference/cli.md",
		"docs/reference/presets.md",
		"docs/reference/services.md",
		"product-manifest.json",
	}
	if len(first) != len(expected) {
		t.Fatalf("GenerateAll paths = %d, want %d", len(first), len(expected))
	}
	for _, path := range expected {
		content, ok := first[path]
		if !ok {
			t.Fatalf("GenerateAll missing %s", path)
		}
		if path != "product-manifest.json" &&
			!bytes.HasPrefix(content, []byte(generatedNotice)) {
			t.Fatalf("%s has no generated notice", path)
		}
		if path != "product-manifest.json" &&
			(!bytes.HasSuffix(content, []byte("\n")) ||
				bytes.HasSuffix(content, []byte("\n\n"))) {
			t.Fatalf("%s must end with exactly one newline", path)
		}
	}
}

func TestGeneratedReferencesMatchReleaseContracts(t *testing.T) {
	outputs, err := GenerateAll()
	if err != nil {
		t.Fatal(err)
	}

	cli := string(outputs["docs/reference/cli.md"])
	for _, expected := range []string{
		"sdbx backup restore <backup-name>",
		"`--confirm`",
		"`--acme-email`",
		"sdbx source add <name> <url>",
	} {
		if !strings.Contains(cli, expected) {
			t.Errorf("CLI reference missing %q", expected)
		}
	}

	services := string(outputs["docs/reference/services.md"])
	for _, expected := range []string{
		"**40 services**",
		"**7 core definitions**",
		"**33 addons**",
		"`sdbx-managed-forms`",
		"`Hidden`",
	} {
		if !strings.Contains(services, expected) {
			t.Errorf("service reference missing %q", expected)
		}
	}

	presets := string(outputs["docs/reference/presets.md"])
	if !strings.Contains(presets, "**4 named addon presets**") {
		t.Error("preset reference does not report four built-in presets")
	}
	configuration := string(outputs["docs/configuration.md"])
	for _, expected := range []string{
		"cannot override an image",
		"`kind: ServiceOverride` catalog documents are rejected",
	} {
		if !strings.Contains(configuration, expected) {
			t.Errorf("configuration reference missing %q", expected)
		}
	}

	all := cli + services + presets + configuration
	for _, retired := range []string{
		"SDBX-Services",
		"forgejo.cloud.",
		"Overseerr",
		"Homepage",
	} {
		if strings.Contains(all, retired) {
			t.Errorf("generated reference contains retired dependency %q", retired)
		}
	}
}
