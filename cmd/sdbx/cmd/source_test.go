package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/registry"
)

func TestSourceAddPersistsImmutableTrustConfiguration(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	setSourceAddTestFlags(t)

	output := captureAddonOutput(t, func() error {
		return runSourceAdd(sourceAddCmd, []string{
			"community",
			"https://forgejo.example.com/org/services.git",
		})
	})
	for _, expected := range []string{
		"Source trust policy",
		sourceRef,
		sourceSigningKey,
		"ghcr.io",
		"host-network",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("source trust summary missing %q:\n%s", expected, output)
		}
	}

	cfg, err := loadSourceConfig()
	if err != nil {
		t.Fatalf("loadSourceConfig failed: %v", err)
	}
	if len(cfg.Sources) != 1 {
		t.Fatalf("sources = %#v, want one source", cfg.Sources)
	}
	source := cfg.Sources[0]
	if source.Ref != sourceRef {
		t.Fatalf("source ref = %q, want %q", source.Ref, sourceRef)
	}
	if source.SigningKey != sourceSigningKey {
		t.Fatalf("signing key = %q, want %q", source.SigningKey, sourceSigningKey)
	}
	if len(source.Trust.AllowCatalogPermissions) != 1 ||
		source.Trust.AllowCatalogPermissions[0] != "host-network" {
		t.Fatalf("permission grants = %#v", source.Trust.AllowCatalogPermissions)
	}
	if len(source.Trust.AllowedRegistries) != 1 ||
		source.Trust.AllowedRegistries[0] != "ghcr.io" {
		t.Fatalf("registry grants = %#v", source.Trust.AllowedRegistries)
	}
}

func TestSourceAddDefaultsToNoRegistryGrants(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetSourceAddTestFlags(t)
	sourceRef = "0123456789abcdef0123456789abcdef01234567"
	sourceSigningKey = "0123456789ABCDEF0123456789ABCDEF01234567"

	output := captureAddonOutput(t, func() error {
		return runSourceAdd(sourceAddCmd, []string{
			"community",
			"https://forgejo.example.com/org/services.git",
		})
	})
	if !strings.Contains(output, "none (external images denied)") {
		t.Fatalf("empty registry policy was not disclosed:\n%s", output)
	}

	cfg, err := loadSourceConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Sources) != 1 {
		t.Fatalf("sources = %#v, want one source", cfg.Sources)
	}
	source := cfg.Sources[0]
	if len(source.Trust.AllowedRegistries) != 0 {
		t.Fatalf("implicit registry grants persisted: %#v", source.Trust.AllowedRegistries)
	}

	def := &registry.ServiceDefinition{
		APIVersion: registry.APIVersion,
		Kind:       registry.KindService,
		Metadata: registry.ServiceMetadata{
			Name:        "external",
			Version:     "1.0.0",
			Category:    registry.CategoryUtility,
			Description: "External test image",
		},
		Spec: registry.ServiceSpec{
			Image: registry.ImageSpec{
				Repository: "alpine",
				Tag:        "latest",
			},
			Container: registry.ContainerSpec{
				NameTemplate: "sdbx-{{ .Name }}",
			},
			Networking: registry.NetworkSpec{
				Networks: []registry.NetworkRef{{Name: registry.NetworkApplication}},
			},
		},
	}
	validationErrors := registry.NewValidator().ValidateWithTrustLevel(def, source.Trust)
	registryDenied := false
	for _, validationErr := range validationErrors {
		if validationErr.Severity == "error" &&
			strings.Contains(validationErr.Message, "registry docker.io not allowed") {
			registryDenied = true
		}
	}
	if !registryDenied {
		t.Fatalf("external image was not denied: %#v", validationErrors)
	}
}

func TestSourceAddRejectsMissingImmutableRefAndSigner(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetSourceAddTestFlags(t)

	err := runSourceAdd(sourceAddCmd, []string{
		"community",
		"https://forgejo.example.com/org/services.git",
	})
	if err == nil || !strings.Contains(err.Error(), "--ref is required") {
		t.Fatalf("runSourceAdd error = %v, want missing ref", err)
	}

	sourceRef = "0123456789abcdef0123456789abcdef01234567"
	err = runSourceAdd(sourceAddCmd, []string{
		"community",
		"https://forgejo.example.com/org/services.git",
	})
	if err == nil || !strings.Contains(err.Error(), "--signing-key is required") {
		t.Fatalf("runSourceAdd error = %v, want missing signing key", err)
	}
}

func TestSourceAddPreservesUnreadableOrInvalidConfiguration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setSourceAddTestFlags(t)

	configPath := filepath.Join(home, ".config", "sdbx", "sources.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	canary := []byte("not: [valid\nSOURCE_CONFIG_CANARY\n")
	if err := os.WriteFile(configPath, canary, 0o600); err != nil {
		t.Fatal(err)
	}

	err := runSourceAdd(sourceAddCmd, []string{
		"community",
		"https://forgejo.example.com/org/services.git",
	})
	if err == nil || !strings.Contains(err.Error(), "load source configuration") {
		t.Fatalf("runSourceAdd invalid config error = %v", err)
	}
	after, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != string(canary) {
		t.Fatalf("invalid source configuration was overwritten: %q", after)
	}
}

func TestSourceAddPreservesSemanticallyInvalidPolicy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setSourceAddTestFlags(t)

	configPath := filepath.Join(home, ".config", "sdbx", "sources.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	canary := []byte(`apiVersion: sdbx.one/v1
kind: SourceConfig
metadata:
  version: 2
sources:
  - name: disabled-insecure
    type: git
    url: http://catalog.example.test/services.git
    enabled: false
`)
	if err := os.WriteFile(configPath, canary, 0o600); err != nil {
		t.Fatal(err)
	}

	err := runSourceAdd(sourceAddCmd, []string{
		"community",
		"https://forgejo.example.com/org/services.git",
	})
	if err == nil || !strings.Contains(err.Error(), "load source configuration") {
		t.Fatalf("runSourceAdd invalid policy error = %v", err)
	}
	after, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != string(canary) {
		t.Fatalf("invalid source policy was overwritten: %q", after)
	}
}

func TestSourceRemoveAllowsExplicitSourceNamedOfficial(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfg := registry.DefaultSourceConfig()
	cfg.Sources = []registry.Source{{
		Name:       "official",
		Type:       "git",
		URL:        "https://forgejo.example.com/org/services.git",
		Ref:        "0123456789abcdef0123456789abcdef01234567",
		SigningKey: strings.Repeat("01", 20),
		Enabled:    true,
	}}
	if err := saveSourceConfig(cfg); err != nil {
		t.Fatal(err)
	}

	output := captureAddonOutput(t, func() error {
		return runSourceRemove(sourceRemoveCmd, []string{"official"})
	})
	if !strings.Contains(output, "Removed source: official") {
		t.Fatalf("remove output = %q", output)
	}
	reloaded, err := loadSourceConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Sources) != 0 {
		t.Fatalf("sources after removal = %#v", reloaded.Sources)
	}

	if err := runSourceRemove(sourceRemoveCmd, []string{"embedded"}); err == nil ||
		!strings.Contains(err.Error(), "cannot remove built-in source") {
		t.Fatalf("embedded removal error = %v", err)
	}
}

func TestSourceInfoLoadsAndDisplaysEveryDiscoveredService(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	catalogRoot := filepath.Join(home, "catalog")
	serviceRoot := filepath.Join(catalogRoot, "addons", "example")
	if err := os.MkdirAll(serviceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(serviceRoot, "service.yaml"),
		[]byte(`apiVersion: sdbx.one/v1
kind: Service
applicationAuth:
  mode: none
metadata:
  name: example
  version: 1.0.0
  category: utility
  description: Synthetic local source
spec:
  image:
    repository: alpine
    tag: latest
conditions:
  requireAddon: true
`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	cfg := registry.DefaultSourceConfig()
	cfg.Sources = []registry.Source{{
		Name:     "local-test",
		Type:     "local",
		Path:     catalogRoot,
		Priority: 100,
		Enabled:  true,
	}}
	if err := saveSourceConfig(cfg); err != nil {
		t.Fatal(err)
	}

	output := captureAddonOutput(t, func() error {
		return runSourceInfo(sourceInfoCmd, []string{"local-test"})
	})
	for _, expected := range []string{
		"Source: local-test",
		"Type:     local",
		"Services: 1",
		"example",
		"(addon)",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("source info missing %q:\n%s", expected, output)
		}
	}
}

func setSourceAddTestFlags(t *testing.T) {
	t.Helper()
	resetSourceAddTestFlags(t)
	sourceRef = "0123456789abcdef0123456789abcdef01234567"
	sourceSigningKey = "0123456789ABCDEF0123456789ABCDEF01234567"
	sourceAllowedPermissions = []string{"host-network"}
	sourceAllowedRegistries = []string{"ghcr.io"}
}

func resetSourceAddTestFlags(t *testing.T) {
	t.Helper()
	oldPriority := sourcePriority
	oldRef := sourceRef
	oldSigningKey := sourceSigningKey
	oldSSHKey := sourceSSHKey
	oldPermissions := sourceAllowedPermissions
	oldRegistries := sourceAllowedRegistries
	t.Cleanup(func() {
		sourcePriority = oldPriority
		sourceRef = oldRef
		sourceSigningKey = oldSigningKey
		sourceSSHKey = oldSSHKey
		sourceAllowedPermissions = oldPermissions
		sourceAllowedRegistries = oldRegistries
	})

	sourcePriority = 10
	sourceRef = ""
	sourceSigningKey = ""
	sourceSSHKey = ""
	sourceAllowedPermissions = nil
	sourceAllowedRegistries = nil
}
