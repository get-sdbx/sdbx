package registry

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
)

func TestResolveRejectsServiceDefinitionsWithValidationErrors(t *testing.T) {
	tmpDir := t.TempDir()
	serviceDir := filepath.Join(tmpDir, "danger")
	if err := os.MkdirAll(serviceDir, 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(serviceDir, "service.yaml"), []byte(`
apiVersion: sdbx.one/v1
kind: Service
applicationAuth:
  mode: none
metadata:
  name: danger
  version: 1.0.0
  category: utility
  description: Dangerous service
permissions:
  - network:app
  - privileged
spec:
  image:
    repository: alpine
    tag: latest
  container:
    name_template: sdbx-{{ .Name }}
    privileged: true
conditions:
  always: true
`), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	reg, err := New(&SourceConfig{
		APIVersion: APIVersion,
		Kind:       KindSourceConfig,
		Sources: []Source{
			{
				Name:     "local-test",
				Type:     "local",
				Path:     tmpDir,
				Priority: 100,
				Enabled:  true,
				Trust: TrustLevel{
					AllowedRegistries: []string{"docker.io"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	graph, err := reg.Resolve(context.Background(), config.DefaultConfig())
	if err == nil {
		t.Fatalf("Resolve accepted an ungranted privileged definition: %#v", graph)
	}
	if !strings.Contains(err.Error(), "not granted to this source") {
		t.Fatalf("Resolve error = %v, want source permission denial", err)
	}
}

func TestResolveCapturesServiceDefinitionValidationWarnings(t *testing.T) {
	tmpDir := t.TempDir()
	serviceDir := filepath.Join(tmpDir, "privileged-helper")
	if err := os.MkdirAll(serviceDir, 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(serviceDir, "service.yaml"), []byte(`
apiVersion: sdbx.one/v1
kind: Service
applicationAuth:
  mode: none
metadata:
  name: privileged-helper
  version: 1.0.0
  category: utility
  description: Privileged helper
permissions:
  - network:app
  - privileged
spec:
  image:
    repository: alpine
    tag: latest
  container:
    name_template: sdbx-{{ .Name }}
    privileged: true
  networking:
    networks:
      - name: app
conditions:
  always: true
`), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	reg, err := New(&SourceConfig{
		APIVersion: APIVersion,
		Kind:       KindSourceConfig,
		Sources: []Source{
			{
				Name:     "local-test",
				Type:     "local",
				Path:     tmpDir,
				Priority: 100,
				Enabled:  true,
				Trust: TrustLevel{
					AllowCatalogPermissions: []string{
						"network:app",
						PermissionPrivileged,
					},
					AllowedRegistries: []string{"docker.io"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	graph, err := reg.Resolve(context.Background(), config.DefaultConfig())
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(graph.Errors) != 0 {
		t.Fatalf("Resolve returned errors for warning-only service: %#v", graph.Errors)
	}
	if _, ok := graph.Services["privileged-helper"]; !ok {
		t.Fatal("warning-only service was not resolved")
	}
	for _, warning := range graph.Warnings {
		if warning.Service == "privileged-helper" &&
			strings.Contains(warning.Message, "privileged mode") {
			return
		}
	}
	t.Fatalf("expected privileged-mode warning, got %#v", graph.Warnings)
}

func TestResolveRejectsRequiredDependencyDisabledByConfiguration(t *testing.T) {
	tmpDir := t.TempDir()
	serviceDir := filepath.Join(tmpDir, "requires-vpn")
	if err := os.MkdirAll(serviceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(serviceDir, "service.yaml"), []byte(`
apiVersion: sdbx.one/v1
kind: Service
applicationAuth:
  mode: none
metadata:
  name: requires-vpn
  version: 1.0.0
  category: utility
  description: Requires a disabled dependency
permissions:
  - network:app
spec:
  image:
    repository: alpine
    tag: latest
  container:
    name_template: sdbx-requires-vpn
  networking:
    networks:
      - name: app
  dependencies:
    required:
      - gluetun
conditions:
  always: true
`), 0o600); err != nil {
		t.Fatal(err)
	}

	reg, err := New(&SourceConfig{
		APIVersion: APIVersion,
		Kind:       KindSourceConfig,
		Sources: []Source{{
			Name:     "local-test",
			Type:     "local",
			Path:     tmpDir,
			Priority: 100,
			Enabled:  true,
			Trust: TrustLevel{
				AllowedRegistries:       []string{"docker.io"},
				AllowCatalogPermissions: []string{"network:app"},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.VPNEnabled = false
	graph, err := reg.Resolve(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, resolutionError := range graph.Errors {
		if resolutionError.Service == "requires-vpn" &&
			strings.Contains(
				resolutionError.Message,
				"dependency gluetun is not enabled",
			) {
			return
		}
	}
	t.Fatalf("missing dependency was not reported: %#v", graph.Errors)
}

func TestGenerateLockFileWithWarningsReturnsResolutionWarnings(t *testing.T) {
	reg := registryWithWarningOnlyService(t)

	lockFile, warnings, err := reg.GenerateLockFileWithOptions(
		context.Background(),
		config.DefaultConfig(),
		LockOptions{
			CLIVersion:        "test",
			AllowLocalSources: true,
		},
	)
	if err != nil {
		t.Fatalf("GenerateLockFileWithWarnings failed: %v", err)
	}
	if lockFile == nil {
		t.Fatal("lock file was nil")
	}
	if _, ok := lockFile.Services["privileged-helper"]; !ok {
		t.Fatalf("lock file missing warning-only service: %#v", lockFile.Services)
	}
	for _, warning := range warnings {
		if warning.Service == "privileged-helper" &&
			strings.Contains(warning.Message, "privileged mode") {
			return
		}
	}
	t.Fatalf("expected privileged-mode warning, got %#v", warnings)
}

func registryWithWarningOnlyService(t *testing.T) *Registry {
	t.Helper()
	tmpDir := t.TempDir()
	serviceDir := filepath.Join(tmpDir, "privileged-helper")
	if err := os.MkdirAll(serviceDir, 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(serviceDir, "service.yaml"), []byte(`
apiVersion: sdbx.one/v1
kind: Service
applicationAuth:
  mode: none
metadata:
  name: privileged-helper
  version: 1.0.0
  category: utility
  description: Privileged helper
permissions:
  - network:app
  - privileged
spec:
  image:
    repository: alpine
    tag: latest
  container:
    name_template: sdbx-{{ .Name }}
    privileged: true
  networking:
    networks:
      - name: app
conditions:
  always: true
`), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	reg, err := New(&SourceConfig{
		APIVersion: APIVersion,
		Kind:       KindSourceConfig,
		Sources: []Source{
			{
				Name:     "local-test",
				Type:     "local",
				Path:     tmpDir,
				Priority: 100,
				Enabled:  true,
				Trust: TrustLevel{
					AllowCatalogPermissions: []string{
						"network:app",
						PermissionPrivileged,
					},
					AllowedRegistries: []string{"docker.io"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return reg
}
