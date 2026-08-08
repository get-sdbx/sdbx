package registry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoaderAcceptsCanonicalDomainAPIVersion(t *testing.T) {
	def, err := NewLoader().ParseServiceDefinition([]byte(`
apiVersion: sdbx.one/v1
kind: Service
applicationAuth:
  mode: none
metadata:
  name: sample
  version: 1.0.0
  category: utility
  description: Sample service
spec:
  image:
    repository: busybox
    tag: latest
  container:
    name_template: sdbx-sample
conditions:
  requireAddon: true
`))
	if err != nil {
		t.Fatalf("ParseServiceDefinition failed: %v", err)
	}
	if def.APIVersion != APIVersion {
		t.Fatalf("APIVersion = %q, want %q", def.APIVersion, APIVersion)
	}
}

func TestLoaderAcceptsCamelCaseHealthCheck(t *testing.T) {
	def, err := NewLoader().ParseServiceDefinition([]byte(`
apiVersion: sdbx.one/v1
kind: Service
applicationAuth:
  mode: none
metadata:
  name: sample
  version: 1.0.0
  category: utility
  description: Sample service
spec:
  image:
    repository: busybox
    tag: latest
  container:
    name_template: sdbx-sample
  healthCheck:
    test: ["CMD", "true"]
    interval: 30s
    timeout: 5s
    retries: 3
conditions:
  requireAddon: true
`))
	if err != nil {
		t.Fatalf("ParseServiceDefinition failed: %v", err)
	}
	if def.Spec.HealthCheck == nil {
		t.Fatal("HealthCheck was not populated from healthCheck")
	}
	if got := def.Spec.HealthCheck.Test; len(got) != 2 || got[0] != "CMD" || got[1] != "true" {
		t.Fatalf("HealthCheck.Test = %#v, want [CMD true]", got)
	}
}

func TestLoaderRejectsUnknownServiceFields(t *testing.T) {
	_, err := NewLoader().ParseServiceDefinition([]byte(`
apiVersion: sdbx.one/v1
kind: Service
applicationAuth:
  mode: none
metadata:
  name: sample
  version: 1.0.0
  category: utility
spec:
  image:
    repository: busybox
  container:
    name_template: sdbx-sample
    privleged: true
conditions:
  requireAddon: true
`))
	if err == nil || !strings.Contains(err.Error(), "field privleged not found") {
		t.Fatalf("ParseServiceDefinition error = %v, want unknown-field rejection", err)
	}
}

func TestLoaderRejectsMultipleServiceDocuments(t *testing.T) {
	data := []byte(`
apiVersion: sdbx.one/v1
kind: Service
applicationAuth:
  mode: none
metadata:
  name: sample
  version: 1.0.0
  category: utility
spec:
  image:
    repository: busybox
  container:
    name_template: sdbx-sample
conditions:
  requireAddon: true
---
apiVersion: sdbx.one/v1
kind: Service
applicationAuth:
  mode: none
metadata:
  name: hidden
`)
	_, err := NewLoader().ParseServiceDefinition(data)
	if err == nil || !strings.Contains(err.Error(), "multiple documents") {
		t.Fatalf("ParseServiceDefinition error = %v, want multi-document rejection", err)
	}
}

func TestLoaderRejectsRetiredPartialServiceOverrideKind(t *testing.T) {
	_, err := NewLoader().ParseServiceDefinition([]byte(`
apiVersion: sdbx.one/v1
kind: ServiceOverride
metadata:
  name: sample
spec:
  image:
    repository: attacker.example/sample
`))
	if err == nil || !strings.Contains(err.Error(), "unexpected kind") {
		t.Fatalf(
			"ParseServiceDefinition error = %v, want partial override rejection",
			err,
		)
	}
}

func TestLoaderRejectsRetiredUnimplementedConditionFields(t *testing.T) {
	testCases := []struct {
		name       string
		extraSpec  string
		conditions string
	}{
		{
			name:       "feature-selector",
			conditions: "  requireFeature: unsafe\n",
		},
		{
			name:       "optional-dependency",
			extraSpec:  "  dependencies:\n    optional: [unsafe]\n",
			conditions: "  always: true\n",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			document := `apiVersion: sdbx.one/v1
kind: Service
applicationAuth:
  mode: none
metadata:
  name: sample
  version: 1.0.0
  category: utility
  description: Sample
spec:
  image:
    repository: busybox
    tag: latest
  container:
    name_template: sdbx-sample
` + testCase.extraSpec + "conditions:\n" + testCase.conditions
			_, err := NewLoader().ParseServiceDefinition([]byte(document))
			if err == nil || !strings.Contains(err.Error(), "field") {
				t.Fatalf("retired field was accepted: %v", err)
			}
		})
	}
}

func TestListServicesRejectsInvalidHigherPriorityDefinition(t *testing.T) {
	tmpDir := t.TempDir()
	serviceDir := filepath.Join(tmpDir, "core", "traefik")
	if err := os.MkdirAll(serviceDir, 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(serviceDir, "service.yaml"), []byte(`
apiVersion: invalid.example/v1
kind: Service
applicationAuth:
  mode: none
metadata:
  name: traefik
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
			},
		},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	_, err = reg.ListServices(context.Background())
	if err == nil {
		t.Fatal("ListServices silently fell back from an invalid higher-priority definition")
	}
}

func TestLoaderRejectsSymlinkedServiceDefinition(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "service.yaml")
	if err := os.WriteFile(outside, []byte(`
apiVersion: sdbx.one/v1
kind: Service
applicationAuth:
  mode: none
metadata:
  name: escape
`), 0o600); err != nil {
		t.Fatal(err)
	}

	serviceDir := filepath.Join(root, "escape")
	if err := os.MkdirAll(serviceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	servicePath := filepath.Join(serviceDir, "service.yaml")
	if err := os.Symlink(outside, servicePath); err != nil {
		t.Fatal(err)
	}

	if _, err := NewLoader().LoadServiceDefinition(servicePath); err == nil {
		t.Fatal("LoadServiceDefinition accepted a symbolic link")
	}
	if _, err := NewLoader().DiscoverServices(root); err == nil {
		t.Fatal("DiscoverServices accepted a symbolic link")
	}
}

func TestDiscoverServicesRejectsCatalogResourceLimitOverflows(t *testing.T) {
	tests := []struct {
		name string
		want string
		fill func(*testing.T, string)
	}{
		{
			name: "entries",
			want: "entry discovery limit",
			fill: func(t *testing.T, root string) {
				writeCatalogFiles(t, root, maxCatalogEntries+1, 0)
			},
		},
		{
			name: "individual file bytes",
			want: "file exceeds",
			fill: func(t *testing.T, root string) {
				writeSparseCatalogFile(
					t,
					filepath.Join(root, "oversized"),
					maxCatalogTraversalFile+1,
				)
			},
		},
		{
			name: "tree bytes",
			want: "byte tree limit",
			fill: func(t *testing.T, root string) {
				for index := 0; index < 9; index++ {
					writeSparseCatalogFile(
						t,
						filepath.Join(root, fmt.Sprintf("payload-%02d", index)),
						maxCatalogTraversalFile,
					)
				}
			},
		},
		{
			name: "depth",
			want: "discovery depth limit",
			fill: func(t *testing.T, root string) {
				path := root
				for depth := 0; depth <= maxCatalogTraversalDepth; depth++ {
					path = filepath.Join(path, fmt.Sprintf("d%d", depth))
				}
				if err := os.MkdirAll(path, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "definition count",
			want: "definition parse limit",
			fill: func(t *testing.T, root string) {
				writeCatalogDefinitions(t, root, maxCatalogDefinitions+1, 0)
			},
		},
		{
			name: "definition bytes",
			want: "definition parse limit",
			fill: func(t *testing.T, root string) {
				count := maxCatalogDefinitionBytes/maxServiceDefinitionSize + 1
				writeCatalogDefinitions(t, root, count, maxServiceDefinitionSize)
			},
		},
		{
			name: "noncanonical definition path",
			want: "must use <name>/service.yaml",
			fill: func(t *testing.T, root string) {
				path := filepath.Join(root, "nested", "catalog", "service", "service.yaml")
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			test.fill(t, root)
			_, err := NewLoader().DiscoverServices(root)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("DiscoverServices error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDiscoverServicesAcceptsCatalogResourceLimitBoundaries(t *testing.T) {
	t.Run("entries", func(t *testing.T) {
		root := t.TempDir()
		writeCatalogFiles(t, root, maxCatalogEntries, 0)
		services, err := NewLoader().DiscoverServices(root)
		if err != nil || len(services) != 0 {
			t.Fatalf("boundary catalog = %d services, %v", len(services), err)
		}
	})
	t.Run("tree bytes and individual file", func(t *testing.T) {
		root := t.TempDir()
		for index := 0; index < maxCatalogTreeBytes/maxCatalogTraversalFile; index++ {
			writeSparseCatalogFile(
				t,
				filepath.Join(root, fmt.Sprintf("payload-%02d", index)),
				maxCatalogTraversalFile,
			)
		}
		if _, err := NewLoader().DiscoverServices(root); err != nil {
			t.Fatalf("exact byte boundaries rejected: %v", err)
		}
	})
	t.Run("depth", func(t *testing.T) {
		root := t.TempDir()
		path := root
		for depth := 0; depth < maxCatalogTraversalDepth; depth++ {
			path = filepath.Join(path, fmt.Sprintf("d%d", depth))
		}
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := NewLoader().DiscoverServices(root); err != nil {
			t.Fatalf("exact depth boundary rejected: %v", err)
		}
	})
	t.Run("definitions", func(t *testing.T) {
		root := t.TempDir()
		writeCatalogDefinitions(t, root, maxCatalogDefinitions, 0)
		services, err := NewLoader().DiscoverServices(root)
		if err != nil || len(services) != maxCatalogDefinitions {
			t.Fatalf("definition boundary = %d services, %v", len(services), err)
		}
	})
	t.Run("definition bytes", func(t *testing.T) {
		root := t.TempDir()
		count := maxCatalogDefinitionBytes / maxServiceDefinitionSize
		writeCatalogDefinitions(t, root, count, maxServiceDefinitionSize)
		services, err := NewLoader().DiscoverServices(root)
		if err != nil || len(services) != count {
			t.Fatalf("definition-byte boundary = %d services, %v", len(services), err)
		}
	})
}

func writeCatalogFiles(t *testing.T, root string, count int, size int64) {
	t.Helper()
	for index := 0; index < count; index++ {
		writeSparseCatalogFile(
			t,
			filepath.Join(root, fmt.Sprintf("entry-%05d", index)),
			size,
		)
	}
}

func writeCatalogDefinitions(t *testing.T, root string, count int, size int64) {
	t.Helper()
	for index := 0; index < count; index++ {
		path := filepath.Join(root, fmt.Sprintf("service-%05d", index), "service.yaml")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		writeSparseCatalogFile(t, path, size)
	}
}

func writeSparseCatalogFile(t *testing.T, path string, size int64) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, size); err != nil {
		t.Fatal(err)
	}
}

func TestSaveLockFileUsesAtomicPublicMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".sdbx.lock")
	if err := NewLoader().SaveLockFile(path, minimalValidLock()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("lock mode = %o, want 644", got)
	}
	if _, err := NewLoader().LoadLockFile(path); err != nil {
		t.Fatalf("saved lock could not be loaded: %v", err)
	}
}

func TestSaveSourceConfigUsesPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sources.yaml")
	cfg := DefaultSourceConfig()
	if err := NewLoader().SaveSourceConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("source config mode = %o, want 600", got)
	}
}

func TestParseSourceConfigRejectsAmbiguousOrUnknownPolicy(t *testing.T) {
	valid := `apiVersion: sdbx.one/v1
kind: SourceConfig
metadata:
  version: 2
sources:
  - name: local-test
    type: local
    path: /srv/sdbx/catalog
    enabled: true
`
	testCases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "unknown nested trust field",
			body: valid + `    trust:
      allowedRegistry:
        - docker.io
`,
			want: "field allowedRegistry not found",
		},
		{
			name: "multiple documents",
			body: valid + "---\napiVersion: sdbx.one/v1\nkind: SourceConfig\n",
			want: "multiple documents",
		},
		{
			name: "wrong API version",
			body: strings.Replace(
				valid,
				"apiVersion: sdbx.one/v1",
				"apiVersion: attacker.example/v1",
				1,
			),
			want: "unsupported API version",
		},
		{
			name: "wrong kind",
			body: strings.Replace(
				valid,
				"kind: SourceConfig",
				"kind: Service",
				1,
			),
			want: "unexpected kind",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewLoader().ParseSourceConfig([]byte(testCase.body))
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("ParseSourceConfig error = %v, want %q", err, testCase.want)
			}
		})
	}
}
