package registry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type failingSourceProvider struct {
	BaseSource
	err error
}

func (s *failingSourceProvider) Load(context.Context) ([]*ServiceDefinition, error) {
	return nil, s.err
}

func (s *failingSourceProvider) LoadService(context.Context, string) (*ServiceDefinition, error) {
	return nil, s.err
}

func (s *failingSourceProvider) ListServices(context.Context) ([]string, error) {
	return nil, s.err
}

func (s *failingSourceProvider) GetServicePath(string) string {
	return ""
}

func (s *failingSourceProvider) Update(context.Context) error {
	return s.err
}

func (s *failingSourceProvider) GetCommit() string {
	return ""
}

func TestDefaultSourceConfigUsesEmbeddedCatalogOnly(t *testing.T) {
	cfg := DefaultSourceConfig()

	if len(cfg.Sources) != 0 {
		t.Fatalf("default sources = %#v, want embedded catalog only", cfg.Sources)
	}
	if cfg.Metadata.Version != 2 {
		t.Fatalf("source config version = %d, want 2", cfg.Metadata.Version)
	}
	if cfg.Security.AllowUnverified {
		t.Fatal("default source security must not allow unverified sources")
	}
}

func TestLoadDefaultSourceConfigMigratesLegacyOfficialSource(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	configDir := filepath.Join(home, ".config", "sdbx")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}

	content := `apiVersion: sdbx.one/v1
kind: SourceConfig
metadata:
  version: 1
sources:
  - name: official
    type: git
    url: ssh://git@legacy.example.test:22222/sdbx/catalog.git
    branch: main
    path: services
    priority: 0
    enabled: true
    verified: true
  - name: custom
    type: local
    path: /srv/sdbx-services
    priority: 50
    enabled: true
security:
  allowUnverified: true
`
	if err := os.WriteFile(filepath.Join(configDir, "sources.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadDefaultSourceConfig()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Metadata.Version != 2 {
		t.Fatalf("source config version = %d, want 2", cfg.Metadata.Version)
	}
	if len(cfg.Sources) != 1 || cfg.Sources[0].Name != "custom" {
		t.Fatalf("migrated sources = %#v, want only custom source", cfg.Sources)
	}
}

func TestLoadDefaultSourceConfigRejectsInvalidV2Policy(t *testing.T) {
	testCases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "invalid disabled source",
			body: `apiVersion: sdbx.one/v1
kind: SourceConfig
metadata:
  version: 2
sources:
  - name: disabled-git
    type: git
    url: http://catalog.example.test/services.git
    enabled: false
`,
			want: "HTTPS or SSH",
		},
		{
			name: "future schema version",
			body: `apiVersion: sdbx.one/v1
kind: SourceConfig
metadata:
  version: 3
`,
			want: "unsupported source configuration version",
		},
		{
			name: "invalid cache TTL",
			body: `apiVersion: sdbx.one/v1
kind: SourceConfig
metadata:
  version: 2
cache:
  ttl: never
`,
			want: "source cache TTL",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			configDir := filepath.Join(home, ".config", "sdbx")
			if err := os.MkdirAll(configDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(
				filepath.Join(configDir, "sources.yaml"),
				[]byte(testCase.body),
				0o600,
			); err != nil {
				t.Fatal(err)
			}
			_, err := LoadDefaultSourceConfig()
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("LoadDefaultSourceConfig error = %v, want %q", err, testCase.want)
			}
		})
	}
}

func TestMigrateLegacySourceConfigPreservesVersionTwoSources(t *testing.T) {
	cfg := &SourceConfig{
		Metadata: SourceConfigMetadata{Version: 2},
		Sources: []Source{{
			Name:           "official",
			Type:           "git",
			URL:            "ssh://git@catalog.example.test/team/services.git",
			Path:           "services",
			Enabled:        true,
			LegacyBranch:   "main",
			LegacyVerified: true,
		}},
	}

	migrateLegacySourceConfig(cfg)

	if len(cfg.Sources) != 1 {
		t.Fatalf("version two source was removed: %#v", cfg.Sources)
	}
}

func TestNewDefaultRegistryHasOneEmbeddedSource(t *testing.T) {
	reg, err := NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}

	sources := reg.Sources()
	if len(sources) != 1 {
		t.Fatalf("sources = %d, want one embedded source", len(sources))
	}
	if sources[0].Type() != "embedded" {
		t.Fatalf("source type = %q, want embedded", sources[0].Type())
	}
}

func TestNewValidatesSourceConfigurationAndAppliesCacheTTL(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New accepted a nil source configuration")
	}

	for _, ttl := range []string{"not-a-duration", "0s", "-1s"} {
		cfg := DefaultSourceConfig()
		cfg.Cache.Directory = t.TempDir()
		cfg.Cache.TTL = ttl
		if _, err := New(cfg); err == nil ||
			!strings.Contains(err.Error(), "source cache TTL") {
			t.Fatalf("New cache TTL %q error = %v", ttl, err)
		}
	}

	cfg := DefaultSourceConfig()
	cfg.Cache.Directory = t.TempDir()
	cfg.Cache.TTL = "17m"
	reg, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if reg.cache.ttl != 17*time.Minute {
		t.Fatalf("cache TTL = %s, want 17m", reg.cache.ttl)
	}

	cfg = DefaultSourceConfig()
	cfg.Cache.Directory = t.TempDir()
	cfg.Sources = []Source{{
		Name:    "extra-embedded",
		Type:    "embedded",
		Enabled: true,
	}}
	if _, err := New(cfg); err == nil ||
		!strings.Contains(err.Error(), "unsupported configurable source type") {
		t.Fatalf("New configurable embedded error = %v", err)
	}
}

func TestNewRejectsDuplicateAndReservedSourceNames(t *testing.T) {
	tests := []struct {
		name    string
		sources []Source
	}{
		{
			name: "reserved embedded",
			sources: []Source{{
				Name:    "embedded",
				Type:    "local",
				Path:    t.TempDir(),
				Enabled: true,
			}},
		},
		{
			name: "duplicate",
			sources: []Source{
				{Name: "custom", Type: "local", Path: t.TempDir(), Enabled: true},
				{Name: "custom", Type: "local", Path: t.TempDir(), Enabled: false},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultSourceConfig()
			cfg.Sources = test.sources
			if _, err := New(cfg); err == nil {
				t.Fatalf("New accepted sources %#v", test.sources)
			}
		})
	}
}

func TestRegistrySourceMutationPreservesEmbeddedInvariant(t *testing.T) {
	reg, err := NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := reg.Sources()
	if len(snapshot) != 1 {
		t.Fatalf("initial sources = %d, want 1", len(snapshot))
	}
	snapshot[0] = nil
	if sources := reg.Sources(); len(sources) != 1 || sources[0] == nil {
		t.Fatal("Sources exposed the registry's mutable backing slice")
	}

	if err := reg.RemoveSource("embedded"); err == nil ||
		!strings.Contains(err.Error(), "cannot remove built-in source") {
		t.Fatalf("RemoveSource embedded error = %v", err)
	}
	localRoot := t.TempDir()
	if err := reg.AddSource(Source{
		Name:     "local-test",
		Type:     "local",
		Path:     localRoot,
		Priority: 100,
		Enabled:  true,
	}); err != nil {
		t.Fatal(err)
	}
	if sources := reg.Sources(); len(sources) != 2 ||
		sources[0].Name() != "local-test" {
		t.Fatalf("sorted sources = %#v", sources)
	}
	if err := reg.AddSource(Source{
		Name:    "local-test",
		Type:    "local",
		Path:    localRoot,
		Enabled: true,
	}); err == nil {
		t.Fatal("AddSource accepted a duplicate name")
	}
	if err := reg.RemoveSource("local-test"); err != nil {
		t.Fatal(err)
	}
	if sources := reg.Sources(); len(sources) != 1 ||
		sources[0].Name() != "embedded" {
		t.Fatalf("sources after removal = %#v", sources)
	}
}

func TestListServicesReturnsEnabledSourceErrors(t *testing.T) {
	sourceErr := errors.New("source cache is not a git repository")
	reg := &Registry{
		sources: []SourceProvider{
			&failingSourceProvider{
				BaseSource: BaseSource{
					name:     "official",
					srcType:  "git",
					priority: 0,
					enabled:  true,
				},
				err: sourceErr,
			},
		},
	}

	_, err := reg.ListServices(context.Background())

	if err == nil {
		t.Fatal("ListServices returned nil error for failing enabled source")
	}
	if !strings.Contains(err.Error(), "official") {
		t.Fatalf("ListServices error = %q, want source name", err)
	}
	if !errors.Is(err, sourceErr) {
		t.Fatalf("ListServices error does not wrap source error: %v", err)
	}
}

func TestRegistryRejectsInvalidServiceNameBeforeSourceLookup(t *testing.T) {
	registry := &Registry{
		sources: []SourceProvider{
			&failingSourceProvider{
				BaseSource: BaseSource{
					name:    "must-not-run",
					enabled: true,
				},
				err: errors.New("source lookup should not run"),
			},
		},
	}

	for _, name := range []string{"../outside", "core/traefik", "/absolute", ""} {
		_, _, err := registry.GetService(context.Background(), name)
		if err == nil || !strings.Contains(err.Error(), "invalid service name") {
			t.Fatalf("GetService(%q) error = %v", name, err)
		}
		if strings.Contains(err.Error(), "source lookup should not run") {
			t.Fatalf("GetService(%q) reached a source: %v", name, err)
		}
	}
}

func TestLocalSourceConfinesServiceNameOperations(t *testing.T) {
	root := t.TempDir()
	catalogRoot := filepath.Join(root, "catalog")
	outsideRoot := filepath.Join(root, "outside")
	if err := os.MkdirAll(catalogRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	canaryPath := filepath.Join(outsideRoot, "service.yaml")
	if err := os.WriteFile(canaryPath, []byte("outside-canary\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	source := NewLocalSource(Source{
		Name:    "local",
		Type:    "local",
		Path:    catalogRoot,
		Enabled: true,
	})
	traversal := "../outside"

	if _, err := source.LoadService(context.Background(), traversal); err == nil ||
		!strings.Contains(err.Error(), "invalid service name") {
		t.Fatalf("LoadService traversal error = %v", err)
	}
	if path := source.GetServicePath(traversal); path != "" {
		t.Fatalf("GetServicePath traversal = %q, want empty", path)
	}
	if source.HasService(traversal) {
		t.Fatal("HasService accepted traversal")
	}
	if _, err := source.CreateServiceDir(traversal, false); err == nil {
		t.Fatal("CreateServiceDir accepted traversal")
	}
	if err := source.SaveService(&ServiceDefinition{
		Metadata: ServiceMetadata{Name: traversal},
	}); err == nil {
		t.Fatal("SaveService accepted traversal")
	}
	if err := source.DeleteService(traversal); err == nil {
		t.Fatal("DeleteService accepted traversal")
	}

	data, err := os.ReadFile(canaryPath)
	if err != nil {
		t.Fatalf("outside canary was removed: %v", err)
	}
	if string(data) != "outside-canary\n" {
		t.Fatalf("outside canary changed: %q", data)
	}
}

func TestSearchServicesMatchesNameDescriptionAndCategory(t *testing.T) {
	reg, err := NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		query    string
		category ServiceCategory
		want     string
	}{
		{query: "SONARR", want: "sonarr"},
		{query: "multi-factor", want: "authelia"},
		{
			query:    "kill switch",
			category: CategoryNetworking,
			want:     "gluetun",
		},
	}
	for _, testCase := range testCases {
		results, err := reg.SearchServices(
			context.Background(),
			testCase.query,
			testCase.category,
		)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, result := range results {
			if result.Name == testCase.want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf(
				"SearchServices(%q, %q) = %#v, missing %q",
				testCase.query,
				testCase.category,
				results,
				testCase.want,
			)
		}
	}
}

func TestExternalEmbeddedServiceOverrideRequiresExactGrant(t *testing.T) {
	tests := []struct {
		name        string
		permissions []string
		grants      []string
		wantError   string
	}{
		{
			name:        "missing declaration",
			permissions: []string{"network:app"},
			grants:      []string{"network:app"},
			wantError:   "without declaring catalog permission",
		},
		{
			name: "ungranted declaration",
			permissions: []string{
				"network:app",
				"service-override:traefik",
			},
			grants:    []string{"network:app"},
			wantError: "requires ungranted catalog permission",
		},
		{
			name: "explicit declaration and grant",
			permissions: []string{
				"network:app",
				"service-override:traefik",
			},
			grants: []string{
				"network:app",
				"service-override:traefik",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sourceRoot := t.TempDir()
			writeCatalogService(
				t,
				sourceRoot,
				"traefik",
				test.permissions,
			)
			cfg := DefaultSourceConfig()
			cfg.Sources = []Source{{
				Name:     "external",
				Type:     "local",
				Path:     sourceRoot,
				Priority: 100,
				Enabled:  true,
				Trust: TrustLevel{
					AllowCatalogPermissions: test.grants,
					AllowedRegistries:       []string{"docker.io"},
				},
			}}
			reg, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}

			services, err := reg.ListServices(context.Background())
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("ListServices() error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, service := range services {
				if service.Name == "traefik" {
					if service.Source != "external" {
						t.Fatalf("traefik source = %q, want external", service.Source)
					}
					return
				}
			}
			t.Fatal("overridden traefik service is missing")
		})
	}
}

func TestUniqueExternalServiceRejectsUnusedOverridePermission(t *testing.T) {
	sourceRoot := t.TempDir()
	writeCatalogService(
		t,
		sourceRoot,
		"unique-service",
		[]string{
			"network:app",
			"service-override:unique-service",
		},
	)
	cfg := DefaultSourceConfig()
	cfg.Sources = []Source{{
		Name:     "external",
		Type:     "local",
		Path:     sourceRoot,
		Priority: 100,
		Enabled:  true,
		Trust: TrustLevel{
			AllowCatalogPermissions: []string{
				"network:app",
				"service-override:unique-service",
			},
			AllowedRegistries: []string{"docker.io"},
		},
	}}
	reg, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	_, err = reg.ListServices(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unused catalog permission") {
		t.Fatalf("ListServices() error = %v, want unused override rejection", err)
	}
}

func writeCatalogService(
	t *testing.T,
	root string,
	name string,
	permissions []string,
) {
	t.Helper()
	serviceDir := filepath.Join(root, name)
	if err := os.MkdirAll(serviceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var permissionLines strings.Builder
	for _, permission := range permissions {
		permissionLines.WriteString("  - ")
		permissionLines.WriteString(permission)
		permissionLines.WriteByte('\n')
	}
	body := "apiVersion: sdbx.one/v1\n" +
		"kind: Service\n" +
		"applicationAuth:\n" +
		"  mode: none\n" +
		"metadata:\n" +
		"  name: " + name + "\n" +
		"  version: 1.0.0\n" +
		"  category: utility\n" +
		"  description: Synthetic external service\n" +
		"permissions:\n" + permissionLines.String() +
		"spec:\n" +
		"  image:\n" +
		"    repository: alpine\n" +
		"    tag: latest\n" +
		"  container:\n" +
		"    name_template: sdbx-{{ .Name }}\n" +
		"  networking:\n" +
		"    networks:\n" +
		"      - name: app\n" +
		"routing:\n" +
		"  enabled: false\n" +
		"conditions:\n" +
		"  always: true\n"
	if err := os.WriteFile(
		filepath.Join(serviceDir, "service.yaml"),
		[]byte(body),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}
