package registry

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/get-sdbx/sdbx/internal/config"
)

type fakeImageResolver struct{}

func (fakeImageResolver) Resolve(
	_ context.Context,
	repository, tag string,
) (ResolvedImage, error) {
	indexDigest := testDigest(repository + ":" + tag)
	return ResolvedImage{
		Digest: indexDigest,
		PlatformDigests: map[string]string{
			"linux/amd64":    testDigest(repository + ":" + tag + ":linux/amd64"),
			"linux/arm64/v8": testDigest(repository + ":" + tag + ":linux/arm64/v8"),
		},
	}, nil
}

func TestGenerateLockFileV2RecordsCompleteProvenance(t *testing.T) {
	reg := NewEmbeddedOnlyRegistry()
	reg.resolver = NewResolver(reg)
	cfg := config.DefaultConfig()
	cfg.VPNEnabled = true
	cfg.VPNProvider = "mullvad"

	lock, warnings, err := reg.GenerateLockFileWithOptions(
		context.Background(),
		cfg,
		LockOptions{
			CLIVersion:    "v1.0.0",
			ImageResolver: fakeImageResolver{},
		},
	)
	if err != nil {
		t.Fatalf("GenerateLockFileWithOptions failed: %v", err)
	}
	if lock.Metadata.Version != lockSchemaVersion {
		t.Fatalf("lock version = %d", lock.Metadata.Version)
	}
	if !isSHA256Digest(lock.Metadata.ConfigDigest) ||
		!isSHA256Digest(lock.Metadata.CatalogDigest) {
		t.Fatalf("lock metadata digests = %#v", lock.Metadata)
	}
	embedded, ok := lock.Sources["embedded"]
	if !ok || !embedded.Verified || !isSHA256Digest(embedded.Digest) {
		t.Fatalf("embedded provenance = %#v", embedded)
	}
	if len(lock.Services) == 0 || len(lock.InstallOrder) != len(lock.Services) {
		t.Fatalf("locked services/order = %d/%d", len(lock.Services), len(lock.InstallOrder))
	}
	for name, service := range lock.Services {
		if !isSHA256Digest(service.DefinitionDigest) ||
			!isSHA256Digest(service.Image.Digest) {
			t.Fatalf("service %s provenance = %#v", name, service)
		}
		if service.Image.PlatformDigests["linux/amd64"] == "" ||
			service.Image.PlatformDigests["linux/arm64/v8"] == "" {
			t.Fatalf("service %s platform digests = %#v", name, service.Image.PlatformDigests)
		}
	}
	if len(warnings) == 0 {
		t.Fatal("expected security warnings for sensitive built-in services")
	}
	if err := ValidateLockFile(lock, true); err != nil {
		t.Fatalf("ValidateLockFile failed: %v", err)
	}
}

func TestLockGenerationIsDeterministicExceptTimestamp(t *testing.T) {
	reg := NewEmbeddedOnlyRegistry()
	reg.resolver = NewResolver(reg)
	firstConfig := config.DefaultConfig()
	firstConfig.Addons = []string{"sonarr", "radarr"}
	secondConfig := config.DefaultConfig()
	secondConfig.Addons = []string{"radarr", "sonarr"}
	firstConfig.AdminUser = "admin-one"
	firstConfig.AdminPasswordHash = "$argon2id$hash-one"
	firstConfig.ProjectDir = "/private/one"
	secondConfig.AdminUser = "admin-two"
	secondConfig.AdminPasswordHash = "$argon2id$hash-two"
	secondConfig.ProjectDir = "/private/two"

	options := LockOptions{CLIVersion: "v1.0.0", ImageResolver: fakeImageResolver{}}
	first, _, err := reg.GenerateLockFileWithOptions(context.Background(), firstConfig, options)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := reg.GenerateLockFileWithOptions(context.Background(), secondConfig, options)
	if err != nil {
		t.Fatal(err)
	}
	first.Metadata.GeneratedAt = time.Time{}
	second.Metadata.GeneratedAt = time.Time{}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("equivalent configs produced different locks:\nfirst=%#v\nsecond=%#v", first, second)
	}
}

func TestReleaseLockRejectsLocalSourceWithoutExplicitOverride(t *testing.T) {
	sourceRoot := t.TempDir()
	reg, err := New(&SourceConfig{
		APIVersion: APIVersion,
		Kind:       KindSourceConfig,
		Sources: []Source{{
			Name:     "development",
			Type:     "local",
			Path:     sourceRoot,
			Priority: 100,
			Enabled:  true,
		}},
		Cache: CacheConfig{Directory: filepath.Join(t.TempDir(), "cache")},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = reg.GenerateLockFileWithOptions(
		context.Background(),
		config.DefaultConfig(),
		LockOptions{CLIVersion: "v1.0.0", ImageResolver: fakeImageResolver{}},
	)
	if err == nil || !strings.Contains(err.Error(), "local source") {
		t.Fatalf("release lock error = %v", err)
	}
}

func TestLockDiffDetectsDefinitionAndConfigChanges(t *testing.T) {
	reg := NewEmbeddedOnlyRegistry()
	existing := minimalValidLock()
	current := minimalValidLock()
	current.Metadata.ConfigDigest = testDigest("changed-config")
	service := current.Services["test"]
	service.DefinitionDigest = testDigest("changed-definition")
	current.Services["test"] = service

	diffs := reg.DiffLockFiles(existing, current)
	if len(diffs) != 2 {
		t.Fatalf("diffs = %#v, want config and service changes", diffs)
	}
}

func TestLockDiffDetectsSourceCatalogAndImageChanges(t *testing.T) {
	reg := NewEmbeddedOnlyRegistry()
	existing := minimalValidLock()
	current := minimalValidLock()
	current.Metadata.CatalogVersion = testDigest("changed-catalog-version")
	current.Metadata.CatalogDigest = testDigest("changed-catalog")

	source := current.Sources["embedded"]
	source.Digest = testDigest("changed-source")
	current.Sources["embedded"] = source

	service := current.Services["test"]
	service.Image.Digest = testDigest("changed-image-index")
	service.Image.PlatformDigest = testDigest("changed-platform")
	service.Image.PlatformDigests["linux/arm64"] = service.Image.PlatformDigest
	current.Services["test"] = service

	diffs := reg.DiffLockFiles(existing, current)
	joined := make([]string, 0, len(diffs))
	for _, diff := range diffs {
		joined = append(joined, diff.Description)
	}
	description := strings.Join(joined, "\n")
	for _, expected := range []string{
		"Catalog version changed",
		"Catalog digest changed",
		"Source embedded identity changed",
		"Service test provenance changed",
	} {
		if !strings.Contains(description, expected) {
			t.Errorf("diffs do not contain %q:\n%s", expected, description)
		}
	}
}

func TestSelectPlatformDigestUsesUnambiguousVariant(t *testing.T) {
	digest := testDigest("arm64-v8")
	platform, got, err := selectPlatformDigest(
		"linux/arm64",
		map[string]string{"linux/arm64/v8": digest},
	)
	if err != nil {
		t.Fatal(err)
	}
	if platform != "linux/arm64/v8" || got != digest {
		t.Fatalf("selection = %s %s", platform, got)
	}

	_, _, err = selectPlatformDigest("linux/arm64", map[string]string{
		"linux/arm64/v8": testDigest("v8"),
		"linux/arm64/v9": testDigest("v9"),
	})
	if err == nil {
		t.Fatal("ambiguous platform variants were accepted")
	}
}

func TestValidateGeneratedFilesDetectsRuntimeDrift(t *testing.T) {
	projectDir := t.TempDir()
	configDir := filepath.Join(projectDir, "configs")
	paths := writeRequiredGeneratedFiles(t, projectDir, configDir)
	digests, err := RecordGeneratedFiles(projectDir, configDir, paths)
	if err != nil {
		t.Fatal(err)
	}
	lock := minimalValidLock()
	lock.GeneratedFiles = digests
	if err := ValidateGeneratedFiles(projectDir, configDir, lock); err != nil {
		t.Fatalf("valid generated files rejected: %v", err)
	}

	composePath := filepath.Join(projectDir, "compose.yaml")
	if err := os.WriteFile(composePath, []byte("services:\n  injected: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateGeneratedFiles(projectDir, configDir, lock); err == nil ||
		!strings.Contains(err.Error(), "differs from .sdbx.lock") {
		t.Fatalf("runtime drift error = %v", err)
	}
}

func TestValidateGeneratedFilesRejectsSymlink(t *testing.T) {
	projectDir := t.TempDir()
	configDir := filepath.Join(projectDir, "configs")
	paths := writeRequiredGeneratedFiles(t, projectDir, configDir)
	digests, err := RecordGeneratedFiles(projectDir, configDir, paths)
	if err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(projectDir, "victim.yaml")
	if err := os.WriteFile(victim, []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(projectDir, "compose.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(projectDir, "compose.yaml")); err != nil {
		t.Fatal(err)
	}
	lock := minimalValidLock()
	lock.GeneratedFiles = digests
	if err := ValidateGeneratedFiles(projectDir, configDir, lock); err == nil ||
		!strings.Contains(err.Error(), "symbolic links") {
		t.Fatalf("symlink validation error = %v", err)
	}
}

func TestValidateGeneratedFilesSupportsExternalConfigRoot(t *testing.T) {
	root := t.TempDir()
	projectDir := filepath.Join(root, "project")
	configDir := filepath.Join(root, "external-config")
	for _, dir := range []string{projectDir, configDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	paths := writeRequiredGeneratedFiles(t, projectDir, configDir)
	digests, err := RecordGeneratedFiles(projectDir, configDir, paths)
	if err != nil {
		t.Fatal(err)
	}
	lock := minimalValidLock()
	lock.GeneratedFiles = digests
	if err := ValidateGeneratedFiles(projectDir, configDir, lock); err != nil {
		t.Fatalf("external config root rejected: %v", err)
	}

	policyPath := filepath.Join(configDir, "authelia", "configuration.yml")
	if err := os.WriteFile(policyPath, []byte("access_control: {default_policy: bypass}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateGeneratedFiles(projectDir, configDir, lock); err == nil ||
		!strings.Contains(err.Error(), "@config/authelia/configuration.yml differs") {
		t.Fatalf("external policy drift error = %v", err)
	}
}

func writeRequiredGeneratedFiles(t *testing.T, projectDir, configDir string) []string {
	t.Helper()
	files := map[string]string{
		"compose.yaml": "services: {}\n",
		".env":         "SDBX_DOMAIN=example.test\n",
		ConfigGeneratedFile("authelia/configuration.yml"):      "access_control: {default_policy: deny}\n",
		ConfigGeneratedFile("traefik/traefik.yml"):             "entryPoints: {}\n",
		ConfigGeneratedFile("traefik/dynamic/middlewares.yml"): "http: {middlewares: {}}\n",
	}
	paths := make([]string, 0, len(files))
	for key, body := range files {
		rootKind, relative, err := splitGeneratedFileKey(key)
		if err != nil {
			t.Fatal(err)
		}
		root := projectDir
		if rootKind == generatedFileRootConfig {
			root = configDir
		}
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, key)
	}
	sort.Strings(paths)
	return paths
}

func TestParseLockFileRejectsLegacySchema(t *testing.T) {
	_, err := NewLoader().ParseLockFile([]byte(`
apiVersion: sdbx.one/v1
kind: LockFile
metadata:
  version: 1
`))
	if err == nil || !strings.Contains(err.Error(), "unsupported lock schema version 1") {
		t.Fatalf("ParseLockFile error = %v", err)
	}
}

func TestNewLockedImageResolverRejectsMissingDigests(t *testing.T) {
	lock := minimalValidLock()
	service := lock.Services["test"]
	service.Image.Digest = ""
	lock.Services["test"] = service
	if _, err := NewLockedImageResolver(lock); err == nil {
		t.Fatal("NewLockedImageResolver accepted a mutable image")
	}
}

func TestLiveCoreCatalogImageDigests(t *testing.T) {
	if os.Getenv("SDBX_LIVE_OCI_TEST") != "1" {
		t.Skip("set SDBX_LIVE_OCI_TEST=1 to query live OCI registries")
	}
	reg := NewEmbeddedOnlyRegistry()
	reg.resolver = NewResolver(reg)
	lock, _, err := reg.GenerateLockFileWithOptions(
		context.Background(),
		config.DefaultConfig(),
		LockOptions{
			CLIVersion:    "test",
			ImageResolver: NewDockerImageDigestResolver(),
		},
	)
	if err != nil {
		t.Fatalf("live lock generation failed: %v", err)
	}
	for name, service := range lock.Services {
		if !isSHA256Digest(service.Image.Digest) {
			t.Errorf("%s has no immutable image digest", name)
		}
		if service.Image.PlatformDigests["linux/amd64"] == "" {
			t.Errorf("%s has no linux/amd64 image", name)
		}
		if service.Image.PlatformDigests["linux/arm64"] == "" &&
			service.Image.PlatformDigests["linux/arm64/v8"] == "" {
			t.Errorf("%s has no linux/arm64 image", name)
		}
	}
}

func TestLiveOfficialCatalogImageDigests(t *testing.T) {
	if os.Getenv("SDBX_LIVE_OCI_ALL") != "1" {
		t.Skip("set SDBX_LIVE_OCI_ALL=1 to audit every official image")
	}
	source := NewEmbeddedSource()
	definitions, err := source.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(definitions, func(i, j int) bool {
		return definitions[i].Metadata.Name < definitions[j].Metadata.Name
	})
	resolver := NewDockerImageDigestResolver()
	for _, definition := range definitions {
		image, err := resolver.Resolve(
			context.Background(),
			definition.Spec.Image.Repository,
			definition.Spec.Image.Tag,
		)
		if err != nil {
			t.Errorf("%s: %v", definition.Metadata.Name, err)
			continue
		}
		if image.PlatformDigests["linux/amd64"] == "" {
			t.Errorf("%s has no linux/amd64 image", definition.Metadata.Name)
		}
		if image.PlatformDigests["linux/arm64"] == "" &&
			image.PlatformDigests["linux/arm64/v8"] == "" {
			t.Errorf("%s has no linux/arm64 image", definition.Metadata.Name)
		}
	}
}

func minimalValidLock() *LockFile {
	digest := testDigest("value")
	return &LockFile{
		APIVersion: APIVersion,
		Kind:       KindLockFile,
		Metadata: LockFileMetadata{
			Version:        lockSchemaVersion,
			GeneratedAt:    time.Now().UTC(),
			CLIVersion:     "v1.0.0",
			CatalogVersion: digest,
			ConfigDigest:   digest,
			CatalogDigest:  digest,
		},
		Sources: map[string]LockedSource{
			"embedded": {
				Type:     "embedded",
				Ref:      digest,
				Commit:   digest,
				Digest:   digest,
				Verified: true,
			},
		},
		Services: map[string]LockedService{
			"test": {
				Source:            "embedded",
				DefinitionVersion: "1.0.0",
				DefinitionDigest:  digest,
				Image: LockedImage{
					Registry:       "docker.io",
					Repository:     "alpine",
					Tag:            "3.23",
					Digest:         digest,
					Platform:       "linux/arm64",
					PlatformDigest: digest,
					PlatformDigests: map[string]string{
						"linux/arm64": digest,
					},
				},
				ResolvedFrom: "embedded://services/test/service.yaml",
			},
		},
		InstallOrder: []string{"test"},
	}
}

func testDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", sum[:])
}
