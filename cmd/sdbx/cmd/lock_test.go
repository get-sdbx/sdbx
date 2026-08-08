package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

func TestFormatResolutionWarnings(t *testing.T) {
	output := formatResolutionWarnings([]registry.ResolutionWarning{
		{
			Service: "watch",
			Field:   "spec.volumes[0]",
			Message: "docker socket mount grants host Docker API access",
		},
	})

	if !strings.Contains(output, "watch") {
		t.Fatalf("warning output missing service: %s", output)
	}
	if !strings.Contains(output, "spec.volumes[0]") {
		t.Fatalf("warning output missing field: %s", output)
	}
	if !strings.Contains(output, "docker socket") {
		t.Fatalf("warning output missing message: %s", output)
	}
}

func TestRunGenerateRecordsRuntimeProvenance(t *testing.T) {
	projectDir := setupAddonCommandProject(t, config.DefaultConfig())

	if err := runGenerate(generateCmd, nil); err != nil {
		t.Fatalf("runGenerate failed: %v", err)
	}
	lock, err := registry.NewLoader().LoadLockFile(filepath.Join(projectDir, ".sdbx.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.ValidateGeneratedFiles(
		projectDir,
		config.DefaultConfig().ConfigPath,
		lock,
	); err != nil {
		t.Fatalf("generated runtime provenance is invalid: %v", err)
	}
}

func TestRunLockGenerateAndVerifyAreOfflineAfterRefresh(t *testing.T) {
	projectDir := setupAddonCommandProject(t, config.DefaultConfig())

	if err := runLockGenerate(lockCmd, nil); err != nil {
		t.Fatalf("runLockGenerate failed: %v", err)
	}
	lock, err := registry.NewLoader().LoadLockFile(filepath.Join(projectDir, ".sdbx.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.ValidateGeneratedFiles(
		projectDir,
		config.DefaultConfig().ConfigPath,
		lock,
	); err != nil {
		t.Fatalf("generated runtime provenance is invalid: %v", err)
	}

	imageDigestResolverFactory = func() registry.ImageDigestResolver {
		t.Fatal("lock verify attempted an OCI registry refresh")
		return nil
	}
	if err := runLockVerify(lockVerifyCmd, nil); err != nil {
		t.Fatalf("runLockVerify failed: %v", err)
	}
}

func TestDefaultAndExplicitRefreshImageResolverPolicies(t *testing.T) {
	if _, ok := imageDigestResolverFactory().(*registry.OfficialImageDigestResolver); !ok {
		t.Fatal("default resolver does not use the embedded reviewed image snapshot")
	}
	if _, ok := imageRefreshResolverFactory().(*registry.DockerImageDigestResolver); !ok {
		t.Fatal("explicit refresh resolver does not query current upstream tags")
	}
}

func TestLockPreservesExistingImagePins(t *testing.T) {
	projectDir := setupAddonCommandProject(t, config.DefaultConfig())
	loader := registry.NewLoader()
	before, err := loader.LoadLockFile(filepath.Join(projectDir, ".sdbx.lock"))
	if err != nil {
		t.Fatal(err)
	}

	changedDigest := "sha256:" + strings.Repeat("b", 64)
	changedResolver := fixedCommandImageResolver{
		image: registry.ResolvedImage{
			Digest: changedDigest,
			PlatformDigests: map[string]string{
				"linux/amd64": changedDigest,
				"linux/arm64": changedDigest,
			},
		},
	}
	oldDefaultFactory := imageDigestResolverFactory
	imageDigestResolverFactory = func() registry.ImageDigestResolver {
		return changedResolver
	}
	t.Cleanup(func() {
		imageDigestResolverFactory = oldDefaultFactory
	})
	if err := runLockGenerate(lockCmd, nil); err != nil {
		t.Fatalf("runLockGenerate failed: %v", err)
	}
	preserved, err := loader.LoadLockFile(filepath.Join(projectDir, ".sdbx.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if before.Services["traefik"].Image.Digest !=
		preserved.Services["traefik"].Image.Digest {
		t.Fatal("plain lock generation refreshed an existing image pin")
	}

}

type fixedCommandImageResolver struct {
	image registry.ResolvedImage
}

func (r fixedCommandImageResolver) Resolve(
	_ context.Context,
	_, _ string,
) (registry.ResolvedImage, error) {
	return r.image, nil
}

func TestRunLockVerifyAndUpRejectTamperedCompose(t *testing.T) {
	projectDir := setupAddonCommandProject(t, config.DefaultConfig())
	if err := runGenerate(generateCmd, nil); err != nil {
		t.Fatalf("runGenerate failed: %v", err)
	}
	composePath := filepath.Join(projectDir, "compose.yaml")
	if err := os.WriteFile(
		composePath,
		[]byte("services:\n  attacker-controlled: {}\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	if err := runLockVerify(lockVerifyCmd, nil); err == nil ||
		!strings.Contains(err.Error(), "stale") {
		t.Fatalf("runLockVerify tamper error = %v", err)
	}
	if err := runUp(upCmd, nil); err == nil ||
		!strings.Contains(err.Error(), "generated runtime verification failed") {
		t.Fatalf("runUp tamper error = %v", err)
	}
}

func TestRunLockVerifyAndUpRejectTamperedAuthPolicy(t *testing.T) {
	cfg := config.DefaultConfig()
	projectDir := setupAddonCommandProject(t, cfg)
	if err := runGenerate(generateCmd, nil); err != nil {
		t.Fatalf("runGenerate failed: %v", err)
	}
	policyPath := filepath.Join(
		projectDir,
		"configs",
		"authelia",
		"configuration.yml",
	)
	if err := os.WriteFile(
		policyPath,
		[]byte("access_control:\n  default_policy: bypass\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	if err := runLockVerify(lockVerifyCmd, nil); err == nil ||
		!strings.Contains(err.Error(), "stale") {
		t.Fatalf("runLockVerify policy-tamper error = %v", err)
	}
	if err := runUp(upCmd, nil); err == nil ||
		!strings.Contains(err.Error(), "generated runtime verification failed") {
		t.Fatalf("runUp policy-tamper error = %v", err)
	}
}
