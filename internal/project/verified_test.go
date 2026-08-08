package project

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/generator"
	"github.com/get-sdbx/sdbx/internal/registry"
)

type deterministicResolver struct{}

func (deterministicResolver) Resolve(
	_ context.Context,
	_, _ string,
) (registry.ResolvedImage, error) {
	digest := "sha256:" + strings.Repeat("a", 64)
	return registry.ResolvedImage{
		Digest: digest,
		PlatformDigests: map[string]string{
			"linux/amd64": digest,
			"linux/arm64": digest,
		},
	}, nil
}

func TestVerifyLoadsMatchingLockAndActiveGraph(t *testing.T) {
	ctx := context.Background()
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Domain = "verified.example.test"
	cfg.ProjectDir = projectDir
	if err := cfg.Save(filepath.Join(projectDir, ".sdbx.yaml")); err != nil {
		t.Fatal(err)
	}
	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	lock, _, err := reg.GenerateLockFileWithOptions(ctx, cfg, registry.LockOptions{
		CLIVersion:     "test",
		TargetPlatform: "linux/" + runtime.GOARCH,
		ImageResolver:  deterministicResolver{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.NewLoader().SaveLockFile(
		filepath.Join(projectDir, ".sdbx.lock"),
		lock,
	); err != nil {
		t.Fatal(err)
	}

	verified, err := Verify(ctx, projectDir, cfg, reg, "test")
	if err != nil {
		t.Fatal(err)
	}
	if verified.Lock == nil || verified.Graph == nil {
		t.Fatal("verified project omitted lock or graph")
	}
	for _, name := range []string{
		"authelia",
		"qbittorrent",
		"traefik",
	} {
		if !cfg.ActiveServices[name] {
			t.Fatalf("%s missing from active service map", name)
		}
	}

	cfg.Domain = "stale.example.test"
	if _, err := Verify(ctx, projectDir, cfg, reg, "test"); err == nil ||
		!strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale verification error = %v", err)
	}
}

func TestVerifyRejectsMissingLock(t *testing.T) {
	cfg := config.DefaultConfig()
	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), t.TempDir(), cfg, reg, "test"); err == nil ||
		!strings.Contains(err.Error(), "no .sdbx.lock") {
		t.Fatalf("missing lock error = %v", err)
	}
}

func TestVerifyGeneratedRuntimeRejectsDrift(t *testing.T) {
	ctx := context.Background()
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Domain = "runtime.example.test"
	cfg.ProjectDir = projectDir
	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	lock, _, err := reg.GenerateLockFileWithOptions(ctx, cfg, registry.LockOptions{
		CLIVersion:     "test",
		TargetPlatform: "linux/" + runtime.GOARCH,
		ImageResolver:  deterministicResolver{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.NewLoader().SaveLockFile(
		filepath.Join(projectDir, ".sdbx.lock"),
		lock,
	); err != nil {
		t.Fatal(err)
	}
	if err := generator.NewGeneratorWithLock(
		cfg,
		projectDir,
		reg,
		lock,
		"test",
	).Generate(); err != nil {
		t.Fatal(err)
	}
	if err := registry.NewLoader().SaveLockFile(
		filepath.Join(projectDir, ".sdbx.lock"),
		lock,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyGeneratedRuntime(
		ctx,
		projectDir,
		cfg,
		reg,
		"test",
	); err != nil {
		t.Fatalf("generated runtime verification failed: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(projectDir, "compose.yaml"),
		[]byte("services: {}\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyGeneratedRuntime(
		ctx,
		projectDir,
		cfg,
		reg,
		"test",
	); err == nil || !strings.Contains(err.Error(), "differs from .sdbx.lock") {
		t.Fatalf("runtime drift error = %v", err)
	}
}
