package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
	"gopkg.in/yaml.v3"
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

func TestLockDiagnosticsEscapeUntrustedLockNames(t *testing.T) {
	for _, mode := range []string{"verify", "diff"} {
		t.Run(mode, func(t *testing.T) {
			projectDir := setupAddonCommandProject(t, config.DefaultConfig())
			loader := registry.NewLoader()
			path := filepath.Join(projectDir, ".sdbx.lock")
			lock, err := loader.LoadLockFile(path)
			if err != nil {
				t.Fatal(err)
			}
			name := "injected\x1b[2J\nFORGED\r\u202e"
			lock.Services[name] = lock.Services["traefik"]
			lock.InstallOrder = append(lock.InstallOrder, name)
			if err := loader.SaveLockFile(path, lock); err != nil {
				t.Fatal(err)
			}
			output := captureAddonOutput(t, func() error {
				if mode == "verify" {
					if err := runLockVerify(lockVerifyCmd, nil); err == nil {
						t.Error("tampered lock was accepted")
					}
					return nil
				}
				return runLockDiff(lockDiffCmd, nil)
			})
			for _, control := range []string{"\x1b[2J", "\nFORGED", "\r", "\u202e"} {
				if strings.Contains(output, control) {
					t.Errorf("lock diagnostic contains terminal control %q", control)
				}
			}
			if !strings.Contains(output, `injected\x1B[2J\nFORGED\r\u202E`) {
				t.Errorf("lock diagnostic did not preserve the escaped service name: %q", output)
			}
		})
	}
}

func TestResolutionWarningsEscapeTerminalControls(t *testing.T) {
	output := formatResolutionWarnings([]registry.ResolutionWarning{{
		Service: "service\x1b[2J", Field: "field\r", Message: "message\nFORGED\u202e",
	}})
	if strings.Contains(output, "\x1b") || strings.Contains(output, "\r") ||
		strings.Contains(output, "\nFORGED") || strings.Contains(output, "\u202e") {
		t.Fatalf("warning contains terminal controls: %q", output)
	}
	if !strings.Contains(output, `message\nFORGED\u202E`) {
		t.Fatalf("warning did not preserve escaped content: %q", output)
	}
}

func TestLockVerifyJSONPreservesStructuredDiagnostics(t *testing.T) {
	projectDir := setupAddonCommandProject(t, config.DefaultConfig())
	jsonOut = true
	loader := registry.NewLoader()
	path := filepath.Join(projectDir, ".sdbx.lock")
	lock, err := loader.LoadLockFile(path)
	if err != nil {
		t.Fatal(err)
	}
	name := "injected\x1b[2J\nFORGED"
	lock.Services[name] = lock.Services["traefik"]
	lock.InstallOrder = append(lock.InstallOrder, name)
	if err := loader.SaveLockFile(path, lock); err != nil {
		t.Fatal(err)
	}
	output := captureAddonOutput(t, func() error {
		if err := runLockVerify(lockVerifyCmd, nil); err == nil {
			t.Error("tampered lock was accepted")
		}
		return nil
	})
	var result struct {
		Valid       bool
		Differences []registry.LockFileDiff
	}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatal(err)
	}
	if result.Valid || len(result.Differences) == 0 ||
		!strings.Contains(result.Differences[0].Description, name) {
		t.Fatalf("structured diagnostic changed: %+v", result)
	}
}

func TestLockErrorsEscapeUntrustedMetadata(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprint(malformed), func(t *testing.T) {
			projectDir := setupAddonCommandProject(t, config.DefaultConfig())
			captureAddonOutput(t, func() error { return runGenerate(generateCmd, nil) })
			loader := registry.NewLoader()
			path := filepath.Join(projectDir, ".sdbx.lock")
			lock, err := loader.LoadLockFile(path)
			if err != nil {
				t.Fatal(err)
			}
			name := "missing\x1b[2J\nFORGED\r\u202e"
			if malformed {
				lock.Services[name] = lock.Services["traefik"]
				lock.InstallOrder = append(lock.InstallOrder, name, name)
			} else {
				lock.GeneratedFiles[name] = "sha256:" + strings.Repeat("a", 64)
			}
			data, err := yaml.Marshal(lock)
			if err != nil {
				t.Fatal(err)
			}
			// Imported locks need not have been written by the validating loader.
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			var returned error
			output := captureAddonOutput(t, func() error {
				returned = runLockVerify(lockVerifyCmd, nil)
				return nil
			})
			if returned == nil {
				t.Fatal("invalid runtime metadata was accepted")
			}
			if shouldRenderCLIError(returned) {
				var rendered bytes.Buffer
				writeCLIError(&rendered, returned, false)
				output += rendered.String()
			}
			for _, control := range []string{"\x1b[2J", "\nFORGED", "\r", "\u202e"} {
				if strings.Contains(output, control) {
					t.Errorf("lock error contains terminal control %q", control)
				}
			}
		})
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
