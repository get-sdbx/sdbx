package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestCommandContextPreservesCancellation(t *testing.T) {
	if commandContext(nil) == nil {
		t.Fatal("nil command did not receive a safe context")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	command := &cobra.Command{}
	command.SetContext(ctx)
	if err := commandContext(command).Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("command context error = %v, want cancellation", err)
	}
}

func TestWriteCLIErrorJSON(t *testing.T) {
	var output bytes.Buffer
	writeCLIError(&output, errors.New("operation failed"), true)

	const expected = `{"error":{"code":"command_failed","message":"operation failed"}}`
	if strings.TrimSpace(output.String()) != expected {
		t.Fatalf("JSON error = %q, want %q", output.String(), expected)
	}
}

func TestWriteCLIErrorPlainText(t *testing.T) {
	var output bytes.Buffer
	writeCLIError(&output, errors.New("operation failed"), false)

	if output.String() != "Error: operation failed\n" {
		t.Fatalf("plain error = %q", output.String())
	}
}

func TestReportedCLIErrorSuppressesDuplicateRendererAndPreservesCause(t *testing.T) {
	cause := errors.New("operation failed")
	reported := markCLIErrorReported(cause)
	if shouldRenderCLIError(reported) {
		t.Fatal("reported error would be rendered twice")
	}
	if !errors.Is(reported, cause) {
		t.Fatal("reported error does not preserve its cause")
	}
	if !shouldRenderCLIError(cause) {
		t.Fatal("ordinary error renderer was suppressed")
	}
}

func TestCLIErrorRedactsSensitiveAssignments(t *testing.T) {
	message := redactCLIError(
		"password=correct-horse token:abc123 secret = hunter2 identity=/tmp/key",
	)
	for _, secret := range []string{"correct-horse", "abc123", "hunter2", "/tmp/key"} {
		if strings.Contains(message, secret) {
			t.Fatalf("redacted error still contains %q: %s", secret, message)
		}
	}
	if count := strings.Count(message, "[REDACTED]"); count != 4 {
		t.Fatalf("redacted placeholder count = %d, want 4: %s", count, message)
	}
}

func TestValidateOutputModeRejectsUnsupportedCommand(t *testing.T) {
	previous := jsonOut
	jsonOut = true
	t.Cleanup(func() { jsonOut = previous })

	err := validateOutputMode(upCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--json is not supported") {
		t.Fatalf("unsupported JSON error = %v", err)
	}
	if err := validateOutputMode(statusCmd, nil); err != nil {
		t.Fatalf("supported JSON command rejected: %v", err)
	}
	if err := validateOutputMode(tunnelRoutesCmd, nil); err != nil {
		t.Fatalf("tunnel route JSON command rejected: %v", err)
	}
	if err := validateOutputMode(secretsShowCmd, nil); err == nil {
		t.Fatal("plaintext credential recovery still supports JSON")
	}
}

func TestJSONRequested(t *testing.T) {
	previous := jsonOut
	jsonOut = false
	t.Cleanup(func() { jsonOut = previous })

	if !jsonRequested([]string{"status", "--json"}) {
		t.Fatal("--json was not detected")
	}
	if !jsonRequested([]string{"--json=true", "status"}) {
		t.Fatal("--json=true was not detected")
	}
	if jsonRequested([]string{"--json=false", "status"}) {
		t.Fatal("--json=false was treated as enabled")
	}
}

func TestInitConfigRejectsImplicitEnvironmentOverrides(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	t.Setenv("SDBX_DOMAIN", "environment.example.test")
	path := filepath.Join(t.TempDir(), ".sdbx.yaml")
	if err := os.WriteFile(
		path,
		[]byte("domain: file.example.test\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	previousConfigFile := cfgFile
	cfgFile = path
	t.Cleanup(func() { cfgFile = previousConfigFile })

	initConfig()

	if got := viper.GetString("domain"); got != "file.example.test" {
		t.Fatalf("domain = %q, want explicit file value", got)
	}
}

func TestPrepareCommandRecoversTransactionBeforeProjectIntent(t *testing.T) {
	projectDir := t.TempDir()
	t.Chdir(projectDir)
	target := filepath.Join(projectDir, ".sdbx.yaml")
	transactionRoot := filepath.Join(projectDir, ".sdbx-init-transaction")
	source := filepath.Join(transactionRoot, "stage", "project", ".sdbx.yaml")
	backup := filepath.Join(transactionRoot, "rollback", "000000")
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(backup), 0o700); err != nil {
		t.Fatal(err)
	}
	const (
		original = "original project intent\n"
		promoted = "partially promoted project intent\n"
	)
	for path, body := range map[string]string{
		target: promoted,
		source: promoted,
		backup: original,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	digest := func(body string) string {
		sum := sha256.Sum256([]byte(body))
		return fmt.Sprintf("sha256:%x", sum)
	}
	manifest := map[string]any{
		"version":      2,
		"state":        "promoting",
		"project_root": projectDir,
		"secrets_root": filepath.Join(projectDir, "secrets"),
		"allowed_roots": []string{
			projectDir,
		},
		"entries": []map[string]any{{
			"kind":          "file",
			"source":        source,
			"target":        target,
			"backup":        backup,
			"existed":       true,
			"original_mode": 0o600,
			"desired_mode":  0o600,
			"staged_digest": digest(promoted),
			"backup_digest": digest(original),
		}},
	}
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(transactionRoot, "manifest.json"),
		manifestData,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	previousJSON := jsonOut
	jsonOut = false
	t.Cleanup(func() { jsonOut = previousJSON })
	if err := prepareCommand(configGetCmd, nil); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != original {
		t.Fatalf("project intent was not recovered before command: %q", body)
	}
	if _, err := os.Lstat(transactionRoot); !os.IsNotExist(err) {
		t.Fatalf("completed recovery journal still exists: %v", err)
	}
}

func TestRestartUsageAdvertisesMultipleServices(t *testing.T) {
	if restartCmd.Use != "restart [service...]" {
		t.Fatalf("restart usage = %q", restartCmd.Use)
	}
}
