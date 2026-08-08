package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
)

func TestSecretsGenerate(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "sdbx-secrets-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Change to temp directory
	oldCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldCwd)
	writeSecretsCommandTestProject(t, tmpDir)

	// Create secrets directory
	secretsDir := filepath.Join(tmpDir, "secrets")
	if err := os.MkdirAll(secretsDir, 0o755); err != nil {
		t.Fatalf("Failed to create secrets dir: %v", err)
	}

	// Save original stdout
	oldStdout := os.Stdout
	defer func() { os.Stdout = oldStdout }()

	// Capture output
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Execute generate command
	if err := runSecretsGenerate(secretsGenerateCmd, []string{}); err != nil {
		t.Fatalf("runSecretsGenerate failed: %v", err)
	}

	// Close writer and read output
	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify output
	if !strings.Contains(output, "Secrets generated") {
		t.Errorf("Output should confirm secrets generated: %s", output)
	}

	// Verify secrets were created
	entries, err := os.ReadDir(secretsDir)
	if err != nil {
		t.Fatalf("Failed to read secrets dir: %v", err)
	}
	if len(entries) == 0 {
		t.Error("Secrets directory should contain files")
	}
}

func TestSecretsList(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "sdbx-secrets-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Change to temp directory
	oldCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldCwd)
	writeSecretsCommandTestProject(t, tmpDir)

	// Create secrets directory with test secrets
	secretsDir := filepath.Join(tmpDir, "secrets")
	if err := os.MkdirAll(secretsDir, 0o755); err != nil {
		t.Fatalf("Failed to create secrets dir: %v", err)
	}

	// Create a configured secret
	if err := os.WriteFile(filepath.Join(secretsDir, "test_secret.txt"), []byte("test_value"), 0o600); err != nil {
		t.Fatalf("Failed to write test secret: %v", err)
	}

	// Create an empty secret
	if err := os.WriteFile(filepath.Join(secretsDir, "empty_secret.txt"), []byte(""), 0o600); err != nil {
		t.Fatalf("Failed to write empty secret: %v", err)
	}

	// Save original stdout
	oldStdout := os.Stdout
	defer func() { os.Stdout = oldStdout }()

	// Capture output
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Execute list command
	if err := runSecretsList(secretsListCmd, []string{}); err != nil {
		t.Fatalf("runSecretsList failed: %v", err)
	}

	// Close writer and read output
	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify output contains header
	if !strings.Contains(output, "SDBX Secrets") {
		t.Error("Output should contain header")
	}
}

func TestSecretsListJSON(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "sdbx-secrets-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Change to temp directory
	oldCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldCwd)
	writeSecretsCommandTestProject(t, tmpDir)

	// Create secrets directory with test secrets
	secretsDir := filepath.Join(tmpDir, "secrets")
	if err := os.MkdirAll(secretsDir, 0o755); err != nil {
		t.Fatalf("Failed to create secrets dir: %v", err)
	}

	// Create a configured secret
	if err := os.WriteFile(filepath.Join(secretsDir, "configured.txt"), []byte("value"), 0o600); err != nil {
		t.Fatalf("Failed to write test secret: %v", err)
	}

	// Save original stdout and json flag
	oldStdout := os.Stdout
	oldJSON := jsonOut
	defer func() {
		os.Stdout = oldStdout
		jsonOut = oldJSON
	}()

	// Enable JSON output
	jsonOut = true

	// Capture output
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Execute list command
	if err := runSecretsList(secretsListCmd, []string{}); err != nil {
		t.Fatalf("runSecretsList failed: %v", err)
	}

	// Close writer and read output
	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Parse JSON output
	var status map[string]bool
	if err := json.Unmarshal([]byte(output), &status); err != nil {
		t.Fatalf("Failed to parse JSON output: %v\nOutput: %s", err, output)
	}

	// Verify JSON structure
	if len(status) == 0 {
		t.Error("JSON output should contain secrets")
	}
}

func TestSecretsRotateCommandIsUnavailable(t *testing.T) {
	for _, command := range secretsCmd.Commands() {
		if command.Name() == "rotate" {
			t.Fatal("generic secret rotation command is still registered")
		}
	}
}

func TestSecretsShowRequiresExactHumanRevealConfirmation(t *testing.T) {
	previousConfirm := secretsRevealConfirm
	previousJSON := jsonOut
	t.Cleanup(func() {
		secretsRevealConfirm = previousConfirm
		jsonOut = previousJSON
	})

	jsonOut = false
	for _, confirmation := range []string{"", "yes", "Reveal"} {
		secretsRevealConfirm = confirmation
		err := runSecretsShow(secretsShowCmd, []string{"qbittorrent"})
		if err == nil || !strings.Contains(err.Error(), "--confirm reveal") {
			t.Fatalf("confirmation %q error = %v", confirmation, err)
		}
	}

	secretsRevealConfirm = "reveal"
	jsonOut = true
	err := runSecretsShow(secretsShowCmd, []string{"qbittorrent"})
	if err == nil || !strings.Contains(err.Error(), "--json is not supported") {
		t.Fatalf("JSON reveal error = %v", err)
	}
}

func TestShowArrAdminPasswordUsesManagedCredential(t *testing.T) {
	projectDir := t.TempDir()
	writeSecretsCommandTestProject(t, projectDir)
	secretsDir := filepath.Join(projectDir, "secrets")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(secretsDir, "sonarr_admin_password.txt"),
		[]byte("synthetic-managed-password"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	oldCwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(projectDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldCwd) })

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	t.Cleanup(func() { os.Stdout = oldStdout })

	if err := showArrAdminPassword("sonarr"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(output), "sdbx-admin") ||
		!strings.Contains(string(output), "synthetic-managed-password") {
		t.Fatalf("managed credential output = %q", output)
	}
}

func TestShowCobaltAPIKeyUsesManagedKeyMap(t *testing.T) {
	previousConfirm := secretsRevealConfirm
	previousJSON := jsonOut
	t.Cleanup(func() {
		secretsRevealConfirm = previousConfirm
		jsonOut = previousJSON
	})
	secretsRevealConfirm = "reveal"
	jsonOut = false

	projectDir := t.TempDir()
	writeSecretsCommandTestProject(t, projectDir)
	secretsDir := filepath.Join(projectDir, "secrets")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const key = "00000000-0000-4000-8000-000000000000"
	if err := os.WriteFile(
		filepath.Join(secretsDir, "cobalt_keys.txt"),
		[]byte(`{"`+key+`":{"name":"synthetic"}}`),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	oldCwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(projectDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldCwd) })

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	t.Cleanup(func() { os.Stdout = oldStdout })

	if err := runSecretsShow(secretsShowCmd, []string{"cobalt"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(output), key) ||
		!strings.Contains(
			string(output),
			"https://cobalt.tools/settings/instances",
		) {
		t.Fatalf("Cobalt recovery output = %q", output)
	}
}

func TestConfiguredSecretsDirUsesProjectIntentAndRequiresProject(t *testing.T) {
	projectDir := t.TempDir()
	customDir := filepath.Join(projectDir, "private", "credentials")
	cfg := config.DefaultConfig()
	cfg.SecretsPath = customDir
	if err := cfg.Save(filepath.Join(projectDir, ".sdbx.yaml")); err != nil {
		t.Fatal(err)
	}
	oldCwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(projectDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldCwd) })

	resolved, err := configuredSecretsDir()
	if err != nil {
		t.Fatal(err)
	}
	if resolved != customDir {
		t.Fatalf("configured secrets dir = %q, want %q", resolved, customDir)
	}

	if runtime.GOOS != "windows" {
		outside := t.TempDir()
		if err := os.Mkdir(
			filepath.Join(outside, "credentials"),
			0o700,
		); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(projectDir, "redirect")); err != nil {
			t.Fatal(err)
		}
		cfg.SecretsPath = filepath.Join("redirect", "credentials")
		if err := cfg.Save(filepath.Join(projectDir, ".sdbx.yaml")); err != nil {
			t.Fatal(err)
		}
		if _, err := configuredSecretsDir(); err == nil ||
			!strings.Contains(err.Error(), "symlink") {
			t.Fatalf("redirected secrets_path error = %v", err)
		}
	}

	empty := t.TempDir()
	if err := os.Chdir(empty); err != nil {
		t.Fatal(err)
	}
	if _, err := configuredSecretsDir(); err == nil {
		t.Fatal("credential command accepted a directory without an SDBX project")
	}
}

func TestQBTTempPasswordRegex(t *testing.T) {
	tests := []struct {
		name string
		log  string
		want string
	}{
		{
			name: "single startup line",
			log:  "The WebUI administrator password was not set. A temporary password is provided for this session: ZDINDukHe\nYou should set your own password in program preferences.",
			want: "ZDINDukHe",
		},
		{
			name: "trailing newline only",
			log:  "A temporary password is provided for this session: UIjIMReFj\n",
			want: "UIjIMReFj",
		},
		{
			name: "multiple restarts — latest wins",
			log: strings.Join([]string{
				"A temporary password is provided for this session: oldOldOld",
				"... container restart ...",
				"A temporary password is provided for this session: newNewNew",
			}, "\n"),
			want: "newNewNew",
		},
		{
			name: "no match",
			log:  "qBittorrent v5.0.0 started\nWebUI listening on :8080\n",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := qbtTempPasswordRE.FindAllStringSubmatch(tt.log, -1)
			var got string
			if len(matches) > 0 {
				got = matches[len(matches)-1][1]
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFBAdminPasswordRegex(t *testing.T) {
	generatedPassword := "DcPE" + "53At" + "Xely" + "0x9d"
	tests := []struct {
		name     string
		log      string
		wantUser string
		wantPass string
	}{
		{
			name:     "first-launch line",
			log:      "2026/05/06 18:45:50 Performing quick setup\n2026/05/06 18:45:50 User 'admin' initialized with randomly generated password: " + generatedPassword + "\n2026/05/06 18:45:50 Listening on [::]:80",
			wantUser: "admin",
			wantPass: generatedPassword,
		},
		{
			name:     "non-default username",
			log:      "User 'maiko' initialized with randomly generated password: aB3xZqR1\n",
			wantUser: "maiko",
			wantPass: "aB3xZqR1",
		},
		{
			name:     "no match — already initialized",
			log:      "Using config file: /config/settings.json\nUsing database: /database/filebrowser.db\nListening on [::]:80\n",
			wantUser: "",
			wantPass: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := fbAdminPasswordRE.FindAllStringSubmatch(tt.log, -1)
			var gotUser, gotPass string
			if len(matches) > 0 {
				gotUser = matches[len(matches)-1][1]
				gotPass = matches[len(matches)-1][2]
			}
			if gotUser != tt.wantUser || gotPass != tt.wantPass {
				t.Errorf("got (%q, %q), want (%q, %q)", gotUser, gotPass, tt.wantUser, tt.wantPass)
			}
		})
	}
}

func writeSecretsCommandTestProject(t *testing.T, projectDir string) {
	t.Helper()
	cfg := config.DefaultConfig()
	if err := cfg.Save(filepath.Join(projectDir, ".sdbx.yaml")); err != nil {
		t.Fatalf("save test project configuration: %v", err)
	}
}
