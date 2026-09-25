package secrets

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestGenerateRandomString(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"short", 16},
		{"medium", 32},
		{"long", 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GenerateRandomString(tt.length)
			if err != nil {
				t.Fatalf("GenerateRandomString(%d) error = %v", tt.length, err)
			}
			if len(result) != tt.length {
				t.Errorf("GenerateRandomString(%d) = %d chars, want %d", tt.length, len(result), tt.length)
			}
		})
	}
}

func TestGenerateRandomStringUniqueness(t *testing.T) {
	// Generate multiple strings and ensure they're different
	results := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s, err := GenerateRandomString(32)
		if err != nil {
			t.Fatalf("GenerateRandomString failed: %v", err)
		}
		if results[s] {
			t.Error("GenerateRandomString produced duplicate value")
		}
		results[s] = true
	}
}

func TestGenerateSecrets(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "sdbx-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate secrets
	if err := os.Chmod(tmpDir, 0o777); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}
	if err := GenerateSecrets(tmpDir); err != nil {
		t.Fatalf("GenerateSecrets failed: %v", err)
	}
	dirInfo, err := os.Stat(tmpDir)
	if err != nil {
		t.Fatalf("Stat secrets directory failed: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("secrets directory mode = %o, want 700", got)
	}

	// Verify files were created
	for filename, expectedLen := range SecretFiles {
		path := filepath.Join(tmpDir, filename)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("Secret file %s not created: %v", filename, err)
			continue
		}
		if got, want := info.Mode().Perm(), FileMode(filename); got != want {
			t.Errorf("Secret file %s mode = %o, want %o", filename, got, want)
		}

		// User-provided secrets should be empty
		if expectedLen == 0 {
			if info.Size() != 0 {
				t.Errorf("Secret file %s should be empty", filename)
			}
			continue
		}

		// Auto-generated secrets should have content
		if info.Size() == 0 {
			t.Errorf("Secret file %s should have content", filename)
		}
	}
}

func TestGenerateSelectedSecretsCreatesOnlyRequestedFiles(t *testing.T) {
	root := t.TempDir()
	selected := map[string]int{
		"automatic.txt": 24,
		"manual.txt":    0,
	}
	if err := GenerateSelectedSecrets(root, selected); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %v, want exactly two", entries)
	}
	for name, length := range selected {
		info, err := os.Stat(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o", name, info.Mode().Perm())
		}
		if (length == 0) != (info.Size() == 0) {
			t.Fatalf("%s size = %d for requested length %d", name, info.Size(), length)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "vpn_password.txt")); !os.IsNotExist(err) {
		t.Fatal("unrequested global secret was created")
	}
}

func TestGenerateSelectedSecretsRejectsUnsafeSelection(t *testing.T) {
	for _, selected := range []map[string]int{
		{"../escape": 24},
		{"oversized.txt": 4097},
		{"negative.txt": -1},
	} {
		if err := GenerateSelectedSecrets(t.TempDir(), selected); err == nil {
			t.Fatalf("unsafe selection %v was accepted", selected)
		}
	}
}

func TestListSecrets(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sdbx-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate secrets
	if err := GenerateSecrets(tmpDir); err != nil {
		t.Fatalf("GenerateSecrets failed: %v", err)
	}

	// List secrets
	status, err := ListSecrets(tmpDir)
	if err != nil {
		t.Fatalf("ListSecrets failed: %v", err)
	}

	// Verify all secrets are listed
	for filename := range SecretFiles {
		if _, ok := status[filename]; !ok {
			t.Errorf("Secret %s not in list", filename)
		}
	}
}

func TestReadSecretNotConfigured(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sdbx-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create empty file
	emptyFile := filepath.Join(tmpDir, "empty_secret.txt")
	if err := os.WriteFile(emptyFile, []byte(""), 0o600); err != nil {
		t.Fatalf("Failed to create empty file: %v", err)
	}

	// Try to read empty secret
	_, err = ReadSecret(tmpDir, "empty_secret.txt")
	if err == nil {
		t.Error("ReadSecret should fail for empty secret")
	}

	if !IsSecretNotConfigured(err) {
		t.Errorf("Expected SecretNotConfiguredError, got: %v", err)
	}
}

func TestSecretErrors(t *testing.T) {
	// Test SecretNotConfiguredError
	err := &SecretNotConfiguredError{Filename: "test.txt"}
	if !IsSecretNotConfigured(err) {
		t.Error("IsSecretNotConfigured should return true")
	}

}

func TestGenerateSecretsRepairsExistingMode(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "authelia_jwt_secret.txt")
	if err := os.WriteFile(path, []byte("existing"), 0o666); err != nil {
		t.Fatal(err)
	}

	if err := GenerateSecrets(tmpDir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Mode().Perm(), FileMode("authelia_jwt_secret.txt"); got != want {
		t.Fatalf("mode = %o, want %o", got, want)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "existing" {
		t.Fatalf("existing secret was overwritten: %q", data)
	}
}

func TestRepairExistingPermissionsMakesServiceMountedSecretsContainerReadable(t *testing.T) {
	secretsDir := t.TempDir()
	cloudflared := filepath.Join(secretsDir, CloudflaredTunnelTokenFile)
	authelia := filepath.Join(secretsDir, "authelia_jwt_secret.txt")
	qbittorrent := filepath.Join(secretsDir, "qbittorrent_password.txt")
	for _, name := range consoleProxyFiles {
		if err := os.WriteFile(filepath.Join(secretsDir, name), []byte("synthetic-pki"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(cloudflared, []byte("tunnel-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authelia, []byte("authelia-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(qbittorrent, []byte("qbt-secret"), 0o666); err != nil {
		t.Fatal(err)
	}

	if err := RepairExistingPermissions(secretsDir); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{
		cloudflared: 0o644,
		authelia:    0o644,
		qbittorrent: 0o600,
		filepath.Join(secretsDir, ConsoleProxyCAFile):         0o644,
		filepath.Join(secretsDir, ConsoleProxyClientCertFile): 0o644,
		filepath.Join(secretsDir, ConsoleProxyClientKeyFile):  0o644,
		filepath.Join(secretsDir, ConsoleProxyServerCertFile): 0o600,
		filepath.Join(secretsDir, ConsoleProxyServerKeyFile):  0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("%s mode = %o, want %o", path, got, want)
		}
	}
}

func TestGenerateSecretsRejectsManagedSecretSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on Windows")
	}
	tmpDir := t.TempDir()
	victim := filepath.Join(tmpDir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(tmpDir, "authelia_jwt_secret.txt")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}

	if err := GenerateSecrets(tmpDir); err == nil {
		t.Fatal("GenerateSecrets accepted a managed secret symlink")
	}
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep" {
		t.Fatalf("symlink victim changed to %q", data)
	}
}

func TestGenerateSecretsIgnoresPermissiveUmask(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("umask is Unix-specific")
	}
	oldUmask := syscall.Umask(0)
	defer syscall.Umask(oldUmask)

	tmpDir := filepath.Join(t.TempDir(), "secrets")
	if err := GenerateSecrets(tmpDir); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Stat(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("directory mode = %o, want 700", got)
	}
	for filename := range SecretFiles {
		info, err := os.Stat(filepath.Join(tmpDir, filename))
		if err != nil {
			t.Fatal(err)
		}
		if got, want := info.Mode().Perm(), FileMode(filename); got != want {
			t.Fatalf("%s mode = %o, want %o", filename, got, want)
		}
	}
}

func TestReadSecretRejectsTraversalSymlinkAndOversize(t *testing.T) {
	tmpDir := t.TempDir()
	if _, err := ReadSecret(tmpDir, "../outside"); err == nil {
		t.Fatal("ReadSecret accepted path traversal")
	}

	if runtime.GOOS != "windows" {
		victim := filepath.Join(tmpDir, "victim")
		if err := os.WriteFile(victim, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(tmpDir, "link.txt")
		if err := os.Symlink(victim, link); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadSecret(tmpDir, "link.txt"); err == nil {
			t.Fatal("ReadSecret accepted a symlink")
		}
	}

	oversize := filepath.Join(tmpDir, "oversize.txt")
	if err := os.WriteFile(oversize, make([]byte, maxSecretFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecret(tmpDir, "oversize.txt"); err == nil {
		t.Fatal("ReadSecret accepted an oversized secret")
	}
}
