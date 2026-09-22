package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnsureConsoleProxyPKIGeneratesAndPreservesValidSet(t *testing.T) {
	dir := t.TempDir()
	selected := make(map[string]int, len(consoleProxyFiles))
	for _, name := range consoleProxyFiles {
		selected[name] = 0
	}
	if err := GenerateSelectedSecrets(dir, selected); err != nil {
		t.Fatal(err)
	}
	if err := EnsureConsoleProxyPKI(dir); err != nil {
		t.Fatal(err)
	}
	first := make(map[string][]byte, len(consoleProxyFiles))
	for _, name := range consoleProxyFiles {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if len(data) == 0 {
			t.Fatalf("generated PKI file %s is empty", name)
		}
		first[name] = data
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		wantMode := os.FileMode(0o600)
		if name == ConsoleProxyCAFile || name == ConsoleProxyClientCertFile || name == ConsoleProxyClientKeyFile {
			wantMode = 0o644
		}
		if info.Mode().Perm() != wantMode {
			t.Fatalf("console PKI %s mode = %o, want %o", name, info.Mode().Perm(), wantMode)
		}
	}
	if err := validateConsoleProxyPKI(first, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := EnsureConsoleProxyPKI(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range consoleProxyFiles {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != string(first[name]) {
			t.Fatalf("valid console PKI file %s was rotated", name)
		}
	}
}

func TestEnsureConsoleProxyPKIRejectsPartialSet(t *testing.T) {
	dir := t.TempDir()
	selected := make(map[string]int, len(consoleProxyFiles))
	for _, name := range consoleProxyFiles {
		selected[name] = 0
	}
	if err := GenerateSelectedSecrets(dir, selected); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ConsoleProxyCAFile), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := EnsureConsoleProxyPKI(dir)
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("partial PKI error = %v", err)
	}
}
