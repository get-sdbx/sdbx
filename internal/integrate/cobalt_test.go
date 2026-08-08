package integrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
)

func TestEnsureCobaltKeysCreatesAndPreservesValidKeyMap(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SecretsPath = filepath.Join(t.TempDir(), "secrets")

	first, err := EnsureCobaltKeys(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !cobaltUUIDv4Pattern.MatchString(first) {
		t.Fatalf("generated key = %q, want lowercase UUIDv4", first)
	}
	path := filepath.Join(cfg.SecretsPath, cobaltKeysFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if validated, err := ValidateCobaltKeys(data); err != nil || validated != first {
		t.Fatalf("validated key = %q, err = %v", validated, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("key-map mode = %o, want 644", info.Mode().Perm())
	}

	second, err := EnsureCobaltKeys(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("key changed across generation: %q != %q", second, first)
	}
	preserved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(preserved) != string(data) {
		t.Fatal("valid operator-managed key map was rewritten")
	}
}

func TestEnsureCobaltKeysRejectsInvalidExistingMap(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SecretsPath = filepath.Join(t.TempDir(), "secrets")
	if err := os.MkdirAll(cfg.SecretsPath, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.SecretsPath, cobaltKeysFilename)
	if err := os.WriteFile(path, []byte(`{"not-a-uuid":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := EnsureCobaltKeys(cfg); err == nil ||
		!strings.Contains(err.Error(), "not a lowercase UUIDv4") {
		t.Fatalf("invalid key map error = %v", err)
	}
}

func TestValidateCobaltKeysReturnsLexicallyFirstKey(t *testing.T) {
	const document = `{
  "ffffffff-ffff-4fff-bfff-ffffffffffff": {"name": "second"},
  "00000000-0000-4000-8000-000000000000": {"name": "first"}
}`
	key, err := ValidateCobaltKeys([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	if key != "00000000-0000-4000-8000-000000000000" {
		t.Fatalf("key = %q", key)
	}
}
