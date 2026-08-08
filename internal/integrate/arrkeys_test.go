package integrate

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
)

func TestEnsureArrAPIKeys_CreatesMissingFile(t *testing.T) {
	tmp := t.TempDir()
	cfg := &config.Config{
		ConfigPath: tmp,
		PUID:       1000,
		PGID:       1000,
		ActiveServices: map[string]bool{
			"sonarr": true,
		},
	}

	results, err := EnsureArrAPIKeys(cfg)
	if err != nil {
		t.Fatalf("EnsureArrAPIKeys: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(results), results)
	}
	if results[0].Action != "created" {
		t.Errorf("want created, got %q (error: %v)", results[0].Action, results[0].Err)
	}

	data, err := os.ReadFile(filepath.Join(tmp, "sonarr", "config.xml"))
	if err != nil {
		t.Fatalf("read config.xml: %v", err)
	}
	if !apiKeyRE.Match(data) {
		t.Errorf("config.xml has no <ApiKey>: %s", data)
	}
	if !strings.Contains(string(data), "<Config>") || !strings.Contains(string(data), "</Config>") {
		t.Errorf("malformed XML: %s", data)
	}
	info, err := os.Stat(filepath.Join(tmp, "sonarr", "config.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("config.xml mode = %o, want 600", got)
	}
}

func TestEnsureArrAPIKeys_InjectsIntoExistingFileWithoutKey(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "radarr")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Existing config.xml without <ApiKey> — mimics the real-world state we
	// observed on the live server before this feature shipped.
	original := `<?xml version="1.0" encoding="utf-8"?>
<Config>
  <BindAddress>*</BindAddress>
  <Port>7878</Port>
  <AuthenticationRequired>DisabledForLocalAddresses</AuthenticationRequired>
</Config>
`
	if err := os.WriteFile(filepath.Join(dir, "config.xml"), []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		ConfigPath:     tmp,
		ActiveServices: map[string]bool{"radarr": true},
		PUID:           1000,
		PGID:           1000,
	}
	results, err := EnsureArrAPIKeys(cfg)
	if err != nil {
		t.Fatalf("EnsureArrAPIKeys: %v", err)
	}
	if results[0].Action != "injected" {
		t.Errorf("want injected, got %q (err=%v)", results[0].Action, results[0].Err)
	}

	updated, _ := os.ReadFile(filepath.Join(dir, "config.xml"))
	if !apiKeyRE.Match(updated) {
		t.Errorf("config.xml not patched: %s", updated)
	}
	// Original Port=7878 must still be present — we never overwrite.
	if !strings.Contains(string(updated), "<Port>7878</Port>") {
		t.Errorf("existing fields clobbered: %s", updated)
	}
	if !strings.Contains(string(updated), "<AuthenticationMethod>Forms</AuthenticationMethod>") {
		t.Errorf("native Forms auth not enforced: %s", updated)
	}
	if !strings.Contains(string(updated), "<AuthenticationRequired>Enabled</AuthenticationRequired>") {
		t.Errorf("authentication was not required for every address: %s", updated)
	}
	if strings.Contains(string(updated), "DisabledForLocalAddresses") {
		t.Errorf("local-address bypass survived reconciliation: %s", updated)
	}
}

func TestEnsureArrAPIKeys_RepairsInsecureExistingAuthentication(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "lidarr")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	original := `<Config>
  <ApiKey>deadbeefcafef00d1234567890abcdef</ApiKey>
  <AuthenticationMethod>External</AuthenticationMethod>
  <AuthenticationRequired>DisabledForLocalAddresses</AuthenticationRequired>
</Config>
`
	if err := os.WriteFile(filepath.Join(dir, "config.xml"), []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		ConfigPath:     tmp,
		ActiveServices: map[string]bool{"lidarr": true},
	}
	results, _ := EnsureArrAPIKeys(cfg)
	if results[0].Action != "injected" {
		t.Errorf("want injected, got %q", results[0].Action)
	}

	got, _ := os.ReadFile(filepath.Join(dir, "config.xml"))
	body := string(got)
	if !strings.Contains(body, "<AuthenticationMethod>Forms</AuthenticationMethod>") ||
		!strings.Contains(body, "<AuthenticationRequired>Enabled</AuthenticationRequired>") {
		t.Errorf("insecure auth values were not repaired:\n%s", got)
	}
	if strings.Contains(body, "External") ||
		strings.Contains(body, "DisabledForLocalAddresses") {
		t.Errorf("insecure auth values survived:\n%s", got)
	}
	info, err := os.Stat(filepath.Join(dir, "config.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("existing config.xml mode = %o, want repaired 600", got)
	}
}

func TestEnsureArrAPIKeys_AddsMissingAuthMethod(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "sonarr")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Existing file has ApiKey but NO AuthenticationMethod — Sonarr/Radarr
	// in this state default-deny every API request. Must inject Forms.
	original := `<Config>
  <ApiKey>deadbeefcafef00d1234567890abcdef</ApiKey>
  <AuthenticationRequired>Enabled</AuthenticationRequired>
</Config>
`
	if err := os.WriteFile(filepath.Join(dir, "config.xml"), []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		ConfigPath:     tmp,
		ActiveServices: map[string]bool{"sonarr": true},
	}
	results, _ := EnsureArrAPIKeys(cfg)
	if results[0].Action != "injected" {
		t.Errorf("want injected, got %q (err=%v)", results[0].Action, results[0].Err)
	}
	updated, _ := os.ReadFile(filepath.Join(dir, "config.xml"))
	if !authMethodRE.Match(updated) {
		t.Errorf("AuthenticationMethod not injected:\n%s", updated)
	}
	if !strings.Contains(string(updated), "<AuthenticationMethod>Forms</AuthenticationMethod>") {
		t.Errorf("AuthenticationMethod is not Forms:\n%s", updated)
	}
	// Original ApiKey + AuthenticationRequired must still be there.
	if !apiKeyRE.Match(updated) {
		t.Errorf("ApiKey clobbered:\n%s", updated)
	}
	if !regexp.MustCompile(`<AuthenticationRequired>Enabled</AuthenticationRequired>`).Match(updated) {
		t.Errorf("AuthenticationRequired clobbered:\n%s", updated)
	}
}

func TestEnsureArrAPIKeys_KeepsCanonicalAuthenticationByteForByte(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "sonarr")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	original := `<Config>
  <ApiKey>deadbeefcafef00d1234567890abcdef</ApiKey>
  <AuthenticationMethod>Forms</AuthenticationMethod>
  <AuthenticationRequired>Enabled</AuthenticationRequired>
</Config>
`
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		ConfigPath:     tmp,
		ActiveServices: map[string]bool{"sonarr": true},
	}
	results, err := EnsureArrAPIKeys(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Action != "kept" {
		t.Fatalf("action = %q, want kept", results[0].Action)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("canonical file changed:\n%s", got)
	}
}

func TestEnsureArrAPIKeys_RejectsAmbiguousSecurityFields(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{
			name: "api key",
			body: `<Config>
  <ApiKey>one</ApiKey>
  <ApiKey>two</ApiKey>
</Config>
`,
		},
		{
			name: "authentication method",
			body: `<Config>
  <ApiKey>deadbeefcafef00d1234567890abcdef</ApiKey>
  <AuthenticationMethod>Forms</AuthenticationMethod>
  <AuthenticationMethod>External</AuthenticationMethod>
</Config>
`,
		},
		{
			name: "authentication required",
			body: `<Config>
  <ApiKey>deadbeefcafef00d1234567890abcdef</ApiKey>
  <AuthenticationMethod>Forms</AuthenticationMethod>
  <AuthenticationRequired>Enabled</AuthenticationRequired>
  <AuthenticationRequired>DisabledForLocalAddresses</AuthenticationRequired>
</Config>
`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.xml")
			if err := os.WriteFile(path, []byte(test.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ensureArrConfigXML(path, -1, -1); err == nil ||
				!strings.Contains(err.Error(), "ambiguous") {
				t.Fatalf("error = %v, want ambiguous configuration rejection", err)
			}
		})
	}
}

func TestEnsureArrAPIKeys_NoEnabledArrs(t *testing.T) {
	tmp := t.TempDir()
	cfg := &config.Config{ConfigPath: tmp, ActiveServices: map[string]bool{}}
	results, err := EnsureArrAPIKeys(cfg)
	if err != nil {
		t.Fatalf("EnsureArrAPIKeys: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("want empty results, got %+v", results)
	}
}

func TestEnsureArrAPIKeys_PartialEnable(t *testing.T) {
	tmp := t.TempDir()
	cfg := &config.Config{
		ConfigPath: tmp,
		ActiveServices: map[string]bool{
			"sonarr": true,
			"radarr": true,
		},
	}
	results, _ := EnsureArrAPIKeys(cfg)
	if len(results) != 2 {
		t.Fatalf("want 2 results, got %d", len(results))
	}
	for _, r := range results {
		if r.Action != "created" {
			t.Errorf("%s: want created, got %q", r.Service, r.Action)
		}
		// Each service should have its own config.xml with a key.
		key, err := ReadArrAPIKey(cfg, r.Service)
		if err != nil || key == "" {
			t.Errorf("%s: ReadArrAPIKey after Ensure returned key=%q err=%v", r.Service, key, err)
		}
	}
}

func TestEnsureArrAPIKeysRejectsSymlinkedServiceDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on Windows")
	}
	for _, linkTarget := range []string{"absolute", "relative"} {
		t.Run(linkTarget, func(t *testing.T) {
			parent := t.TempDir()
			configRoot := filepath.Join(parent, "configs")
			outside := filepath.Join(parent, "outside")
			if err := os.Mkdir(configRoot, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(outside, 0o755); err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(outside, "config.xml")
			const original = `<Config>
  <ApiKey>deadbeefcafef00d1234567890abcdef</ApiKey>
  <AuthenticationMethod>Forms</AuthenticationMethod>
  <AuthenticationRequired>Enabled</AuthenticationRequired>
</Config>
`
			if err := os.WriteFile(victim, []byte(original), 0o644); err != nil {
				t.Fatal(err)
			}
			target := outside
			if linkTarget == "relative" {
				target = filepath.Join("..", "outside")
			}
			if err := os.Symlink(target, filepath.Join(configRoot, "sonarr")); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{
				ConfigPath:     configRoot,
				PUID:           12345,
				PGID:           12346,
				ActiveServices: map[string]bool{"sonarr": true},
			}

			results, err := EnsureArrAPIKeys(cfg)
			if err != nil {
				t.Fatalf("EnsureArrAPIKeys returned root error: %v", err)
			}
			if len(results) != 1 || results[0].Err == nil {
				t.Fatalf("symlinked service directory was accepted: %+v", results)
			}
			body, err := os.ReadFile(victim)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != original {
				t.Fatalf("outside config changed:\n%s", body)
			}
			info, err := os.Stat(victim)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o644 {
				t.Fatalf("outside config mode changed to %o", info.Mode().Perm())
			}
		})
	}
}

func TestInjectAPIKey_NoCloseTag(t *testing.T) {
	_, err := injectAPIKey([]byte("not-an-xml-document"), "abc")
	if err == nil {
		t.Errorf("want error for missing </Config>")
	}
}

func TestGenerateAPIKey_LengthAndUniqueness(t *testing.T) {
	a, err := generateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := generateAPIKey()
	if len(a) != 32 {
		t.Errorf("want 32-char key, got %d: %q", len(a), a)
	}
	if a == b {
		t.Errorf("two generated keys collided: %s", a)
	}
}
