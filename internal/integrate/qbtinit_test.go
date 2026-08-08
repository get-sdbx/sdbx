package integrate

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"

	"github.com/get-sdbx/sdbx/internal/config"
)

// TestQBTPBKDF2Hash_FormatRoundTrip verifies our hash matches what
// qBittorrent would compute given the same salt + password. We can't call
// qBT itself in unit tests, but we can validate the algorithm + format.
func TestQBTPBKDF2Hash_FormatRoundTrip(t *testing.T) {
	got, err := qbtPBKDF2Hash("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	// Must be the @ByteArray(salt:hash) shape qBT requires.
	if !strings.HasPrefix(got, "@ByteArray(") || !strings.HasSuffix(got, ")") {
		t.Fatalf("hash not wrapped in @ByteArray(): %s", got)
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(got, "@ByteArray("), ")")
	parts := strings.Split(inner, ":")
	if len(parts) != 2 {
		t.Fatalf("want salt:hash, got %d parts: %s", len(parts), inner)
	}
	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil || len(salt) != qbtPBKDF2SaltLength {
		t.Fatalf("salt: want %d bytes, got %d (err=%v)", qbtPBKDF2SaltLength, len(salt), err)
	}
	hash, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(hash) != qbtPBKDF2KeyLength {
		t.Fatalf("hash: want %d bytes, got %d (err=%v)", qbtPBKDF2KeyLength, len(hash), err)
	}
	// The hash must equal pbkdf2(password, salt, iterations, keyLen, sha512).
	expected := pbkdf2.Key([]byte("hunter2"), salt, qbtPBKDF2Iterations, qbtPBKDF2KeyLength, sha512.New)
	if !bytesEqual(expected, hash) {
		t.Errorf("hash doesn't match PBKDF2-HMAC-SHA512(password, salt, %d, %d)", qbtPBKDF2Iterations, qbtPBKDF2KeyLength)
	}
}

func TestQBTManagedCredentialMatchRequiresCurrentSecretAndHash(t *testing.T) {
	root := t.TempDir()
	secretsDir := filepath.Join(root, "secrets")
	if err := os.Mkdir(secretsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(secretsDir, "qbittorrent_password.txt")
	if err := os.WriteFile(credentialPath, []byte("current-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hash, err := qbtPBKDF2Hash("current-password")
	if err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(root, "qBittorrent.conf")
	conf := "[Preferences]\nWebUI\\Password_PBKDF2=" + hash + "\n"
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	if !qbtManagedCredentialMatches(confPath, credentialPath) {
		t.Fatal("matching managed credential was rejected")
	}

	if err := os.WriteFile(credentialPath, []byte("stale-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if qbtManagedCredentialMatches(confPath, credentialPath) {
		t.Fatal("stale managed credential was accepted")
	}
	if QBittorrentPasswordMatchesHash("current-password", "@ByteArray(invalid)") {
		t.Fatal("malformed qBittorrent password hash was accepted")
	}
}

func TestManagedCredentialAvailabilityRejectsMissingAndEmptyFiles(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SecretsPath = t.TempDir()
	const filename = "managed_test_password.txt"
	if managedCredentialAvailable(cfg, filename) {
		t.Fatal("missing managed credential was accepted")
	}
	path := filepath.Join(cfg.SecretsPath, filename)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if managedCredentialAvailable(cfg, filename) {
		t.Fatal("empty managed credential was accepted")
	}
	if err := os.WriteFile(path, []byte("configured\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !managedCredentialAvailable(cfg, filename) {
		t.Fatal("configured managed credential was rejected")
	}
}

func TestRotateQBittorrentCredentialRefusesDesynchronisedRecoverySecret(t *testing.T) {
	root := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ConfigPath = filepath.Join(root, "configs")
	cfg.SecretsPath = filepath.Join(root, "secrets")
	cfg.ActiveServices = map[string]bool{"qbittorrent": true}
	confPath := qbtConfPath(cfg)
	if err := os.MkdirAll(filepath.Dir(confPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.SecretsPath, 0o700); err != nil {
		t.Fatal(err)
	}
	hash, err := qbtPBKDF2Hash("runtime-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		confPath,
		[]byte("[Preferences]\nWebUI\\Password_PBKDF2="+hash+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(cfg.SecretsPath, "qbittorrent_password.txt"),
		[]byte("different-recovery-password"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	result, err := RotateQBittorrentCredential(
		context.Background(),
		cfg,
		"sdbx.example.test",
	)
	if err == nil || result == nil ||
		!strings.Contains(err.Error(), "refusing qBT rotation") {
		t.Fatalf("rotation result=%#v err=%v", result, err)
	}
}

// TestUpdateQBTConf_PreservesUnrelatedKeys verifies our conf editor only
// touches the keys we tell it to and leaves the rest of the file alone.
func TestUpdateQBTConf_PreservesUnrelatedKeys(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "qBittorrent.conf")
	original := `[Application]
SomeKey=value

[Preferences]
Connection\ResolvePeerCountries=true
WebUI\AuthSubnetWhitelist=1.2.3.4/32
WebUI\AuthSubnetWhitelistEnabled=false
General\Locale=en_US
`
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := updateQBTConf(path, map[string]string{
		`WebUI\AuthSubnetWhitelist`:        "172.16.0.0/12",
		`WebUI\AuthSubnetWhitelistEnabled`: "true",
		`WebUI\Username`:                   "admin",
	}, -1, -1); err != nil {
		t.Fatal(err)
	}

	got, _ := os.ReadFile(path)
	body := string(got)

	if !strings.Contains(body, "WebUI\\AuthSubnetWhitelist=172.16.0.0/12") {
		t.Errorf("AuthSubnetWhitelist not updated:\n%s", body)
	}
	if !strings.Contains(body, "WebUI\\AuthSubnetWhitelistEnabled=true") {
		t.Errorf("AuthSubnetWhitelistEnabled not updated:\n%s", body)
	}
	// Username was missing from input — must be appended.
	if !strings.Contains(body, "WebUI\\Username=admin") {
		t.Errorf("Username not appended:\n%s", body)
	}
	// Unrelated keys must be untouched.
	if !strings.Contains(body, "Connection\\ResolvePeerCountries=true") {
		t.Errorf("unrelated key clobbered:\n%s", body)
	}
	if !strings.Contains(body, "General\\Locale=en_US") {
		t.Errorf("unrelated key clobbered:\n%s", body)
	}
	if !strings.Contains(body, "SomeKey=value") {
		t.Errorf("unrelated key clobbered:\n%s", body)
	}
}

func TestUpdateQBTConf_AppendsToFreshFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "qBittorrent.conf")
	if err := os.WriteFile(path, []byte("[Application]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := updateQBTConf(path, map[string]string{
		`WebUI\Username`: "admin",
	}, -1, -1); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "[Preferences]") {
		t.Errorf("[Preferences] header not added:\n%s", body)
	}
	if !strings.Contains(string(body), "WebUI\\Username=admin") {
		t.Errorf("missing key not appended:\n%s", body)
	}
}

func TestUpdateQBTConfSectionsWritesPeerPortOnlyInBitTorrentSection(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "qBittorrent.conf")
	original := `[Application]
Session\Port=9999

[BitTorrent]
Session\Port=6881
Session\QueueingSystemEnabled=true

[Preferences]
WebUI\Username=legacy
`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := updateQBTConfSections(
		path,
		map[string]map[string]string{
			"BitTorrent": {
				`Session\Port`: "51413",
			},
			"Preferences": {
				`WebUI\Username`: "admin",
			},
		},
		-1,
		-1,
	); err != nil {
		t.Fatal(err)
	}

	body := readQBTTestFile(t, path)
	if !strings.Contains(body, "[BitTorrent]\nSession\\Port=51413") {
		t.Fatalf("peer port was not updated in [BitTorrent]:\n%s", body)
	}
	if !strings.Contains(body, "[Application]\nSession\\Port=9999") {
		t.Fatalf("same-named unmanaged key was modified:\n%s", body)
	}
	if !strings.Contains(body, "Session\\QueueingSystemEnabled=true") {
		t.Fatalf("unrelated BitTorrent key was modified:\n%s", body)
	}
	if !strings.Contains(body, "[Preferences]\nWebUI\\Username=admin") {
		t.Fatalf("Preferences key was not updated:\n%s", body)
	}
}

func TestUpdateQBTConfSectionsCreatesMissingBitTorrentSection(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "qBittorrent.conf")
	if err := os.WriteFile(path, []byte("[Preferences]\nWebUI\\Username=admin\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := updateQBTConfSections(
		path,
		map[string]map[string]string{
			"BitTorrent": {
				`Session\Port`: "42424",
			},
		},
		-1,
		-1,
	); err != nil {
		t.Fatal(err)
	}

	body := readQBTTestFile(t, path)
	if !strings.Contains(body, "[BitTorrent]\nSession\\Port=42424") {
		t.Fatalf("missing [BitTorrent] section was not created:\n%s", body)
	}
}

func TestQBTSecurityPreferencesRequireAuthentication(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "media.example.com"
	preferences := qbtSecurityPreferences("qbt.media.example.com", "hash")

	want := map[string]string{
		`WebUI\LocalHostAuth`:              "true",
		`WebUI\AuthSubnetWhitelistEnabled`: "false",
		`WebUI\AuthSubnetWhitelist`:        "",
		`WebUI\HostHeaderValidation`:       "true",
		`WebUI\CSRFProtection`:             "true",
		`WebUI\ClickjackingProtection`:     "true",
	}
	for key, expected := range want {
		if got := preferences[key]; got != expected {
			t.Errorf("%s = %q, want %q", key, got, expected)
		}
	}
	for _, host := range []string{
		"localhost",
		"sdbx-qbittorrent",
		"sdbx-gluetun",
		"qbt.media.example.com",
	} {
		if !strings.Contains(preferences[`WebUI\ServerDomains`], host) {
			t.Errorf("server domains %q missing %q", preferences[`WebUI\ServerDomains`], host)
		}
	}
	if domains := preferences[`WebUI\ServerDomains`]; !strings.HasPrefix(domains, `"`) ||
		!strings.HasSuffix(domains, `"`) {
		t.Errorf("server domains must be a quoted QSettings value, got %q", domains)
	}
	if _, exists := preferences[`WebUI\DomainList`]; exists {
		t.Fatal("used obsolete/non-persistent WebUI\\DomainList key")
	}
}

func TestQBTSecurityPreferencesOverwriteLegacyBypass(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "qBittorrent.conf")
	legacy := `[Preferences]
WebUI\AuthSubnetWhitelist=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
WebUI\AuthSubnetWhitelistEnabled=true
WebUI\HostHeaderValidation=false
WebUI\CSRFProtection=false
WebUI\ClickjackingProtection=false
`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.Domain = "media.example.test"
	if err := updateQBTConf(
		path,
		qbtSecurityPreferences("qbt.media.example.test", "hash"),
		-1,
		-1,
	); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"WebUI\\AuthSubnetWhitelistEnabled=true",
		"WebUI\\HostHeaderValidation=false",
		"WebUI\\CSRFProtection=false",
		"WebUI\\ClickjackingProtection=false",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("legacy security bypass %q survived:\n%s", forbidden, body)
		}
	}
	if !strings.Contains(
		string(body),
		`WebUI\ServerDomains="localhost;127.0.0.1;sdbx-qbittorrent;sdbx-gluetun;qbt.media.example.test"`,
	) {
		t.Fatalf("server domains were not written as a quoted QSettings value:\n%s", body)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func readQBTTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
