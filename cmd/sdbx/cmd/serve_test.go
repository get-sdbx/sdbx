package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/secrets"
)

func TestValidateServeAddressAllowsLoopback(t *testing.T) {
	valid := []string{
		"127.0.0.1:18777",
		"localhost:18777",
		"[::1]:18777",
	}

	for _, addr := range valid {
		if err := validateServeAddress(addr); err != nil {
			t.Fatalf("validateServeAddress(%q) failed: %v", addr, err)
		}
	}
}

func TestValidateServeAddressRejectsRemoteBinds(t *testing.T) {
	invalid := []string{
		":18777",
		"0.0.0.0:18777",
		"[::]:18777",
		"192.168.1.10:18777",
		"sdbx.one:18777",
	}

	for _, addr := range invalid {
		err := validateServeAddress(addr)
		if err == nil {
			t.Fatalf("validateServeAddress(%q) succeeded, want error", addr)
		}
		if !strings.Contains(err.Error(), "loopback") {
			t.Fatalf("validateServeAddress(%q) error = %v, want loopback guidance", addr, err)
		}
	}
}

func TestValidateServeAddressAllowsRemoteBindOnlyInTLSMode(t *testing.T) {
	if err := validateServeAddress("0.0.0.0:18777", true); err != nil {
		t.Fatalf("remote TLS bind rejected: %v", err)
	}
}

func TestValidateRecoveryAddressRequiresDistinctLoopbackInRemoteMode(t *testing.T) {
	tests := []struct {
		name      string
		primary   string
		recovery  string
		remoteTLS bool
		wantError string
	}{
		{name: "disabled", primary: "0.0.0.0:18777", remoteTLS: true},
		{name: "valid", primary: "0.0.0.0:18777", recovery: "127.0.0.1:18778", remoteTLS: true},
		{name: "requires TLS", primary: "127.0.0.1:18777", recovery: "127.0.0.1:18778", wantError: "requires remote TLS"},
		{name: "loopback only", primary: "0.0.0.0:18777", recovery: "0.0.0.0:18778", remoteTLS: true, wantError: "loopback"},
		{name: "distinct", primary: "127.0.0.1:18777", recovery: "127.0.0.1:18777", remoteTLS: true, wantError: "must differ"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateRecoveryAddress(
				test.primary,
				test.recovery,
				test.remoteTLS,
			)
			if test.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestLoadPublicHostFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "host.real")
	if err := os.WriteFile(target, []byte("box.example.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "host")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPublicHostFile(link); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("loadPublicHostFile() error = %v, want regular-file rejection", err)
	}
}

func TestConsoleTLSConfigRequiresTrustedClientCertificate(t *testing.T) {
	dir := t.TempDir()
	selected := map[string]int{
		secrets.ConsoleProxyCAFile:         0,
		secrets.ConsoleProxyServerCertFile: 0,
		secrets.ConsoleProxyServerKeyFile:  0,
		secrets.ConsoleProxyClientCertFile: 0,
		secrets.ConsoleProxyClientKeyFile:  0,
	}
	if err := secrets.GenerateSelectedSecrets(dir, selected); err != nil {
		t.Fatal(err)
	}
	if err := secrets.EnsureConsoleProxyPKI(dir); err != nil {
		t.Fatal(err)
	}
	config, err := consoleTLSConfig(
		filepath.Join(dir, secrets.ConsoleProxyServerCertFile),
		filepath.Join(dir, secrets.ConsoleProxyServerKeyFile),
		filepath.Join(dir, secrets.ConsoleProxyCAFile),
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = config
	server.StartTLS()
	defer server.Close()

	caPEM, err := os.ReadFile(filepath.Join(dir, secrets.ConsoleProxyCAFile))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("generated console CA could not be loaded")
	}
	withoutCertificate := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: secrets.ConsoleProxyServerName,
		RootCAs:    roots,
	}}}
	if _, err := withoutCertificate.Get(server.URL); err == nil {
		t.Fatal("TLS listener accepted a client without the Traefik certificate")
	}

	clientCertificate, err := tls.LoadX509KeyPair(
		filepath.Join(dir, secrets.ConsoleProxyClientCertFile),
		filepath.Join(dir, secrets.ConsoleProxyClientKeyFile),
	)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ServerName:   secrets.ConsoleProxyServerName,
		RootCAs:      roots,
		Certificates: []tls.Certificate{clientCertificate},
	}}}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("mTLS response status = %d", response.StatusCode)
	}
}

func TestConsoleTLSConfigRejectsSymlinkedTrustMaterial(t *testing.T) {
	dir := t.TempDir()
	selected := map[string]int{
		secrets.ConsoleProxyCAFile:         0,
		secrets.ConsoleProxyServerCertFile: 0,
		secrets.ConsoleProxyServerKeyFile:  0,
		secrets.ConsoleProxyClientCertFile: 0,
		secrets.ConsoleProxyClientKeyFile:  0,
	}
	if err := secrets.GenerateSelectedSecrets(dir, selected); err != nil {
		t.Fatal(err)
	}
	if err := secrets.EnsureConsoleProxyPKI(dir); err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, secrets.ConsoleProxyCAFile)
	caLink := filepath.Join(dir, "console-proxy-ca-link.pem")
	if err := os.Symlink(caPath, caLink); err != nil {
		t.Fatal(err)
	}
	_, err := consoleTLSConfig(
		filepath.Join(dir, secrets.ConsoleProxyServerCertFile),
		filepath.Join(dir, secrets.ConsoleProxyServerKeyFile),
		caLink,
	)
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("consoleTLSConfig() error = %v, want regular-file rejection", err)
	}
}

func TestAuthenticatedConsoleURLKeepsCredentialInFragment(t *testing.T) {
	const token = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	value := authenticatedConsoleURL("127.0.0.1:18777", token)
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "http" || parsed.Host != "127.0.0.1:18777" ||
		parsed.Path != "/" {
		t.Fatalf("authenticatedConsoleURL() = %q", value)
	}
	if parsed.RawQuery != "" || parsed.User != nil {
		t.Fatalf("credential escaped into HTTP request components: %q", value)
	}
	if parsed.Fragment != "token="+token {
		t.Fatalf("fragment = %q, want out-of-band token", parsed.Fragment)
	}
}
