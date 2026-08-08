package doctor

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/get-sdbx/sdbx/internal/config"
	sdbxdocker "github.com/get-sdbx/sdbx/internal/docker"
	"github.com/get-sdbx/sdbx/internal/generator"
	"github.com/get-sdbx/sdbx/internal/registry"
	sdbxsecrets "github.com/get-sdbx/sdbx/internal/secrets"
)

func TestNewDoctor(t *testing.T) {
	doc := NewDoctor("/tmp/test")
	if doc.ProjectDir != "/tmp/test" {
		t.Errorf("ProjectDir = %s, want /tmp/test", doc.ProjectDir)
	}
	if len(doc.Checks) != 0 {
		t.Errorf("Initial checks = %d, want 0", len(doc.Checks))
	}
}

func TestCheckDockerVersion(t *testing.T) {
	doc := NewDoctor(".")
	ctx := context.Background()

	passed, msg := doc.checkDockerVersion(ctx)

	// This test depends on Docker being installed
	// If Docker is installed, it should pass
	// We just verify it doesn't panic
	t.Logf("Docker version check: passed=%v, msg=%s", passed, msg)
}

func TestCheckDiskSpace(t *testing.T) {
	doc := NewDoctor(".")
	ctx := context.Background()

	passed, msg := doc.checkDiskSpace(ctx)

	// Should always return something
	if msg == "" {
		t.Error("Disk space check returned empty message")
	}
	t.Logf("Disk space check: passed=%v, msg=%s", passed, msg)
}

func TestCheckPermissions(t *testing.T) {
	// Create temp dir we know we can write to
	tmpDir, err := os.MkdirTemp("", "sdbx-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	doc := NewDoctor(tmpDir)
	ctx := context.Background()

	passed, msg := doc.checkPermissions(ctx)
	if !passed {
		t.Errorf("Permissions check failed: %s", msg)
	}
}

func TestCheckProjectFiles(t *testing.T) {
	// Test with no project files
	tmpDir, err := os.MkdirTemp("", "sdbx-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	doc := NewDoctor(tmpDir)
	ctx := context.Background()

	passed, msg := doc.checkProjectFiles(ctx)
	if passed {
		t.Error("Should fail with no project files")
	}
	if msg == "" {
		t.Error("Should return message about missing files")
	}

	// Create required files
	for name, contents := range map[string]string{
		".sdbx.yaml":   "domain: test.example\n",
		".sdbx.lock":   "apiVersion: sdbx.one/v2\n",
		"compose.yaml": "services: {}\n",
		".env":         "DOMAIN=test\n",
	} {
		if err := os.WriteFile(
			filepath.Join(tmpDir, name),
			[]byte(contents),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}

	passed, msg = doc.checkProjectFiles(ctx)
	if !passed {
		t.Errorf("Should pass with project files: %s", msg)
	}
}

func TestCheckSecrets(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sdbx-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	doc := NewDoctor(tmpDir)
	ctx := context.Background()

	// No secrets dir
	passed, _ := doc.checkSecrets(ctx)
	if passed {
		t.Error("Should fail with no secrets directory")
	}

	// Create secrets dir with files
	secretsDir := filepath.Join(tmpDir, "secrets")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"authelia_jwt_secret.txt":             "secret123",
		"authelia_session_secret.txt":         "secret456",
		"authelia_storage_encryption_key.txt": "secret789",
	} {
		if err := os.WriteFile(
			filepath.Join(secretsDir, name),
			[]byte(value),
			sdbxsecrets.FileMode(name),
		); err != nil {
			t.Fatal(err)
		}
	}

	passed, _ = doc.checkSecrets(ctx)
	if !passed {
		t.Error("Should pass with secrets configured")
	}
}

func TestProjectDoctorSecretInventoryComesFromActiveGraph(t *testing.T) {
	project := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.SecretsPath = "./secrets"
	cfg.ActiveServices = map[string]bool{
		"authelia":    true,
		"qbittorrent": true,
	}
	graph := &registry.ResolutionGraph{
		Order: []string{"authelia", "qbittorrent"},
		Services: map[string]*registry.ResolvedService{
			"authelia": {
				Enabled: true,
				FinalDefinition: &registry.ServiceDefinition{
					Secrets: []registry.SecretDef{
						{Name: "authelia_jwt_secret", Type: "auto", Length: 64},
						{Name: "authelia_session_secret", Type: "auto", Length: 64},
					},
				},
			},
			"qbittorrent": {
				Enabled:         true,
				FinalDefinition: &registry.ServiceDefinition{},
			},
		},
	}
	secretsDir := filepath.Join(project, "secrets")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"authelia_jwt_secret.txt",
		"authelia_session_secret.txt",
		"qbittorrent_password.txt",
	} {
		if err := os.WriteFile(
			filepath.Join(secretsDir, name),
			[]byte("configured"),
			sdbxsecrets.FileMode(name),
		); err != nil {
			t.Fatal(err)
		}
	}
	// An empty disabled-service credential must not poison the active graph.
	if err := os.WriteFile(filepath.Join(secretsDir, "plex_claim_token.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	doc := NewProjectDoctor(project, cfg, graph, &generator.ComposeFile{})
	passed, message := doc.checkSecrets(context.Background())
	if !passed {
		t.Fatalf("graph-derived secret check failed: %s", message)
	}
	if !strings.Contains(message, "3 active credential") {
		t.Fatalf("message = %q", message)
	}
}

func TestProjectDoctorOptionalSecretRequiresProtectedFileButAllowsEmptyContent(t *testing.T) {
	project := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.SecretsPath = "./secrets"
	cfg.ActiveServices = map[string]bool{"plex": true}
	graph := &registry.ResolutionGraph{
		Order: []string{"plex"},
		Services: map[string]*registry.ResolvedService{
			"plex": {
				Enabled: true,
				FinalDefinition: &registry.ServiceDefinition{
					Secrets: []registry.SecretDef{{
						Name: "plex_claim_token", Type: "manual", Optional: true,
					}},
				},
			},
		},
	}
	secretsDir := filepath.Join(project, "secrets")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	doc := NewProjectDoctor(project, cfg, graph, &generator.ComposeFile{})
	if passed, message := doc.checkSecrets(context.Background()); passed ||
		!strings.Contains(message, "plex_claim_token.txt missing") {
		t.Fatalf("missing optional secret result = %t, %q", passed, message)
	}
	if err := os.WriteFile(
		filepath.Join(secretsDir, "plex_claim_token.txt"),
		nil,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if passed, message := doc.checkSecrets(context.Background()); !passed {
		t.Fatalf("empty optional secret result = %t, %q", passed, message)
	}
}

func TestProjectDoctorSecretInventoryRejectsSymlinksAndPermissiveModes(t *testing.T) {
	project := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.SecretsPath = "./secrets"
	cfg.ActiveServices = map[string]bool{"plex": true}
	graph := &registry.ResolutionGraph{
		Order: []string{"plex"},
		Services: map[string]*registry.ResolvedService{
			"plex": {
				Enabled: true,
				FinalDefinition: &registry.ServiceDefinition{
					Secrets: []registry.SecretDef{{
						Name: "plex_claim_token", Type: "manual",
					}},
				},
			},
		},
	}
	secretsDir := filepath.Join(project, "secrets")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(secretsDir, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(secretsDir, "plex_claim_token.txt")
	if err := os.Symlink(target, secret); err != nil {
		t.Fatal(err)
	}
	doc := NewProjectDoctor(project, cfg, graph, &generator.ComposeFile{})
	if passed, message := doc.checkSecrets(context.Background()); passed ||
		!strings.Contains(message, "not a regular file") {
		t.Fatalf("symlink secret result = %t, %q", passed, message)
	}
	if err := os.Remove(secret); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if passed, message := doc.checkSecrets(context.Background()); passed ||
		!strings.Contains(message, "group or other") {
		t.Fatalf("permissive secret result = %t, %q", passed, message)
	}
}

func TestCheckArrAuthRequiresFormsEnabledWithoutAmbiguity(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		pass bool
	}{
		{
			name: "canonical",
			body: `<Config>
  <ApiKey>synthetic-api-key</ApiKey>
  <AuthenticationMethod>Forms</AuthenticationMethod>
  <AuthenticationRequired>Enabled</AuthenticationRequired>
</Config>
`,
			pass: true,
		},
		{
			name: "external bypass",
			body: `<Config>
  <ApiKey>synthetic-api-key</ApiKey>
  <AuthenticationMethod>External</AuthenticationMethod>
  <AuthenticationRequired>Enabled</AuthenticationRequired>
</Config>
`,
		},
		{
			name: "local address bypass",
			body: `<Config>
  <ApiKey>synthetic-api-key</ApiKey>
  <AuthenticationMethod>Forms</AuthenticationMethod>
  <AuthenticationRequired>DisabledForLocalAddresses</AuthenticationRequired>
</Config>
`,
		},
		{
			name: "duplicate method",
			body: `<Config>
  <ApiKey>synthetic-api-key</ApiKey>
  <AuthenticationMethod>Forms</AuthenticationMethod>
  <AuthenticationMethod>External</AuthenticationMethod>
  <AuthenticationRequired>Enabled</AuthenticationRequired>
</Config>
`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			project := t.TempDir()
			configDir := filepath.Join(project, "configs", "sonarr")
			if err := os.MkdirAll(configDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(
				filepath.Join(configDir, "config.xml"),
				[]byte(test.body),
				0o600,
			); err != nil {
				t.Fatal(err)
			}
			cfg := config.DefaultConfig()
			cfg.ConfigPath = "./configs"
			cfg.ActiveServices = map[string]bool{"sonarr": true}
			doctor := NewProjectDoctor(
				project,
				cfg,
				&registry.ResolutionGraph{},
				&generator.ComposeFile{},
			)
			passed, message := doctor.checkArrAuth(context.Background())
			if passed != test.pass {
				t.Fatalf("passed = %t, want %t: %s", passed, test.pass, message)
			}
		})
	}
}

func TestProjectDoctorAcceptsOnlyProtectedContainerReadableSecret(t *testing.T) {
	project := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.SecretsPath = "./secrets"
	cfg.ActiveServices = map[string]bool{"cloudflared": true}
	graph := &registry.ResolutionGraph{
		Order: []string{"cloudflared"},
		Services: map[string]*registry.ResolvedService{
			"cloudflared": {
				Enabled: true,
				FinalDefinition: &registry.ServiceDefinition{
					Secrets: []registry.SecretDef{{
						Name: "cloudflared_tunnel_token", Type: "manual",
					}},
				},
			},
		},
	}
	secretsDir := filepath.Join(project, "secrets")
	if err := os.Mkdir(secretsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(secretsDir, "cloudflared_tunnel_token.txt")
	if err := os.WriteFile(token, []byte("configured"), 0o644); err != nil {
		t.Fatal(err)
	}
	doc := NewProjectDoctor(project, cfg, graph, &generator.ComposeFile{})
	if passed, message := doc.checkSecrets(context.Background()); !passed {
		t.Fatalf("protected container-readable secret failed: %s", message)
	}

	if err := os.Chmod(token, 0o600); err != nil {
		t.Fatal(err)
	}
	if passed, message := doc.checkSecrets(context.Background()); passed ||
		!strings.Contains(message, "mode 0644") {
		t.Fatalf("mode-0600 container secret result = %t, %q", passed, message)
	}
	if err := os.Chmod(token, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(token, filepath.Join(secretsDir, "token-hardlink")); err != nil {
		t.Fatal(err)
	}
	if passed, message := doc.checkSecrets(context.Background()); passed ||
		!strings.Contains(message, "single-linked") {
		t.Fatalf("hard-linked container secret result = %t, %q", passed, message)
	}
}

func TestDoctorPublishedPortsUseGeneratedComposeModel(t *testing.T) {
	compose := &generator.ComposeFile{
		Services: map[string]generator.ComposeService{
			"traefik": {
				Ports: []string{"80:80", "443:443"},
			},
			"dns": {
				Ports: []string{"[::1]:5353:53/udp"},
			},
		},
	}
	bindings, err := doctorPublishedPorts(compose)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 3 {
		t.Fatalf("bindings = %+v", bindings)
	}
	if bindings[2].Host != "::1" ||
		bindings[2].Port != 5353 ||
		bindings[2].Protocol != "udp" {
		t.Fatalf("IPv6 UDP binding = %+v", bindings[2])
	}
}

func TestProjectDoctorPortMessageUsesOperatorFacingLanguage(t *testing.T) {
	doc := NewProjectDoctor(
		t.TempDir(),
		config.DefaultConfig(),
		&registry.ResolutionGraph{},
		&generator.ComposeFile{},
	)
	passed, message := doc.checkPorts(context.Background())
	if !passed {
		t.Fatalf("port check failed: %s", message)
	}
	for _, jargon := range []string{"graph", "binding", "ownership"} {
		if strings.Contains(strings.ToLower(message), jargon) {
			t.Fatalf("port check exposed internal architecture language %q: %q", jargon, message)
		}
	}
}

func TestProjectDoctorServiceHealthUsesEveryActiveGraphService(t *testing.T) {
	graph := &registry.ResolutionGraph{
		Order: []string{"authelia", "qbittorrent"},
		Services: map[string]*registry.ResolvedService{
			"authelia": {
				Enabled:         true,
				FinalDefinition: &registry.ServiceDefinition{},
			},
			"qbittorrent": {
				Enabled:         true,
				FinalDefinition: &registry.ServiceDefinition{},
			},
		},
	}
	cfg := config.DefaultConfig()
	cfg.ActiveServices = map[string]bool{
		"authelia":    true,
		"qbittorrent": true,
	}
	doc := NewProjectDoctor(t.TempDir(), cfg, graph, &generator.ComposeFile{})
	doc.composePS = func(context.Context) ([]sdbxdocker.Service, error) {
		return []sdbxdocker.Service{
			{Service: "authelia", Status: "running", Running: true, Health: "healthy"},
			{Service: "qbittorrent", Status: "exited", ExitCode: 1},
		}, nil
	}
	if passed, message := doc.checkServiceHealth(context.Background()); passed ||
		!strings.Contains(message, "qbittorrent exited") {
		t.Fatalf("failed-service result = %t, %q", passed, message)
	}
	doc.composePS = func(context.Context) ([]sdbxdocker.Service, error) {
		return []sdbxdocker.Service{
			{Service: "authelia", Status: "running", Running: true, Health: "healthy"},
			{Service: "qbittorrent", Status: "running", Running: true},
		}, nil
	}
	if passed, message := doc.checkServiceHealth(context.Background()); !passed {
		t.Fatalf("healthy-service result = %t, %q", passed, message)
	}
}

func TestGluetunCredentialCheckRejectsTemplatePlaceholders(t *testing.T) {
	project := t.TempDir()
	configRoot := filepath.Join(project, "configs")
	path := filepath.Join(configRoot, "gluetun", "gluetun.env")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		path,
		[]byte("VPN_TYPE=wireguard\nWIREGUARD_PRIVATE_KEY=your_private_key\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.ConfigPath = configRoot
	cfg.ActiveServices = map[string]bool{"gluetun": true}
	doc := NewProjectDoctor(project, cfg, &registry.ResolutionGraph{}, &generator.ComposeFile{})
	if message := doc.checkGluetunCredentials(); !strings.Contains(message, "placeholders") {
		t.Fatalf("placeholder result = %q", message)
	}
	if err := os.WriteFile(
		path,
		[]byte("VPN_TYPE=wireguard\nWIREGUARD_PRIVATE_KEY=synthetic-configured-key\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if message := doc.checkGluetunCredentials(); message != "" {
		t.Fatalf("configured result = %q", message)
	}
}

func TestRunAll(t *testing.T) {
	doc := NewDoctor(".")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	checks := doc.RunAll(ctx)

	// Should have run all checks
	if len(checks) == 0 {
		t.Error("RunAll returned no checks")
	}

	// All checks should have a status
	for _, check := range checks {
		if check.Name == "" {
			t.Error("Check has empty name")
		}
		if check.Status == StatusPending || check.Status == StatusRunning {
			t.Errorf("Check %s has invalid status", check.Name)
		}
	}
}

func TestRunAllIncludesVPNConnectivity(t *testing.T) {
	doc := NewDoctor(".")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	checks := doc.RunAll(ctx)

	for _, check := range checks {
		if check.Name == "VPN connectivity" {
			return
		}
	}

	t.Fatal("RunAll did not include VPN connectivity check")
}

func TestCheckVPNRunsProbeInsideGluetunWhenEnabled(t *testing.T) {
	projectDir := t.TempDir()
	writeDoctorConfig(t, projectDir, true)
	doc := NewDoctor(projectDir)
	called := false
	doc.vpnEgress = func(context.Context) (string, error) {
		called = true
		return "203.0.113.42\n", nil
	}

	passed, message := doc.CheckVPN(context.Background())
	if !passed {
		t.Fatalf("CheckVPN failed: %s", message)
	}
	if !called {
		t.Fatal("CheckVPN did not run the Gluetun egress probe")
	}
	if !strings.Contains(message, "203.0.113.42") {
		t.Fatalf("message = %q, want tunnel egress IP", message)
	}
}

func TestCheckVPNReportsGluetunFailure(t *testing.T) {
	projectDir := t.TempDir()
	writeDoctorConfig(t, projectDir, true)
	doc := NewDoctor(projectDir)
	doc.vpnEgress = func(context.Context) (string, error) {
		return "", errors.New("container is not running")
	}

	passed, message := doc.CheckVPN(context.Background())
	if passed {
		t.Fatalf("CheckVPN passed: %s", message)
	}
	if !strings.Contains(message, "Gluetun egress check failed") ||
		!strings.Contains(message, "container is not running") {
		t.Fatalf("message = %q, want actionable Gluetun failure", message)
	}
}

func TestCheckVPNRejectsInvalidContainerResponse(t *testing.T) {
	projectDir := t.TempDir()
	writeDoctorConfig(t, projectDir, true)
	doc := NewDoctor(projectDir)
	doc.vpnEgress = func(context.Context) (string, error) {
		return "<html>gateway error</html>", nil
	}

	passed, message := doc.CheckVPN(context.Background())
	if passed {
		t.Fatalf("CheckVPN passed: %s", message)
	}
	if !strings.Contains(message, "invalid public IP") {
		t.Fatalf("message = %q, want invalid-IP result", message)
	}
}

func TestCheckVPNDoesNotProbeWhenProtectionIsDisabled(t *testing.T) {
	projectDir := t.TempDir()
	writeDoctorConfig(t, projectDir, false)
	doc := NewDoctor(projectDir)
	doc.vpnEgress = func(context.Context) (string, error) {
		t.Fatal("disabled VPN must not run a Gluetun probe")
		return "", nil
	}

	passed, message := doc.CheckVPN(context.Background())
	if !passed {
		t.Fatalf("CheckVPN failed: %s", message)
	}
	if !strings.Contains(message, "torrent traffic uses the host public IP") {
		t.Fatalf("message = %q, want explicit unprotected-traffic status", message)
	}
}

func TestCheckCloudflareRoutingProbesEveryActiveURL(t *testing.T) {
	cfg, graph := cloudflareDoctorFixture()
	doc := NewProjectDoctor(t.TempDir(), cfg, graph, nil)
	var calls atomic.Int32
	doc.cloudflareProbe = func(
		_ context.Context,
		_ string,
	) (int, bool, error) {
		calls.Add(1)
		return http.StatusFound, true, nil
	}

	passed, message := doc.checkCloudflareRouting(context.Background())
	if !passed {
		t.Fatalf("Cloudflare route check failed: %s", message)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("probe calls = %d, want 3", got)
	}
	if !strings.Contains(message, "Public routes reachable through Cloudflare: 3") {
		t.Fatalf("message = %q, want route count", message)
	}
	for _, jargon := range []string{"ownership", "reconciliation"} {
		if strings.Contains(strings.ToLower(message), jargon) {
			t.Fatalf("Cloudflare check exposed internal architecture language %q: %q", jargon, message)
		}
	}
}

func TestPublicInternetAddressesRejectsLocalAliases(t *testing.T) {
	addresses := []netip.Addr{
		netip.MustParseAddr("127.0.1.1"),
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("169.254.1.1"),
		netip.MustParseAddr("2606:4700::6810:85e5"),
		netip.MustParseAddr("104.16.133.229"),
	}
	got := publicInternetAddresses(addresses)
	want := []netip.Addr{
		netip.MustParseAddr("104.16.133.229"),
		netip.MustParseAddr("2606:4700::6810:85e5"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("publicInternetAddresses() = %v, want %v", got, want)
	}
}

func TestCheckCloudflareRoutingRejectsRemoteCatchAll(t *testing.T) {
	cfg, graph := cloudflareDoctorFixture()
	doc := NewProjectDoctor(t.TempDir(), cfg, graph, nil)
	doc.cloudflareProbe = func(
		_ context.Context,
		url string,
	) (int, bool, error) {
		if strings.Contains(url, "sonarr.") {
			return http.StatusNotFound, true, nil
		}
		return http.StatusOK, true, nil
	}

	passed, message := doc.checkCloudflareRouting(context.Background())
	if passed {
		t.Fatalf("Cloudflare route check passed: %s", message)
	}
	if !strings.Contains(message, "returned 404") ||
		!strings.Contains(message, "sdbx tunnel routes") {
		t.Fatalf("message = %q, want route reconciliation guidance", message)
	}
}

func TestCheckCloudflareRoutingRequiresCloudflareEdge(t *testing.T) {
	cfg, graph := cloudflareDoctorFixture()
	doc := NewProjectDoctor(t.TempDir(), cfg, graph, nil)
	doc.cloudflareProbe = func(
		_ context.Context,
		_ string,
	) (int, bool, error) {
		return http.StatusOK, false, nil
	}

	passed, message := doc.checkCloudflareRouting(context.Background())
	if passed {
		t.Fatalf("Cloudflare route check passed: %s", message)
	}
	if !strings.Contains(message, "did not traverse the Cloudflare edge") {
		t.Fatalf("message = %q, want edge-boundary failure", message)
	}
}

func TestCheckCloudflareRoutingSkipsOtherExposureModes(t *testing.T) {
	cfg, graph := cloudflareDoctorFixture()
	cfg.Expose.Mode = config.ExposeModeLAN
	doc := NewProjectDoctor(t.TempDir(), cfg, graph, nil)
	doc.cloudflareProbe = func(
		context.Context,
		string,
	) (int, bool, error) {
		t.Fatal("non-Cloudflare exposure must not run a public route probe")
		return 0, false, nil
	}

	passed, message := doc.checkCloudflareRouting(context.Background())
	if !passed || message != "Not enabled" {
		t.Fatalf("result = %t, %q, want skipped success", passed, message)
	}
}

func cloudflareDoctorFixture() (
	*config.Config,
	*registry.ResolutionGraph,
) {
	cfg := config.DefaultConfig()
	cfg.Domain = "media.example.test"
	cfg.Expose.Mode = config.ExposeModeCloudflared
	graph := &registry.ResolutionGraph{
		Order: []string{"authelia", "sonarr"},
		Services: map[string]*registry.ResolvedService{
			"authelia": {
				Enabled: true,
				FinalDefinition: &registry.ServiceDefinition{
					Metadata: registry.ServiceMetadata{Name: "authelia"},
					Routing: registry.RoutingConfig{
						Enabled:   true,
						Subdomain: "auth",
					},
				},
			},
			"sonarr": {
				Enabled: true,
				FinalDefinition: &registry.ServiceDefinition{
					Metadata: registry.ServiceMetadata{Name: "sonarr"},
					Routing: registry.RoutingConfig{
						Enabled:   true,
						Subdomain: "sonarr",
					},
				},
			},
		},
	}
	return cfg, graph
}

func writeDoctorConfig(t *testing.T, projectDir string, vpnEnabled bool) {
	t.Helper()
	body := []byte("vpn_enabled: " + map[bool]string{
		true:  "true",
		false: "false",
	}[vpnEnabled] + "\n")
	if err := os.WriteFile(filepath.Join(projectDir, ".sdbx.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}
