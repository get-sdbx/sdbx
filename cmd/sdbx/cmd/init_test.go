package cmd

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/generator"
	"github.com/get-sdbx/sdbx/internal/registry"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/argon2"
)

func TestValidateAdminPasswordRejectsUnsafeValues(t *testing.T) {
	unsafe := []string{
		"",
		"admin",
		"password",
		"short",
		"12345678901",
	}

	for _, password := range unsafe {
		err := validateAdminPassword(password)
		if err == nil {
			t.Fatalf("validateAdminPassword(%q) succeeded, want error", password)
		}
		if !strings.Contains(err.Error(), "admin password") {
			t.Fatalf("validateAdminPassword(%q) error = %v, want admin password guidance", password, err)
		}
	}
}

func TestValidateAdminPasswordAcceptsStrongValue(t *testing.T) {
	if err := validateAdminPassword("correct-horse-battery-staple"); err != nil {
		t.Fatalf("validateAdminPassword failed: %v", err)
	}
}

func TestWizardFieldValidatorsRejectLateConfigurationFailures(t *testing.T) {
	tests := []struct {
		name     string
		validate func(string) error
		invalid  []string
		valid    string
	}{
		{
			name:     "domain",
			validate: validateWizardDomain,
			invalid:  []string{"", "localhost", "box.example.com\nother"},
			valid:    "box.example.com",
		},
		{
			name:     "path routing base domain",
			validate: validateWizardBaseDomain,
			invalid:  []string{"", "-sdbx", "sdbx.example"},
			valid:    "sdbx",
		},
		{
			name:     "admin username",
			validate: validateWizardAdminUser,
			invalid:  []string{"", " ", "admin:name", "admin\nroot"},
			valid:    "maiko.admin",
		},
		{
			name:     "timezone",
			validate: validateWizardTimezone,
			invalid:  []string{"", "Mars/Olympus", "Europe/Paris\nUTC"},
			valid:    "Europe/Paris",
		},
		{
			name: "media path",
			validate: func(value string) error {
				return validateWizardManagedPath("media_path", value)
			},
			invalid: []string{"", ".", "..", "../outside", "/"},
			valid:   "./data/media",
		},
		{
			name: "downloads path",
			validate: func(value string) error {
				return validateWizardManagedPath("downloads_path", value)
			},
			invalid: []string{"", ".", "..", "../outside", "/"},
			valid:   "/opt/sdbx/downloads",
		},
		{
			name: "config path",
			validate: func(value string) error {
				return validateWizardManagedPath("config_path", value)
			},
			invalid: []string{"", ".", "..", "../outside", "/"},
			valid:   "./configs",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, invalid := range test.invalid {
				if err := test.validate(invalid); err == nil {
					t.Errorf("validator accepted invalid value %q", invalid)
				}
			}
			if err := test.validate(test.valid); err != nil {
				t.Fatalf("validator rejected valid value %q: %v", test.valid, err)
			}
		})
	}
}

func TestValidateWizardManagedPathRejectsUnknownField(t *testing.T) {
	err := validateWizardManagedPath("data_path", "./data")
	if err == nil || !strings.Contains(err.Error(), "unsupported wizard managed path") {
		t.Fatalf("unknown wizard path error = %v", err)
	}
}

func TestApplyWizardDefaultsProvidesUsableAdminIdentity(t *testing.T) {
	for _, initial := range []string{"", " \t"} {
		cfg := config.DefaultConfig()
		cfg.AdminUser = initial
		applyWizardDefaults(cfg)
		if cfg.AdminUser != "admin" {
			t.Fatalf("AdminUser = %q, want admin", cfg.AdminUser)
		}
	}

	cfg := config.DefaultConfig()
	cfg.AdminUser = "maiko"
	applyWizardDefaults(cfg)
	if cfg.AdminUser != "maiko" {
		t.Fatalf("custom AdminUser changed to %q", cfg.AdminUser)
	}
}

func TestGenerateArgon2HashUsesAutheliaCompatibleParameters(t *testing.T) {
	password := []byte("synthetic-test-password")
	encoded, err := generateArgon2Hash(password)
	if err != nil {
		t.Fatalf("generateArgon2Hash failed: %v", err)
	}

	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		t.Fatalf("hash has %d fields, want 6: %q", len(parts), encoded)
	}
	if parts[0] != "" ||
		parts[1] != "argon2id" ||
		parts[2] != "v=19" ||
		parts[3] != "m=65536,t=3,p=4" {
		t.Fatalf("hash parameters are not Authelia-compatible: %q", encoded)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatalf("decode salt: %v", err)
	}
	if len(salt) != 16 {
		t.Fatalf("salt length = %d, want 16", len(salt))
	}
	actualHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		t.Fatalf("decode hash: %v", err)
	}
	if len(actualHash) != 32 {
		t.Fatalf("hash length = %d, want 32", len(actualHash))
	}

	expectedHash := argon2.IDKey(password, salt, 3, 64*1024, 4, 32)
	if subtle.ConstantTimeCompare(actualHash, expectedHash) != 1 {
		t.Fatal("encoded hash does not verify against its declared parameters")
	}
}

func TestValidateDownloadProtectionRequiresExplicitAcknowledgement(t *testing.T) {
	if err := validateDownloadProtection(true, false); err != nil {
		t.Fatalf("VPN-protected downloads were rejected: %v", err)
	}
	if err := validateDownloadProtection(false, true); err != nil {
		t.Fatalf("acknowledged direct downloads were rejected: %v", err)
	}
	err := validateDownloadProtection(false, false)
	if err == nil || !strings.Contains(err.Error(), "--allow-unprotected-downloads") {
		t.Fatalf("unacknowledged direct downloads error = %v", err)
	}
}

func TestInitCommandNeverAcceptsPasswordAsArgument(t *testing.T) {
	if initCmd.Flags().Lookup("admin-password") != nil {
		t.Fatal("init still exposes an admin-password process-argument flag")
	}
	for _, name := range []string{"admin-password-file", "admin-password-stdin"} {
		if initCmd.Flags().Lookup(name) == nil {
			t.Fatalf("init is missing --%s", name)
		}
	}
}

func TestInitCommandRequiresExplicitNonemptyDirectoryAcknowledgement(t *testing.T) {
	if initCmd.Flags().Lookup("allow-nonempty-directory") == nil {
		t.Fatal("init is missing --allow-nonempty-directory")
	}
}

func TestClassifyInitDirectoryFailsClosedForForeignContent(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{".git", "compose.yaml", "README.md"} {
		path := filepath.Join(root, name)
		if name == ".git" {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}

	existing, foreign := classifyInitDirectory(entries)

	if existing {
		t.Fatal("foreign directory was classified as an existing SDBX project")
	}
	if !reflect.DeepEqual(foreign, []string{"README.md", "compose.yaml"}) {
		t.Fatalf("foreign entries = %#v", foreign)
	}
}

func TestClassifyInitDirectoryRecognizesSDBXMarker(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{".sdbx.yaml", "README.md"} {
		if err := os.WriteFile(
			filepath.Join(root, name),
			[]byte("fixture"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}

	existing, foreign := classifyInitDirectory(entries)

	if !existing || len(foreign) != 0 {
		t.Fatalf("classification = existing:%t foreign:%#v", existing, foreign)
	}
}

func TestInitCommandRequiresTypedACMEContactInput(t *testing.T) {
	if initCmd.Flags().Lookup("acme-email") == nil {
		t.Fatal("init is missing --acme-email")
	}
	for _, value := range []string{"", "Display Name <ops@example.test>", "invalid"} {
		if err := validateACMEContactEmail(value); err == nil {
			t.Fatalf("invalid ACME contact %q was accepted", value)
		}
	}
	if err := validateACMEContactEmail("ops@example.test"); err != nil {
		t.Fatalf("valid ACME contact was rejected: %v", err)
	}
}

func TestApplyMediaServerChoiceRequiresExplicitKnownPolicy(t *testing.T) {
	tests := []struct {
		choice       string
		wantPlex     bool
		wantJellyfin bool
		wantError    bool
	}{
		{choice: "plex", wantPlex: true},
		{choice: "jellyfin", wantJellyfin: true},
		{choice: "both", wantPlex: true, wantJellyfin: true},
		{choice: "none"},
		{choice: "", wantError: true},
		{choice: "emby", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.choice, func(t *testing.T) {
			cfg := config.DefaultConfig()
			err := applyMediaServerChoice(cfg, test.choice)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError %t", err, test.wantError)
			}
			if err == nil && (cfg.PlexEnabled != test.wantPlex ||
				cfg.JellyfinEnabled != test.wantJellyfin) {
				t.Fatalf(
					"media policy = plex:%t jellyfin:%t, want plex:%t jellyfin:%t",
					cfg.PlexEnabled,
					cfg.JellyfinEnabled,
					test.wantPlex,
					test.wantJellyfin,
				)
			}
		})
	}
}

func TestApplyInitPresetKeepsMediaExplicitAndDeduplicatesExtras(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfg := config.DefaultConfig()
	cfg.PlexEnabled = true
	if err := applyInitPreset(cfg, "media-plex", []string{"sonarr", "filebrowser"}); err != nil {
		t.Fatal(err)
	}
	if !cfg.PlexEnabled || cfg.JellyfinEnabled {
		t.Fatalf("preset changed explicit media selection: %+v", cfg)
	}
	seen := make(map[string]bool)
	for _, addon := range cfg.Addons {
		if seen[addon] {
			t.Fatalf("duplicate addon %q in %v", addon, cfg.Addons)
		}
		seen[addon] = true
	}
	for _, expected := range []string{"sonarr", "prowlarr", "filebrowser"} {
		if !seen[expected] {
			t.Fatalf("preset addons %v omit %q", cfg.Addons, expected)
		}
	}

	cfg = config.DefaultConfig()
	err := applyInitPreset(cfg, "media-plex", nil)
	if err == nil || !strings.Contains(err.Error(), "requires Plex") {
		t.Fatalf("media-plex without Plex error = %v", err)
	}

	cfg = config.DefaultConfig()
	cfg.JellyfinEnabled = true
	if err := applyInitPreset(cfg, "power-user", nil); err != nil {
		t.Fatalf("media-neutral power-user preset with Jellyfin failed: %v", err)
	}
	if cfg.PlexEnabled || !cfg.JellyfinEnabled {
		t.Fatalf("power-user preset changed explicit media selection: %+v", cfg)
	}
	for _, expected := range []string{"sonarr", "prowlarr", "nzbhydra2", "filebrowser"} {
		if !slices.Contains(cfg.Addons, expected) {
			t.Fatalf("power-user addons %v omit %q", cfg.Addons, expected)
		}
	}

	if err := applyInitPreset(cfg, "none", []string{"sonarr"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.Addons, []string{"sonarr"}) {
		t.Fatalf("none preset addons = %v", cfg.Addons)
	}
}

func TestRunInitDryRunExercisesCompletePlanWithoutWritingOrLeakingCredential(t *testing.T) {
	projectDir := t.TempDir()
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(projectDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalDir)
	})

	t.Setenv("HOME", t.TempDir())
	viper.Reset()
	t.Cleanup(viper.Reset)

	password := "synthetic-correct-horse-battery-staple"
	passwordPath := filepath.Join(t.TempDir(), "admin-password")
	if err := os.WriteFile(passwordPath, []byte(password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	restoreInitTestGlobals(t)
	initDomain = "box.example.test"
	initExposeMode = config.ExposeModeCloudflared
	initRoutingStrategy = config.RoutingStrategySubdomain
	initTimezone = "Europe/Paris"
	initMediaServer = "none"
	initPreset = "none"
	initVPNEnabled = false
	initTorrentPort = 6881
	initAllowUnprotectedDownloads = true
	initSkipWizard = true
	initAdminUser = "admin"
	initAdminPasswordFile = passwordPath
	initDryRun = true

	// This orchestration test uses synthetic Docker state. Probe ephemeral
	// listeners so unrelated host services cannot occupy its planned ports.
	originalTCPListen, originalUDPListen := initTCPListen, initUDPListen
	initTCPListen = func(network, _ string) (net.Listener, error) {
		return net.Listen(network, "127.0.0.1:0")
	}
	initUDPListen = func(network, _ string) (net.PacketConn, error) {
		return net.ListenPacket(network, "127.0.0.1:0")
	}
	t.Cleanup(func() {
		initTCPListen, initUDPListen = originalTCPListen, originalUDPListen
	})

	originalResolverFactory := imageDigestResolverFactory
	imageDigestResolverFactory = func() registry.ImageDigestResolver {
		return commandTestImageResolver{}
	}
	t.Cleanup(func() {
		imageDigestResolverFactory = originalResolverFactory
	})

	originalDockerOutput := initDockerCommandOutput
	var dockerChecks []string
	initDockerCommandOutput = func(
		ctx context.Context,
		args ...string,
	) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		dockerChecks = append(dockerChecks, strings.Join(args, " "))
		switch args[0] {
		case "version":
			return []byte("28.3.3\n"), nil
		case "compose":
			return []byte("2.39.1\n"), nil
		case "buildx":
			return []byte("github.com/docker/buildx v0.29.1 synthetic\n"), nil
		default:
			return nil, errors.New("unexpected Docker command")
		}
	}
	t.Cleanup(func() {
		initDockerCommandOutput = originalDockerOutput
	})

	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.Flags().String("acme-email", "", "")
	command.Flags().Bool("vpn", false, "")
	command.Flags().Int("torrent-peer-port", 6881, "")
	command.Flags().String("admin-user", "admin", "")

	output := captureAddonOutput(t, func() error {
		return runInit(command, nil)
	})
	for _, expected := range []string{
		"Preflight",
		"Deployment preview",
		"Docker Engine",
		"Docker Compose",
		"Docker Buildx",
		"Dry run complete. No files were written.",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("dry-run output missing %q:\n%s", expected, output)
		}
	}
	if strings.Contains(output, password) {
		t.Fatal("dry-run output disclosed the admin password")
	}
	if len(dockerChecks) != 3 {
		t.Fatalf("Docker preflight calls = %#v, want three version checks", dockerChecks)
	}
	for _, name := range []string{".sdbx.yaml", ".sdbx.lock", "compose.yaml"} {
		if _, err := os.Lstat(filepath.Join(projectDir, name)); !os.IsNotExist(err) {
			t.Fatalf("dry run wrote %s: %v", name, err)
		}
	}
}

func restoreInitTestGlobals(t *testing.T) {
	t.Helper()
	oldDomain := initDomain
	oldExposeMode := initExposeMode
	oldACMEEmail := initACMEEmail
	oldRoutingStrategy := initRoutingStrategy
	oldTimezone := initTimezone
	oldMediaPath := initMediaPath
	oldDownloadsPath := initDownloadsPath
	oldConfigPath := initConfigPath
	oldLegacyConfigPath := initLegacyConfigPath
	oldMediaServer := initMediaServer
	oldPreset := initPreset
	oldAddons := append([]string(nil), initAddons...)
	oldVPNEnabled := initVPNEnabled
	oldVPNProvider := initVPNProvider
	oldVPNCountry := initVPNCountry
	oldTorrentPort := initTorrentPort
	oldAllowUnprotectedDownloads := initAllowUnprotectedDownloads
	oldSkipWizard := initSkipWizard
	oldAdminUser := initAdminUser
	oldAdminPasswordFile := initAdminPasswordFile
	oldAdminPasswordStdin := initAdminPasswordStdin
	oldDryRun := initDryRun
	oldYes := initYes
	oldForce := initForce
	oldAllowNonemptyDirectory := initAllowNonemptyDirectory

	initDomain = ""
	initExposeMode = ""
	initACMEEmail = ""
	initRoutingStrategy = ""
	initTimezone = ""
	initMediaPath = ""
	initDownloadsPath = ""
	initConfigPath = ""
	initLegacyConfigPath = ""
	initMediaServer = ""
	initPreset = ""
	initAddons = nil
	initVPNEnabled = false
	initVPNProvider = ""
	initVPNCountry = "France"
	initTorrentPort = 6881
	initAllowUnprotectedDownloads = false
	initSkipWizard = false
	initAdminUser = "admin"
	initAdminPasswordFile = ""
	initAdminPasswordStdin = false
	initDryRun = false
	initYes = false
	initForce = false
	initAllowNonemptyDirectory = false

	t.Cleanup(func() {
		initDomain = oldDomain
		initExposeMode = oldExposeMode
		initACMEEmail = oldACMEEmail
		initRoutingStrategy = oldRoutingStrategy
		initTimezone = oldTimezone
		initMediaPath = oldMediaPath
		initDownloadsPath = oldDownloadsPath
		initConfigPath = oldConfigPath
		initLegacyConfigPath = oldLegacyConfigPath
		initMediaServer = oldMediaServer
		initPreset = oldPreset
		initAddons = oldAddons
		initVPNEnabled = oldVPNEnabled
		initVPNProvider = oldVPNProvider
		initVPNCountry = oldVPNCountry
		initTorrentPort = oldTorrentPort
		initAllowUnprotectedDownloads = oldAllowUnprotectedDownloads
		initSkipWizard = oldSkipWizard
		initAdminUser = oldAdminUser
		initAdminPasswordFile = oldAdminPasswordFile
		initAdminPasswordStdin = oldAdminPasswordStdin
		initDryRun = oldDryRun
		initYes = oldYes
		initForce = oldForce
		initAllowNonemptyDirectory = oldAllowNonemptyDirectory
	})
}

func TestReadPrivateCredentialFileEnforcesPrivateRegularSingleLine(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "password")
	if err := os.WriteFile(path, []byte("correct-horse-battery-staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := readPrivateCredentialFile(path, "admin password")
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "correct-horse-battery-staple" {
		t.Fatalf("credential = %q", value)
	}
	zeroBytes(value)

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateCredentialFile(path, "admin password"); err == nil ||
		!strings.Contains(err.Error(), "0600") {
		t.Fatalf("permissive credential error = %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "password-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateCredentialFile(link, "admin password"); err == nil ||
		!strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink credential error = %v", err)
	}
}

func TestNormalizeCredentialLineRejectsAmbiguousInput(t *testing.T) {
	for _, input := range [][]byte{
		{},
		[]byte(" leading"),
		[]byte("trailing "),
		[]byte("first\nsecond\n"),
		[]byte("nul\x00byte"),
	} {
		if _, err := normalizeCredentialLine(input, "credential"); err == nil {
			t.Fatalf("normalizeCredentialLine(%q) succeeded", input)
		}
	}
}

func TestReadCredentialStdinAcceptsOneBoundedPrivateLine(t *testing.T) {
	withCredentialStdin(t, []byte("correct-horse-battery-staple\r\n"), func() {
		credential, err := readCredentialStdin("admin password")
		if err != nil {
			t.Fatal(err)
		}
		defer zeroBytes(credential)
		if string(credential) != "correct-horse-battery-staple" {
			t.Fatalf("credential = %q", credential)
		}
	})
}

func TestReadCredentialStdinRejectsAmbiguousOrOversizedInput(t *testing.T) {
	for name, input := range map[string][]byte{
		"multiple lines": []byte("first\nsecond\n"),
		"oversized":      bytes.Repeat([]byte("x"), maxCredentialBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			withCredentialStdin(t, input, func() {
				if _, err := readCredentialStdin("admin password"); err == nil {
					t.Fatal("unsafe stdin credential was accepted")
				}
			})
		})
	}
}

func withCredentialStdin(t *testing.T, input []byte, test func()) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() {
		os.Stdin = original
		_ = reader.Close()
	})
	if _, err := writer.Write(input); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	test()
}

func TestValidateStagedComposePropagatesParentCancellation(t *testing.T) {
	original := initDockerCommandOutput
	t.Cleanup(func() {
		initDockerCommandOutput = original
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var observed error
	initDockerCommandOutput = func(ctx context.Context, _ ...string) ([]byte, error) {
		observed = ctx.Err()
		return nil, ctx.Err()
	}

	err := validateStagedCompose(ctx, t.TempDir())
	if !errors.Is(observed, context.Canceled) {
		t.Fatalf("docker validation context error = %v, want cancellation", observed)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("validation error = %v, want cancellation", err)
	}
}

func TestValidateStagedComposeUsesHermeticResolutionFlags(t *testing.T) {
	original := initDockerCommandOutput
	t.Cleanup(func() {
		initDockerCommandOutput = original
	})

	var args []string
	initDockerCommandOutput = func(_ context.Context, got ...string) ([]byte, error) {
		args = append([]string(nil), got...)
		return nil, nil
	}

	stage := t.TempDir()
	if err := validateStagedCompose(context.Background(), stage); err != nil {
		t.Fatalf("validateStagedCompose() error = %v", err)
	}

	joined := strings.Join(args, " ")
	// compose.yaml keeps final absolute env-file paths while the transaction
	// writes those files under stage/external-config, so staged validation must
	// not resolve service env files. Docker Compose 2.35.0 is the first release
	// that accepts both flags; the documented minimum, the init preflight and
	// this call must stay in step.
	for _, required := range []string{
		"compose",
		"config",
		"--quiet",
		"--no-env-resolution",
		"--no-path-resolution",
		stage,
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("compose validation args = %v, want %q", args, required)
		}
	}
}

func TestFirstVersionParsesDockerToolOutputs(t *testing.T) {
	tests := map[string][3]int{
		"28.3.3": {28, 3, 3},
		"Docker Compose version v2.39.1-desktop.1": {2, 39, 1},
		"github.com/docker/buildx v0.29.1 123abc":  {0, 29, 1},
		"go1.26": {1, 26, 0},
	}
	for raw, expected := range tests {
		actual, err := firstVersion(raw)
		if err != nil {
			t.Fatalf("firstVersion(%q): %v", raw, err)
		}
		if actual != expected {
			t.Fatalf("firstVersion(%q) = %v, want %v", raw, actual, expected)
		}
	}
	if _, err := firstVersion("version unavailable"); err == nil {
		t.Fatal("firstVersion accepted output without a version")
	}
}

func TestParsePublishedPortSupportsHostAndIPv6Bindings(t *testing.T) {
	tests := []struct {
		raw  string
		want publishedPort
	}{
		{"443:443", publishedPort{Protocol: "tcp", Port: 443}},
		{"127.0.0.1:8080:80/tcp", publishedPort{Protocol: "tcp", Host: "127.0.0.1", Port: 8080}},
		{"[::1]:5353:53/udp", publishedPort{Protocol: "udp", Host: "::1", Port: 5353}},
	}
	for _, test := range tests {
		actual, err := parsePublishedPort(test.raw)
		if err != nil {
			t.Fatalf("parsePublishedPort(%q): %v", test.raw, err)
		}
		if actual != test.want {
			t.Fatalf("parsePublishedPort(%q) = %+v, want %+v", test.raw, actual, test.want)
		}
	}
	for _, invalid := range []string{"80", "0:80", "70000:80", "80:0", "80:70000", "80:80/sctp"} {
		if _, err := parsePublishedPort(invalid); err == nil {
			t.Fatalf("parsePublishedPort(%q) succeeded", invalid)
		}
	}
}

func TestCheckPublishedPortsRejectsOverlappingBindings(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	compose := &generator.ComposeFile{
		Services: map[string]generator.ComposeService{
			"edge": {Ports: []string{
				strings.Join([]string{"0.0.0.0", strconv.Itoa(port), "80"}, ":"),
			}},
			"admin": {Ports: []string{
				strings.Join([]string{"127.0.0.1", strconv.Itoa(port), "8080"}, ":"),
			}},
		},
	}
	if _, err := checkPublishedPorts(compose, false); err == nil ||
		!strings.Contains(err.Error(), "overlapping hosts") {
		t.Fatalf("overlapping binding error = %v", err)
	}
}

func TestCheckPublishedPortsReportsOccupiedBinding(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	compose := &generator.ComposeFile{
		Services: map[string]generator.ComposeService{
			"edge": {Ports: []string{
				strings.Join([]string{"127.0.0.1", strconv.Itoa(port), "80"}, ":"),
			}},
		},
	}
	if _, err := checkPublishedPorts(compose, false); err == nil ||
		!strings.Contains(err.Error(), "occupied") {
		t.Fatalf("occupied binding error = %v", err)
	}
	warnings, err := checkPublishedPorts(compose, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "existing-project") {
		t.Fatalf("occupied binding warnings = %v", warnings)
	}
}

func TestCheckPublishedPortsWarnsWhenPrivilegesPreventProbe(t *testing.T) {
	originalListen := initTCPListen
	initTCPListen = func(_, _ string) (net.Listener, error) {
		return nil, os.ErrPermission
	}
	t.Cleanup(func() {
		initTCPListen = originalListen
	})

	compose := &generator.ComposeFile{
		Services: map[string]generator.ComposeService{
			"traefik": {Ports: []string{"80:80"}},
		},
	}
	warnings, err := checkPublishedPorts(compose, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 ||
		!strings.Contains(warnings[0], "could not be verified") ||
		!strings.Contains(warnings[0], "permission denied") {
		t.Fatalf("permission warnings = %v", warnings)
	}
}

func TestCheckInitManagedPathsRejectsSymlinkAncestors(t *testing.T) {
	project := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ProjectDir = project
	if summary, err := checkInitManagedPaths(cfg); err != nil {
		t.Fatal(err)
	} else if !strings.Contains(summary, "root(s)") {
		t.Fatalf("path summary = %q", summary)
	}

	external := t.TempDir()
	if err := os.Symlink(external, filepath.Join(project, "linked-config")); err != nil {
		t.Fatal(err)
	}
	cfg.ConfigPath = "./linked-config/nested"
	if _, err := checkInitManagedPaths(cfg); err == nil ||
		!strings.Contains(err.Error(), "symlink ancestor") {
		t.Fatalf("symlink path error = %v", err)
	}
}

func TestInitServiceURLUsesResolvedCatalogRoute(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "box.example.test"
	definition := &registry.ServiceDefinition{}
	definition.Routing.Enabled = true
	definition.Routing.Subdomain = "auth"
	definition.Routing.Path = "/auth"
	if actual := initServiceURL(cfg, definition); actual != "https://auth.box.example.test" {
		t.Fatalf("subdomain URL = %q", actual)
	}
	cfg.Routing.Strategy = config.RoutingStrategyPath
	cfg.Routing.BaseDomain = "sdbx"
	if actual := initServiceURL(cfg, definition); actual != "https://sdbx.box.example.test/auth" {
		t.Fatalf("path URL = %q", actual)
	}
	definition.Routing.ForceSubdomain = true
	if actual := initServiceURL(cfg, definition); actual != "https://auth.box.example.test" {
		t.Fatalf("forced subdomain URL = %q", actual)
	}
}

func TestUniqueResolutionWarningsPreservesFirstOccurrence(t *testing.T) {
	one := registry.ResolutionWarning{Service: "one", Field: "field", Message: "message"}
	two := registry.ResolutionWarning{Service: "two", Field: "field", Message: "message"}
	actual := uniqueResolutionWarnings([]registry.ResolutionWarning{one, two, one})
	expected := []registry.ResolutionWarning{one, two}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("uniqueResolutionWarnings = %v, want %v", actual, expected)
	}
}
