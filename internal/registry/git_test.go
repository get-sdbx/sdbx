package registry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testCommitRef          = "0123456789abcdef0123456789abcdef01234567"
	testSigningFingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"
)

func TestGitCommandReliesOnStrictUserHostKeyPolicy(t *testing.T) {
	source, err := NewGitSource(Source{
		Name:       "private",
		Type:       "git",
		URL:        "git@example.com:org/services.git",
		Ref:        testCommitRef,
		SigningKey: testSigningFingerprint,
		SSHKey:     "/home/operator/.ssh/id_ed25519",
	}, NewCache(t.TempDir()))
	if err != nil {
		t.Fatalf("NewGitSource failed: %v", err)
	}

	cmd := source.gitCommand(context.Background(), "", "status")
	sshCommand := gitSSHCommand(cmd.Env)

	if sshCommand == "" {
		t.Fatal("GIT_SSH_COMMAND was not configured")
	}
	if strings.Contains(sshCommand, "StrictHostKeyChecking") {
		t.Fatalf("GIT_SSH_COMMAND overrides the user's strict host-key policy: %s", sshCommand)
	}
	if !strings.Contains(sshCommand, "IdentitiesOnly=yes") {
		t.Fatalf("GIT_SSH_COMMAND should restrict authentication to the configured identity: %s", sshCommand)
	}
}

func TestGitCommandDisablesRedirectsAndLFSMaterialization(t *testing.T) {
	source, err := NewGitSource(validGitSourceConfig(), NewCache(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	command := source.gitCommand(context.Background(), "", "fetch", "origin", testCommitRef)
	arguments := strings.Join(command.Args, "\x00")
	for _, required := range []string{
		"http.followRedirects=false",
		"protocol.allow=never",
		"protocol.https.allow=always",
		"protocol.ssh.allow=always",
		"submodule.recurse=false",
	} {
		if !strings.Contains(arguments, required) {
			t.Fatalf("git command is missing safety config %q: %v", required, command.Args)
		}
	}
	if !environmentContains(command.Env, "GIT_LFS_SKIP_SMUDGE=1") {
		t.Fatal("git command permits Git LFS smudge downloads")
	}
}

func TestGitSourceRejectsInvalidServiceNamesBeforeFetching(t *testing.T) {
	source, err := NewGitSource(validGitSourceConfig(), NewCache(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{
		"../outside",
		"addons/sonarr",
		"/absolute",
		"UPPERCASE",
		"",
	} {
		if _, err := source.LoadService(context.Background(), name); err == nil ||
			!strings.Contains(err.Error(), "invalid service name") {
			t.Fatalf("LoadService(%q) error = %v", name, err)
		}
		if path := source.GetServicePath(name); path != "" {
			t.Fatalf("GetServicePath(%q) = %q, want empty", name, path)
		}
		if source.HasService(context.Background(), name) {
			t.Fatalf("HasService(%q) = true", name)
		}
	}
	if source.cache.Exists(source.name) {
		t.Fatal("invalid lookup fetched or created an external source cache")
	}
}

func TestValidateSourceConfigRejectsMutableOrInsecureGitSources(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Source)
		want   string
	}{
		{
			name: "http URL",
			mutate: func(source *Source) {
				source.URL = "http://example.com/org/services.git"
			},
			want: "HTTPS or SSH",
		},
		{
			name: "URL credentials",
			mutate: func(source *Source) {
				source.URL = "https://token@example.com/org/services.git"
			},
			want: "must not contain credentials",
		},
		{
			name: "mutable branch",
			mutate: func(source *Source) {
				source.Ref = ""
				source.LegacyBranch = "main"
			},
			want: "mutable branch",
		},
		{
			name: "short ref",
			mutate: func(source *Source) {
				source.Ref = "deadbeef"
			},
			want: "exact 40- or 64-character",
		},
		{
			name: "missing signer",
			mutate: func(source *Source) {
				source.SigningKey = ""
			},
			want: "signingKey",
		},
		{
			name: "path traversal",
			mutate: func(source *Source) {
				source.Path = "../services"
			},
			want: "stay within",
		},
		{
			name: "unknown permission",
			mutate: func(source *Source) {
				source.Trust.AllowCatalogPermissions = []string{"host-root"}
			},
			want: "invalid catalog permission",
		},
		{
			name: "duplicate registry",
			mutate: func(source *Source) {
				source.Trust.AllowedRegistries = []string{"docker.io", "docker.io"}
			},
			want: "duplicate allowed registry",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := validGitSourceConfig()
			test.mutate(&source)
			err := ValidateSourceConfig(source)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateSourceConfig error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestVerifySignatureMetadataRequiresPinnedSigner(t *testing.T) {
	good := testCommitRef + "\nG\n" + testSigningFingerprint + "\n" + testSigningFingerprint + "\n"
	if err := verifySignatureMetadata(good, strings.ToLower(testSigningFingerprint)); err != nil {
		t.Fatalf("valid pinned signature rejected: %v", err)
	}

	unknownTrust := testCommitRef + "\nU\n" + testSigningFingerprint + "\n" + testSigningFingerprint + "\n"
	if err := verifySignatureMetadata(unknownTrust, testSigningFingerprint); err != nil {
		t.Fatalf("cryptographically valid pinned signature with unknown trust rejected: %v", err)
	}

	badSigner := testCommitRef + "\nG\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
	if err := verifySignatureMetadata(badSigner, testSigningFingerprint); err == nil {
		t.Fatal("signature from an unpinned signer was accepted")
	}

	unsigned := testCommitRef + "\nN\n\n\n"
	if err := verifySignatureMetadata(unsigned, testSigningFingerprint); err == nil {
		t.Fatal("unsigned commit was accepted")
	}
}

func TestVerifyCommitSignatureWithSSHSigningKey(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}

	repo := t.TempDir()
	keyPath := filepath.Join(repo, "signing_key")
	runCommand(t, "", "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", keyPath)
	runCommand(t, repo, "git", "init", "--quiet")
	runCommand(t, repo, "git", "config", "user.name", "SDBX Test")
	runCommand(t, repo, "git", "config", "user.email", "sdbx@example.test")
	runCommand(t, repo, "git", "config", "gpg.format", "ssh")
	runCommand(t, repo, "git", "config", "user.signingkey", keyPath)
	runCommand(t, repo, "git", "config", "commit.gpgsign", "true")

	publicKey, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	keyFields := strings.Fields(string(publicKey))
	if len(keyFields) < 2 {
		t.Fatalf("unexpected SSH public key: %q", publicKey)
	}
	allowedSignersPath := filepath.Join(repo, "allowed_signers")
	if err := os.WriteFile(
		allowedSignersPath,
		[]byte("sdbx "+keyFields[0]+" "+keyFields[1]+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	runCommand(t, repo, "git", "config", "gpg.ssh.allowedSignersFile", allowedSignersPath)

	if err := os.WriteFile(filepath.Join(repo, "catalog"), []byte("signed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runCommand(t, repo, "git", "add", "catalog")
	runCommand(t, repo, "git", "commit", "--quiet", "-m", "signed catalog")

	fingerprintOutput := runCommand(
		t,
		"",
		"ssh-keygen",
		"-lf",
		keyPath+".pub",
		"-E",
		"sha256",
	)
	fingerprintFields := strings.Fields(fingerprintOutput)
	if len(fingerprintFields) < 2 {
		t.Fatalf("unexpected ssh-keygen fingerprint output: %q", fingerprintOutput)
	}

	source := &GitSource{signingKey: fingerprintFields[1]}
	if err := source.verifyCommitSignature(context.Background(), repo); err != nil {
		t.Fatalf("verifyCommitSignature rejected a valid pinned SSH signature: %v", err)
	}
}

func TestRunGitRejectsExcessiveDiagnosticOutput(t *testing.T) {
	source := &GitSource{
		gitExecutable:      os.Args[0],
		commandTimeout:     time.Second,
		commandOutputLimit: 1_024,
	}

	_, err := source.runGit(
		context.Background(),
		"",
		"",
		"-test.run=TestGitCommandHelperProcess",
		"--",
		"output",
	)
	if !errors.Is(err, errExternalSourceOutputLimit) {
		t.Fatalf("runGit error = %v, want output-limit error", err)
	}
}

func TestRunGitRejectsSlowCommand(t *testing.T) {
	source := &GitSource{
		gitExecutable:  os.Args[0],
		commandTimeout: 25 * time.Millisecond,
	}

	_, err := source.runGit(
		context.Background(),
		"",
		"",
		"-test.run=TestGitCommandHelperProcess",
		"--",
		"slow",
	)
	if !errors.Is(err, errExternalSourceTimeout) {
		t.Fatalf("runGit error = %v, want timeout error", err)
	}
}

func TestRunGitRejectsStagingCacheGrowth(t *testing.T) {
	stagingPath := t.TempDir()
	source := &GitSource{
		gitExecutable:    os.Args[0],
		commandTimeout:   time.Second,
		monitorInterval:  time.Millisecond,
		cacheByteLimit:   1_024,
		cacheEntryLimit:  32,
		workingFileLimit: 1_024,
	}

	_, err := source.runGit(
		context.Background(),
		stagingPath,
		stagingPath,
		"-test.run=TestGitCommandHelperProcess",
		"--",
		"grow-cache",
	)
	var resourceErr *sourceResourceError
	if !errors.As(err, &resourceErr) {
		t.Fatalf("runGit error = %v, want source resource error", err)
	}
}

func TestRunGitRejectsOversizedPackGrowth(t *testing.T) {
	stagingPath := t.TempDir()
	source := &GitSource{
		gitExecutable:    os.Args[0],
		commandTimeout:   time.Second,
		monitorInterval:  time.Millisecond,
		cacheByteLimit:   1_024,
		cacheEntryLimit:  32,
		workingFileLimit: 1_024,
	}

	_, err := source.runGit(
		context.Background(),
		stagingPath,
		stagingPath,
		"-test.run=TestGitCommandHelperProcess",
		"--",
		"grow-pack",
	)
	var resourceErr *sourceResourceError
	if !errors.As(err, &resourceErr) {
		t.Fatalf("runGit error = %v, want source resource error", err)
	}
}

func TestParseGitObjectUsage(t *testing.T) {
	count, size, err := parseGitObjectUsage(
		"count: 2\nsize: 3\nin-pack: 5\npacks: 1\nsize-pack: 7\nprune-packable: 0\ngarbage: 0\n",
	)
	if err != nil {
		t.Fatalf("parseGitObjectUsage failed: %v", err)
	}
	if count != 7 {
		t.Fatalf("object count = %d, want 7", count)
	}
	if size != 10*1024 {
		t.Fatalf("object size = %d, want %d", size, 10*1024)
	}
}

func TestValidateGitObjectUsageRejectsExcessiveCount(t *testing.T) {
	err := validateGitObjectUsage(externalSourceObjectLimit+1, 1)
	var resourceErr *sourceResourceError
	if !errors.As(err, &resourceErr) {
		t.Fatalf("validateGitObjectUsage error = %v, want source resource error", err)
	}
}

func TestClonePromotesNormalSignedShallowSource(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}

	originPath := filepath.Join(t.TempDir(), "origin")
	if err := os.Mkdir(originPath, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "signing_key")
	runCommand(t, "", "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", keyPath)
	runCommand(t, originPath, "git", "init", "--quiet")
	runCommand(t, originPath, "git", "config", "user.name", "SDBX Test")
	runCommand(t, originPath, "git", "config", "user.email", "sdbx@example.test")
	runCommand(t, originPath, "git", "config", "gpg.format", "ssh")
	runCommand(t, originPath, "git", "config", "user.signingkey", keyPath)
	runCommand(t, originPath, "git", "config", "commit.gpgsign", "true")

	publicKey, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	keyFields := strings.Fields(string(publicKey))
	if len(keyFields) < 2 {
		t.Fatalf("unexpected SSH public key: %q", publicKey)
	}
	allowedSignersPath := filepath.Join(t.TempDir(), "allowed_signers")
	if err := os.WriteFile(
		allowedSignersPath,
		[]byte("sdbx "+keyFields[0]+" "+keyFields[1]+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	globalConfigPath := filepath.Join(t.TempDir(), "gitconfig")
	runCommand(
		t,
		"",
		"git",
		"config",
		"--file",
		globalConfigPath,
		"gpg.ssh.allowedSignersFile",
		allowedSignersPath,
	)
	t.Setenv("GIT_CONFIG_GLOBAL", globalConfigPath)

	catalogPath := filepath.Join(originPath, "services", "addons", "example")
	if err := os.MkdirAll(catalogPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(catalogPath, "service.yaml"),
		[]byte(`apiVersion: sdbx.one/v1
kind: Service
applicationAuth:
  mode: none
metadata:
  name: example
  version: 1.0.0
  category: utility
  description: Synthetic signed catalog service
spec:
  image:
    repository: alpine
    tag: latest
conditions:
  requireAddon: true
`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(originPath, "sources.yaml"),
		[]byte(`apiVersion: sdbx.one/v1
kind: SourceRepository
metadata:
  name: signed-test
  version: 1.0.0
schemaVersion: "1"
`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	runCommand(t, originPath, "git", "add", "services", "sources.yaml")
	runCommand(t, originPath, "git", "commit", "--quiet", "-m", "signed catalog")
	commit := strings.TrimSpace(runCommand(t, originPath, "git", "rev-parse", "HEAD"))
	fingerprintFields := strings.Fields(
		runCommand(t, "", "ssh-keygen", "-lf", keyPath+".pub", "-E", "sha256"),
	)
	if len(fingerprintFields) < 2 {
		t.Fatalf("unexpected ssh-keygen fingerprint output: %q", fingerprintFields)
	}

	cache := NewCache(t.TempDir())
	source := &GitSource{
		BaseSource: BaseSource{name: "signed-test"},
		url:        originPath,
		ref:        commit,
		signingKey: fingerprintFields[1],
		subPath:    "services",
		cache:      cache,
	}
	if err := source.clone(context.Background()); err != nil {
		t.Fatalf("clone rejected a normal signed shallow source: %v", err)
	}
	if !source.IsVerified() {
		t.Fatal("promoted source was not marked verified")
	}
	if source.GetCommit() != commit {
		t.Fatalf("source commit = %q, want %q", source.GetCommit(), commit)
	}
	if _, err := os.Stat(
		filepath.Join(cache.GetRepoPath("signed-test"), "services", "addons", "example", "service.yaml"),
	); err != nil {
		t.Fatalf("promoted catalog is missing: %v", err)
	}

	definitions, err := source.Load(context.Background())
	if err != nil {
		t.Fatalf("Load failed on verified cache: %v", err)
	}
	if len(definitions) != 1 || definitions[0].Metadata.Name != "example" {
		t.Fatalf("loaded definitions = %#v", definitions)
	}
	names, err := source.ListServices(context.Background())
	if err != nil {
		t.Fatalf("ListServices failed on verified cache: %v", err)
	}
	if len(names) != 1 || names[0] != "example" {
		t.Fatalf("service names = %#v", names)
	}
	definition, err := source.LoadService(context.Background(), "example")
	if err != nil {
		t.Fatalf("LoadService failed on verified cache: %v", err)
	}
	if definition.Metadata.Name != "example" {
		t.Fatalf("loaded definition = %#v", definition)
	}
	if _, err := source.LoadService(context.Background(), "missing"); !errors.Is(
		err,
		ErrServiceNotFound,
	) {
		t.Fatalf("missing service error = %v, want ErrServiceNotFound", err)
	}
	expectedServicePath := filepath.Join(
		cache.GetRepoPath("signed-test"),
		"services",
		"addons",
		"example",
		"service.yaml",
	)
	if path := source.GetServicePath("example"); path != expectedServicePath {
		t.Fatalf("service path = %q, want %q", path, expectedServicePath)
	}
	if !source.HasService(context.Background(), "example") ||
		source.HasService(context.Background(), "missing") {
		t.Fatal("HasService returned an inconsistent verified-cache result")
	}
	repository, err := source.GetRepoMetadata(context.Background())
	if err != nil {
		t.Fatalf("GetRepoMetadata failed on verified cache: %v", err)
	}
	if repository.Metadata.Name != "signed-test" {
		t.Fatalf("repository metadata = %#v", repository)
	}
	if source.GetURL() != originPath ||
		source.GetRef() != commit ||
		source.GetSigningKey() != fingerprintFields[1] ||
		source.GetSubPath() != "services" ||
		source.GetLastUpdated().IsZero() {
		t.Fatal("verified source metadata getters are inconsistent")
	}
	if err := source.Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch rejected the unchanged signed source: %v", err)
	}

	source.ref = strings.Repeat("0", 40)
	if err := source.Update(context.Background()); err == nil {
		t.Fatal("update unexpectedly accepted an unavailable immutable commit")
	}
	activeCommit := strings.TrimSpace(
		runCommand(t, cache.GetRepoPath("signed-test"), "git", "rev-parse", "HEAD"),
	)
	if activeCommit != commit {
		t.Fatalf("failed update replaced active commit %q with %q", commit, activeCommit)
	}
	assertNoSourceStagingDirs(t, cache)
	source.ref = commit

	activeDefinition := filepath.Join(
		cache.GetRepoPath("signed-test"),
		"services",
		"addons",
		"example",
		"service.yaml",
	)
	if err := os.WriteFile(activeDefinition, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := source.verifyCheckout(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "differs from its signed commit") {
		t.Fatalf("verifyCheckout accepted a dirty active cache: %v", err)
	}
}

func TestGitCommandHelperProcess(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		return
	}

	switch os.Args[separator+1] {
	case "output":
		_, _ = fmt.Print(strings.Repeat("diagnostic", 1_024))
	case "slow":
		time.Sleep(time.Second)
	case "grow-cache":
		_ = os.WriteFile("oversized", []byte(strings.Repeat("x", 8_192)), 0o600)
		time.Sleep(250 * time.Millisecond)
	case "grow-pack":
		_ = os.MkdirAll(filepath.Join(".git", "objects", "pack"), 0o700)
		packPath := filepath.Join(".git", "objects", "pack", "oversized.pack")
		_ = os.WriteFile(packPath, nil, 0o600)
		_ = os.Truncate(packPath, 8_192)
		time.Sleep(250 * time.Millisecond)
	default:
		os.Exit(2)
	}
	os.Exit(0)
}

func validGitSourceConfig() Source {
	return Source{
		Name:       "community",
		Type:       "git",
		URL:        "https://forgejo.example.com/org/services.git",
		Ref:        testCommitRef,
		SigningKey: testSigningFingerprint,
		Enabled:    true,
		Trust: TrustLevel{
			AllowedRegistries: []string{"docker.io"},
		},
	}
}

func gitSSHCommand(env []string) string {
	for _, item := range env {
		if strings.HasPrefix(item, "GIT_SSH_COMMAND=") {
			return strings.TrimPrefix(item, "GIT_SSH_COMMAND=")
		}
	}
	return ""
}

func environmentContains(environment []string, expected string) bool {
	for _, item := range environment {
		if item == expected {
			return true
		}
	}
	return false
}

func runCommand(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, output)
	}
	return string(output)
}

func assertNoSourceStagingDirs(t *testing.T, cache *Cache) {
	t.Helper()
	entries, err := os.ReadDir(cache.baseDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "-staging-") {
			t.Fatalf("partial staging cache was not removed: %s", entry.Name())
		}
	}
}
