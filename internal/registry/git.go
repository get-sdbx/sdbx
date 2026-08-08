package registry

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/get-sdbx/sdbx/internal/redact"
)

// GitSource implements SourceProvider for Git repository sources
type GitSource struct {
	BaseSource
	url        string
	ref        string
	signingKey string
	sshKey     string
	subPath    string
	cache      *Cache
	commit     string
	verified   bool

	// Tests override these process limits without weakening production defaults.
	gitExecutable      string
	commandTimeout     time.Duration
	commandOutputLimit int
	monitorInterval    time.Duration
	cacheByteLimit     int64
	cacheEntryLimit    int64
	workingFileLimit   int64
}

var (
	immutableGitRefPattern = regexp.MustCompile(`^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)
	sourceNamePattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	openPGPFingerprint     = regexp.MustCompile(`^(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$`)
	sshFingerprint         = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}=?$`)
	scpLikeGitURL          = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[A-Za-z0-9._~/-]+$`)
)

// ValidateSourceConfig validates a source before it is persisted or loaded.
func ValidateSourceConfig(src Source) error {
	switch src.Type {
	case "git":
		return validateGitSourceConfig(src)
	case "local":
		if !sourceNamePattern.MatchString(src.Name) {
			return fmt.Errorf("source name must be lowercase alphanumeric with hyphens")
		}
		return nil
	default:
		return fmt.Errorf("unsupported configurable source type %q", src.Type)
	}
}

func validateGitSourceConfig(src Source) error {
	if !sourceNamePattern.MatchString(src.Name) {
		return fmt.Errorf("source name must be lowercase alphanumeric with hyphens")
	}
	if err := validateGitSourceURL(src.URL); err != nil {
		return err
	}
	if !immutableGitRefPattern.MatchString(src.Ref) {
		if src.LegacyBranch != "" {
			return fmt.Errorf("mutable branch %q is no longer supported; configure an exact 40- or 64-character commit ref", src.LegacyBranch)
		}
		return fmt.Errorf("source ref must be an exact 40- or 64-character commit hash")
	}
	if !isValidSigningFingerprint(src.SigningKey) {
		return fmt.Errorf("signingKey must be a full OpenPGP or SHA256 SSH signing-key fingerprint")
	}
	if src.Path != "" {
		cleanPath := filepath.Clean(src.Path)
		if filepath.IsAbs(src.Path) || cleanPath == ".." ||
			strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) {
			return fmt.Errorf("source path must stay within the Git repository")
		}
	}
	seenPermissions := make(map[string]bool)
	for _, permission := range src.Trust.AllowCatalogPermissions {
		if permission != "*" && !isValidCatalogPermission(permission) &&
			permission != "capability:*" && permission != "secret:*" {
			return fmt.Errorf("invalid catalog permission grant %q", permission)
		}
		if seenPermissions[permission] {
			return fmt.Errorf("duplicate catalog permission grant %q", permission)
		}
		seenPermissions[permission] = true
	}
	seenRegistries := make(map[string]bool)
	for _, registry := range src.Trust.AllowedRegistries {
		if registry != "*" &&
			!regexp.MustCompile(`^[a-z0-9.-]+(?::[0-9]+)?$`).MatchString(registry) {
			return fmt.Errorf("invalid allowed registry %q", registry)
		}
		if seenRegistries[registry] {
			return fmt.Errorf("duplicate allowed registry %q", registry)
		}
		seenRegistries[registry] = true
	}
	return nil
}

func validateGitSourceURL(rawURL string) error {
	if rawURL == "" || strings.ContainsAny(rawURL, "\r\n\t ") {
		return fmt.Errorf("source URL is required and must not contain whitespace")
	}
	if scpLikeGitURL.MatchString(rawURL) {
		return nil
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid source URL: %w", err)
	}
	switch parsed.Scheme {
	case "https":
		if parsed.User != nil {
			return fmt.Errorf("source URL must not contain credentials; use a credential helper")
		}
	case "ssh":
		if parsed.User != nil {
			if _, hasPassword := parsed.User.Password(); hasPassword {
				return fmt.Errorf("source URL must not contain a password")
			}
		}
	default:
		return fmt.Errorf("source URL must use HTTPS or SSH")
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("source URL must include a host")
	}
	return nil
}

func isValidSigningFingerprint(fingerprint string) bool {
	return openPGPFingerprint.MatchString(fingerprint) ||
		sshFingerprint.MatchString(fingerprint)
}

func normalizeSigningFingerprint(fingerprint string) string {
	fingerprint = strings.TrimSpace(fingerprint)
	if openPGPFingerprint.MatchString(fingerprint) {
		return strings.ToUpper(fingerprint)
	}
	return fingerprint
}

// NewGitSource creates a new Git source
func NewGitSource(src Source, cache *Cache) (*GitSource, error) {
	if err := ValidateSourceConfig(src); err != nil {
		return nil, err
	}

	sshKey := src.SSHKey
	if sshKey == "" {
		sshKey = src.LegacySSHKey
	}

	return &GitSource{
		BaseSource: BaseSource{
			name:     src.Name,
			srcType:  "git",
			priority: src.Priority,
			enabled:  src.Enabled,
			trust:    src.Trust,
			loader:   NewLoader(),
		},
		url:           src.URL,
		ref:           strings.ToLower(src.Ref),
		signingKey:    normalizeSigningFingerprint(src.SigningKey),
		sshKey:        sshKey,
		subPath:       src.Path,
		cache:         cache,
		gitExecutable: "git",
	}, nil
}

// Load loads all service definitions from the Git source
func (s *GitSource) Load(ctx context.Context) ([]*ServiceDefinition, error) {
	// Ensure repo is cloned/updated
	if err := s.ensureCloned(ctx); err != nil {
		return nil, err
	}

	servicesPath := s.getServicesPath()
	return s.loader.LoadServicesFromDir(servicesPath)
}

// LoadService loads a specific service definition
func (s *GitSource) LoadService(ctx context.Context, name string) (*ServiceDefinition, error) {
	if err := validateServiceLookupName(name); err != nil {
		return nil, err
	}
	if err := s.ensureCloned(ctx); err != nil {
		return nil, err
	}

	servicesPath := s.getServicesPath()

	// Try direct path
	path := filepath.Join(servicesPath, name, "service.yaml")
	if _, err := os.Stat(path); err == nil {
		return s.loader.LoadServiceDefinition(path)
	}

	// Try core/ subdirectory
	path = filepath.Join(servicesPath, "core", name, "service.yaml")
	if _, err := os.Stat(path); err == nil {
		return s.loader.LoadServiceDefinition(path)
	}

	// Try addons/ subdirectory
	path = filepath.Join(servicesPath, "addons", name, "service.yaml")
	if _, err := os.Stat(path); err == nil {
		return s.loader.LoadServiceDefinition(path)
	}

	return nil, fmt.Errorf("%w: service %s in source %s", ErrServiceNotFound, name, s.name)
}

// ListServices returns names of all available services
func (s *GitSource) ListServices(ctx context.Context) ([]string, error) {
	if err := s.ensureCloned(ctx); err != nil {
		return nil, err
	}

	servicesPath := s.getServicesPath()
	return s.loader.DiscoverServices(servicesPath)
}

// GetServicePath returns the path to a service definition
func (s *GitSource) GetServicePath(name string) string {
	if validateServiceLookupName(name) != nil {
		return ""
	}
	servicesPath := s.getServicesPath()

	// Check direct path
	path := filepath.Join(servicesPath, name, "service.yaml")
	if _, err := os.Stat(path); err == nil {
		return path
	}

	// Check core/
	path = filepath.Join(servicesPath, "core", name, "service.yaml")
	if _, err := os.Stat(path); err == nil {
		return path
	}

	// Check addons/
	path = filepath.Join(servicesPath, "addons", name, "service.yaml")
	if _, err := os.Stat(path); err == nil {
		return path
	}

	return filepath.Join(servicesPath, name, "service.yaml")
}

// Update updates the Git repository
func (s *GitSource) Update(ctx context.Context) error {
	if !s.isCloned() {
		return s.clone(ctx)
	}

	if err := s.verifyRemote(ctx); err != nil {
		return err
	}
	return s.fetchCheckoutAndVerify(ctx)
}

// GetCommit returns the current commit hash
func (s *GitSource) GetCommit() string {
	return s.commit
}

// IsVerified returns whether the pinned commit signature has been verified.
func (s *GitSource) IsVerified() bool {
	return s.verified
}

// GetURL returns the Git repository URL
func (s *GitSource) GetURL() string {
	return s.url
}

// GetRef returns the immutable commit referenced by this source.
func (s *GitSource) GetRef() string {
	return s.ref
}

// GetSigningKey returns the configured signer fingerprint.
func (s *GitSource) GetSigningKey() string {
	return s.signingKey
}

// GetSubPath returns the repository-relative service catalog path.
func (s *GitSource) GetSubPath() string {
	return s.subPath
}

// ensureCloned ensures the repository is cloned and up to date
func (s *GitSource) ensureCloned(ctx context.Context) error {
	if s.isCloned() {
		if s.cache.NeedsUpdate(s.name) {
			return s.Update(ctx)
		}
		if err := s.verifyRemote(ctx); err != nil {
			return err
		}
		return s.verifyCheckout(ctx)
	}

	return s.clone(ctx)
}

// isCloned checks if the repository is already cloned
func (s *GitSource) isCloned() bool {
	repoPath := s.cache.GetRepoPath(s.name)
	gitPath := filepath.Join(repoPath, ".git")
	info, err := os.Lstat(gitPath)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

// clone clones the Git repository
func (s *GitSource) clone(ctx context.Context) error {
	repoPath := s.cache.GetRepoPath(s.name)

	if err := os.MkdirAll(filepath.Dir(repoPath), 0o700); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	if entries, err := os.ReadDir(repoPath); err == nil && len(entries) > 0 {
		return fmt.Errorf("source cache path exists and is not an initialized Git repository: %s", repoPath)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to inspect source cache path: %w", err)
	}
	return s.fetchCheckoutAndVerify(ctx)
}

func (s *GitSource) fetchCheckoutAndVerify(ctx context.Context) error {
	operationContext, operationCancel := context.WithTimeout(ctx, externalSourceFetchTimeout)
	defer operationCancel()

	stagingPath, err := s.cache.CreateStagingDir(s.name)
	if err != nil {
		return err
	}
	stagingOwned := true
	defer func() {
		if stagingOwned {
			_ = os.RemoveAll(stagingPath)
		}
	}()

	if _, err := s.runGit(operationContext, stagingPath, stagingPath, "init", "--quiet"); err != nil {
		return fmt.Errorf("git init failed: %w", err)
	}
	if _, err := s.runGit(operationContext, stagingPath, stagingPath, "remote", "add", "origin", s.url); err != nil {
		return fmt.Errorf("git remote configuration failed: %w", err)
	}
	if _, err := s.runGit(
		operationContext,
		stagingPath,
		stagingPath,
		"-c",
		"protocol.version=2",
		"fetch",
		"--depth=1",
		"--no-tags",
		"--filter="+externalSourceBlobFilterArgument,
		"origin",
		s.ref,
	); err != nil {
		return fmt.Errorf("git fetch of immutable ref failed: %w", err)
	}
	if err := s.validateGitObjectBudget(operationContext, stagingPath); err != nil {
		return err
	}
	if err := s.verifyFetchedCommit(operationContext, stagingPath); err != nil {
		return err
	}
	if _, err := s.runGit(
		operationContext,
		stagingPath,
		stagingPath,
		"checkout",
		"--detach",
		"--force",
		"--no-recurse-submodules",
		"FETCH_HEAD",
	); err != nil {
		return fmt.Errorf("git checkout of immutable ref failed: %w", err)
	}
	if err := validateSourceWorkingTree(stagingPath); err != nil {
		return fmt.Errorf("validate external source checkout: %w", err)
	}
	if err := s.validateGitObjectBudget(operationContext, stagingPath); err != nil {
		return err
	}
	if err := s.verifyRemoteAt(operationContext, stagingPath); err != nil {
		return err
	}
	commit, err := s.verifyCheckoutAt(operationContext, stagingPath)
	if err != nil {
		return err
	}
	if err := s.cache.ValidatePromotionBudget(s.name, stagingPath); err != nil {
		return err
	}
	if err := s.cache.PromoteRepo(s.name, stagingPath); err != nil {
		return err
	}
	stagingOwned = false
	s.commit = commit
	s.verified = true
	s.cache.MarkUpdated(s.name)
	return nil
}

func (s *GitSource) verifyRemote(ctx context.Context) error {
	repoPath := s.cache.GetRepoPath(s.name)
	return s.verifyRemoteAt(ctx, repoPath)
}

func (s *GitSource) verifyRemoteAt(ctx context.Context, repoPath string) error {
	output, err := s.runGit(ctx, repoPath, "", "remote", "get-url", "origin")
	if err != nil {
		return fmt.Errorf("failed to read cached source remote: %w", err)
	}
	if actual := strings.TrimSpace(string(output)); actual != s.url {
		return fmt.Errorf("cached source remote mismatch: expected %q, got %q", s.url, actual)
	}
	return nil
}

func (s *GitSource) verifyCheckout(ctx context.Context) error {
	repoPath := s.cache.GetRepoPath(s.name)
	commit, err := s.verifyCheckoutAt(ctx, repoPath)
	if err != nil {
		s.verified = false
		return err
	}
	s.commit = commit
	s.verified = true
	return nil
}

func (s *GitSource) verifyCheckoutAt(ctx context.Context, repoPath string) (string, error) {
	if err := validateSourceWorkingTree(repoPath); err != nil {
		return "", fmt.Errorf("validate external source checkout: %w", err)
	}
	if err := s.validateGitObjectBudget(ctx, repoPath); err != nil {
		return "", err
	}
	status, err := s.runGit(ctx, repoPath, "", "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return "", fmt.Errorf("inspect cached source worktree: %w", err)
	}
	if strings.TrimSpace(string(status)) != "" {
		return "", fmt.Errorf("cached source worktree differs from its signed commit")
	}

	output, err := s.runGit(ctx, repoPath, "", "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("failed to get cached source commit: %w", err)
	}
	commit := strings.ToLower(strings.TrimSpace(string(output)))
	if commit != s.ref {
		return "", fmt.Errorf("cached source commit mismatch: expected %s, got %s", s.ref, commit)
	}
	if err := s.verifyCommitSignature(ctx, repoPath); err != nil {
		return "", err
	}
	return commit, nil
}

func (s *GitSource) verifyCommitSignature(ctx context.Context, repoPath string) error {
	return s.verifyRevisionSignature(ctx, repoPath, "HEAD")
}

func (s *GitSource) verifyFetchedCommit(ctx context.Context, repoPath string) error {
	output, err := s.runGit(ctx, repoPath, "", "rev-parse", "FETCH_HEAD")
	if err != nil {
		return fmt.Errorf("failed to inspect fetched source commit: %w", err)
	}
	commit := strings.ToLower(strings.TrimSpace(string(output)))
	if commit != s.ref {
		return fmt.Errorf("fetched source commit mismatch: expected %s, got %s", s.ref, commit)
	}
	return s.verifyRevisionSignature(ctx, repoPath, "FETCH_HEAD")
}

func (s *GitSource) verifyRevisionSignature(
	ctx context.Context,
	repoPath string,
	revision string,
) error {
	output, err := s.runGit(
		ctx,
		repoPath,
		"",
		"log",
		"-1",
		"--format=%H%n%G?%n%GF%n%GP",
		revision,
	)
	if err != nil {
		return fmt.Errorf("failed to inspect source commit signature: %w", err)
	}
	return verifySignatureMetadata(string(output), s.signingKey)
}

func (s *GitSource) validateGitObjectBudget(ctx context.Context, repoPath string) error {
	output, err := s.runGit(ctx, repoPath, repoPath, "count-objects", "-v")
	if err != nil {
		return fmt.Errorf("inspect external source Git objects: %w", err)
	}
	objectCount, objectBytes, err := parseGitObjectUsage(string(output))
	if err != nil {
		return fmt.Errorf("inspect external source Git objects: %w", err)
	}
	return validateGitObjectUsage(objectCount, objectBytes)
}

func validateGitObjectUsage(objectCount, objectBytes int64) error {
	if objectCount > externalSourceObjectLimit {
		return &sourceResourceError{
			resource: "Git object count",
			limit:    externalSourceObjectLimit,
		}
	}
	if objectBytes > externalSourceCacheLimit {
		return &sourceResourceError{
			resource: "Git object byte",
			limit:    externalSourceCacheLimit,
		}
	}
	return nil
}

func (s *GitSource) runGit(
	ctx context.Context,
	dir string,
	monitorDir string,
	args ...string,
) ([]byte, error) {
	commandContext, cancel := context.WithTimeout(ctx, s.effectiveCommandTimeout())
	defer cancel()

	output := newBoundedCommandOutput(s.effectiveOutputLimit(), cancel)
	command := s.gitCommand(commandContext, dir, args...)
	command.Stdout = output
	command.Stderr = output
	command.WaitDelay = 2 * time.Second

	monitorDone := make(chan struct{})
	monitorStopped := make(chan struct{})
	monitorViolation := make(chan error, 1)
	if monitorDir != "" {
		go func() {
			defer close(monitorStopped)
			monitorSourceDirectory(
				commandContext,
				monitorDone,
				monitorViolation,
				cancel,
				monitorDir,
				s.cache,
				s.effectiveMonitorLimits(),
				s.effectiveMonitorInterval(),
			)
		}()
	}

	commandErr := command.Run()
	close(monitorDone)
	if monitorDir != "" {
		<-monitorStopped
	}

	select {
	case violation := <-monitorViolation:
		return output.Bytes(), violation
	default:
	}
	if output.Exceeded() {
		return output.Bytes(), errExternalSourceOutputLimit
	}
	if ctx.Err() != nil {
		return output.Bytes(), ctx.Err()
	}
	if commandContext.Err() == context.DeadlineExceeded {
		return output.Bytes(), errExternalSourceTimeout
	}
	if commandErr != nil {
		diagnostic := strings.TrimSpace(string(output.Bytes()))
		if diagnostic == "" {
			return output.Bytes(), commandErr
		}
		return output.Bytes(), fmt.Errorf(
			"%s: %w",
			redact.Text(diagnostic),
			commandErr,
		)
	}
	return output.Bytes(), nil
}

func (s *GitSource) effectiveCommandTimeout() time.Duration {
	if s.commandTimeout > 0 {
		return s.commandTimeout
	}
	return externalSourceFetchTimeout
}

func (s *GitSource) effectiveOutputLimit() int {
	if s.commandOutputLimit > 0 {
		return s.commandOutputLimit
	}
	return externalSourceOutputLimit
}

func (s *GitSource) effectiveMonitorInterval() time.Duration {
	if s.monitorInterval > 0 {
		return s.monitorInterval
	}
	return externalSourceMonitorInterval
}

func (s *GitSource) effectiveMonitorLimits() sourceDirectoryLimits {
	cacheByteLimit := s.cacheByteLimit
	if cacheByteLimit <= 0 {
		cacheByteLimit = externalSourceCacheLimit
	}
	cacheEntryLimit := s.cacheEntryLimit
	if cacheEntryLimit <= 0 {
		cacheEntryLimit = externalSourceCacheEntryLimit
	}
	workingFileLimit := s.workingFileLimit
	if workingFileLimit <= 0 {
		workingFileLimit = externalSourceWorkingFileLimit
	}
	return sourceDirectoryLimits{
		maxBytes:            cacheByteLimit,
		maxEntries:          cacheEntryLimit,
		maxWorkingFileBytes: workingFileLimit,
		rejectSymlinks:      true,
	}
}

func monitorSourceDirectory(
	ctx context.Context,
	done <-chan struct{},
	violation chan<- error,
	cancel context.CancelFunc,
	root string,
	cache *Cache,
	limits sourceDirectoryLimits,
	interval time.Duration,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	inspect := func() bool {
		_, err := inspectSourceDirectory(root, limits)
		if err == nil {
			if cache == nil {
				return false
			}
			_, err = inspectSourceDirectory(cache.baseDir, sourceDirectoryLimits{
				maxBytes:   externalSourceGlobalCacheLimit + externalSourceCacheLimit,
				maxEntries: externalSourceCacheEntryLimit * 5,
			})
			if err == nil {
				return false
			}
		}
		select {
		case violation <- fmt.Errorf("monitor external source staging cache: %w", err):
		default:
		}
		cancel()
		return true
	}
	if inspect() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			if inspect() {
				return
			}
		}
	}
}

func verifySignatureMetadata(output, expectedFingerprint string) error {
	lines := strings.Split(strings.TrimRight(output, "\r\n"), "\n")
	if len(lines) < 3 {
		return fmt.Errorf("source commit signature metadata is incomplete")
	}
	status := strings.TrimSpace(lines[1])
	if status != "G" && status != "U" {
		return fmt.Errorf("source commit does not have a cryptographically valid signature (git status %q)", status)
	}
	signingFingerprint := normalizeSigningFingerprint(lines[2])
	primaryFingerprint := ""
	if len(lines) >= 4 {
		primaryFingerprint = normalizeSigningFingerprint(lines[3])
	}
	expectedFingerprint = normalizeSigningFingerprint(expectedFingerprint)
	if expectedFingerprint != signingFingerprint && expectedFingerprint != primaryFingerprint {
		return fmt.Errorf("source commit signer mismatch: expected fingerprint %s", expectedFingerprint)
	}
	return nil
}

// gitCommand creates a git command with optional SSH key
func (s *GitSource) gitCommand(ctx context.Context, dir string, args ...string) *exec.Cmd {
	executable := s.gitExecutable
	if executable == "" {
		executable = "git"
	}
	if executable == "git" {
		safetyArgs := []string{
			"-c", "http.followRedirects=false",
			"-c", "core.bigFileThreshold=4m",
			"-c", "core.deltaBaseCacheLimit=16m",
			"-c", "pack.deltaCacheSize=16m",
			"-c", "pack.windowMemory=16m",
			"-c", "pack.threads=1",
			"-c", "index.threads=1",
			"-c", "submodule.recurse=false",
		}
		if validateGitSourceURL(s.url) == nil {
			safetyArgs = append(
				safetyArgs,
				"-c", "protocol.allow=never",
				"-c", "protocol.https.allow=always",
				"-c", "protocol.ssh.allow=always",
			)
		}
		args = append(safetyArgs, args...)
	}
	// #nosec G204 -- production constructors fix the executable to Git; the
	// unexported override exists only for bounded-process unit tests.
	cmd := exec.CommandContext(ctx, executable, args...)
	if dir != "" {
		cmd.Dir = dir
	}

	// Set up SSH key if provided
	if s.sshKey != "" {
		// Expand ~ in path
		sshKey := s.sshKey
		if len(sshKey) > 0 && sshKey[0] == '~' {
			home, _ := os.UserHomeDir()
			sshKey = filepath.Join(home, sshKey[1:])
		}

		env := os.Environ()
		env = append(
			env,
			fmt.Sprintf(
				"GIT_SSH_COMMAND=ssh -i %s -o IdentitiesOnly=yes -o BatchMode=yes",
				shellQuote(sshKey),
			),
		)
		cmd.Env = env
	}
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	cmd.Env = append(
		cmd.Env,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_LFS_SKIP_SMUDGE=1",
	)

	return cmd
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// getServicesPath returns the path to the services directory
func (s *GitSource) getServicesPath() string {
	repoPath := s.cache.GetRepoPath(s.name)
	if s.subPath != "" {
		return filepath.Join(repoPath, s.subPath)
	}
	return repoPath
}

// GetRepoMetadata loads the repository metadata
func (s *GitSource) GetRepoMetadata(ctx context.Context) (*SourceRepository, error) {
	if err := s.ensureCloned(ctx); err != nil {
		return nil, err
	}

	repoPath := s.cache.GetRepoPath(s.name)
	metaPath := filepath.Join(repoPath, "sources.yaml")

	if _, err := os.Stat(metaPath); err != nil {
		return nil, fmt.Errorf("repository metadata not found")
	}

	return s.loader.LoadSourceRepository(metaPath)
}

// Fetch fetches updates without merging
func (s *GitSource) Fetch(ctx context.Context) error {
	if !s.isCloned() {
		return s.clone(ctx)
	}
	if err := s.verifyRemote(ctx); err != nil {
		return err
	}
	return s.fetchCheckoutAndVerify(ctx)
}

// GetLastUpdated returns when the source was last updated
func (s *GitSource) GetLastUpdated() time.Time {
	return s.cache.GetLastUpdated(s.name)
}

// HasService checks if a service exists in this source
func (s *GitSource) HasService(ctx context.Context, name string) bool {
	if validateServiceLookupName(name) != nil {
		return false
	}
	if err := s.ensureCloned(ctx); err != nil {
		return false
	}

	servicesPath := s.getServicesPath()
	paths := []string{
		filepath.Join(servicesPath, name, "service.yaml"),
		filepath.Join(servicesPath, "core", name, "service.yaml"),
		filepath.Join(servicesPath, "addons", name, "service.yaml"),
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	return false
}
