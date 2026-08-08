package registry

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/get-sdbx/sdbx/internal/config"
	"gopkg.in/yaml.v3"
)

const lockSchemaVersion = 2

const maxGeneratedFileBytes = 16 << 20

// LockOptions controls explicit development exceptions and release metadata.
type LockOptions struct {
	CLIVersion        string
	AllowLocalSources bool
	ImageResolver     ImageDigestResolver
	TargetPlatform    string
}

// ResolvedImage records an immutable image manifest plus optional per-platform
// manifests. The top-level digest should normally identify a multi-platform
// OCI index.
type ResolvedImage struct {
	Digest          string
	PlatformDigests map[string]string
}

// ImageDigestResolver resolves a mutable image tag to immutable OCI digests.
type ImageDigestResolver interface {
	Resolve(ctx context.Context, repository, tag string) (ResolvedImage, error)
}

type lockedImageResolver struct {
	images   map[string]ResolvedImage
	fallback ImageDigestResolver
}

// NewLockedImageResolver reuses only the digests already present in a validated
// lock. Verification and diff operations therefore perform no registry refresh.
func NewLockedImageResolver(lock *LockFile) (ImageDigestResolver, error) {
	if err := ValidateLockFile(lock, true); err != nil {
		return nil, err
	}
	resolver := &lockedImageResolver{images: make(map[string]ResolvedImage, len(lock.Services))}
	for name, service := range lock.Services {
		reference, err := imageReference(service.Image.Repository, service.Image.Tag)
		if err != nil {
			return nil, fmt.Errorf("locked service %s has invalid image reference: %w", name, err)
		}
		resolved := ResolvedImage{
			Digest:          service.Image.Digest,
			PlatformDigests: cloneSortedMap(service.Image.PlatformDigests),
		}
		if existing, ok := resolver.images[reference]; ok &&
			!reflect.DeepEqual(existing, resolved) {
			return nil, fmt.Errorf("lock contains conflicting digests for image %s", reference)
		}
		resolver.images[reference] = resolved
	}
	return resolver, nil
}

// NewUpdatingImageResolver reuses existing pins and resolves only image
// references newly introduced by an explicit lock-changing operation.
func NewUpdatingImageResolver(
	lock *LockFile,
	fallback ImageDigestResolver,
) (ImageDigestResolver, error) {
	if fallback == nil {
		return nil, fmt.Errorf("fallback image resolver is required")
	}
	resolver, err := NewLockedImageResolver(lock)
	if err != nil {
		return nil, err
	}
	typed := resolver.(*lockedImageResolver)
	typed.fallback = fallback
	return typed, nil
}

func (r *lockedImageResolver) Resolve(
	ctx context.Context,
	repository, tag string,
) (ResolvedImage, error) {
	reference, err := imageReference(repository, tag)
	if err != nil {
		return ResolvedImage{}, err
	}
	resolved, ok := r.images[reference]
	if !ok {
		if r.fallback == nil {
			return ResolvedImage{}, fmt.Errorf("image %s is not present in the existing lock", reference)
		}
		resolved, err = r.fallback.Resolve(ctx, repository, tag)
		if err != nil {
			return ResolvedImage{}, err
		}
		r.images[reference] = resolved
	}
	return resolved, nil
}

// LockFileDiff represents one reproducibility-relevant lock change.
type LockFileDiff struct {
	Type        string `json:"type"` // "added", "removed", "changed"
	Description string `json:"description"`
}

// GenerateLockFileWithOptions is the single lock generation implementation.
func (r *Registry) GenerateLockFileWithOptions(
	ctx context.Context,
	cfg *config.Config,
	options LockOptions,
) (*LockFile, []ResolutionWarning, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("project configuration is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid project configuration: %w", err)
	}
	if options.CLIVersion == "" {
		return nil, nil, fmt.Errorf("CLI version is required for lock generation")
	}
	targetPlatform := options.TargetPlatform
	if targetPlatform == "" {
		targetPlatform = "linux/" + runtime.GOARCH
	}
	if !isValidPlatform(targetPlatform) {
		return nil, nil, fmt.Errorf("invalid target platform %q", targetPlatform)
	}

	graph, err := r.Resolve(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve services: %w", err)
	}
	if len(graph.Errors) > 0 {
		return nil, graph.Warnings, fmt.Errorf("service resolution failed: %w", graph.Errors[0])
	}

	configDigest, err := calculateLockConfigDigest(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate config digest: %w", err)
	}
	lockedSources, catalogDigest, err := r.lockSources(ctx, options.AllowLocalSources)
	if err != nil {
		return nil, nil, err
	}

	lock := &LockFile{
		APIVersion: APIVersion,
		Kind:       KindLockFile,
		Metadata: LockFileMetadata{
			Version:        lockSchemaVersion,
			GeneratedAt:    time.Now().UTC(),
			CLIVersion:     options.CLIVersion,
			CatalogVersion: catalogDigest,
			ConfigDigest:   configDigest,
			CatalogDigest:  catalogDigest,
		},
		Sources:        lockedSources,
		Services:       make(map[string]LockedService),
		InstallOrder:   append([]string(nil), graph.Order...),
		GeneratedFiles: make(map[string]string),
	}

	for _, name := range graph.Order {
		resolved := graph.Services[name]
		if resolved == nil || !resolved.Enabled {
			continue
		}
		def := resolved.FinalDefinition
		image := LockedImage{
			Registry:   def.Spec.Image.Registry,
			Repository: def.Spec.Image.Repository,
			Tag:        def.Spec.Image.Tag,
		}
		if options.ImageResolver != nil {
			resolvedImage, err := options.ImageResolver.Resolve(
				ctx,
				def.Spec.Image.Repository,
				def.Spec.Image.Tag,
			)
			if err != nil {
				return nil, graph.Warnings, fmt.Errorf("failed to resolve image for %s: %w", name, err)
			}
			image.Digest = resolvedImage.Digest
			image.PlatformDigests = cloneSortedMap(resolvedImage.PlatformDigests)
			image.Platform, image.PlatformDigest, err = selectPlatformDigest(
				targetPlatform,
				resolvedImage.PlatformDigests,
			)
			if err != nil {
				return nil, graph.Warnings, fmt.Errorf(
					"image for %s does not support target platform: %w",
					name,
					err,
				)
			}
		}

		lock.Services[name] = LockedService{
			Source:            resolved.Source,
			DefinitionVersion: def.Metadata.Version,
			DefinitionDigest:  resolved.DefinitionHash,
			Image:             image,
			ResolvedFrom:      resolved.SourcePath,
		}
	}

	if err := ValidateLockFile(lock, options.ImageResolver != nil); err != nil {
		return nil, graph.Warnings, err
	}
	return lock, graph.Warnings, nil
}

func (r *Registry) lockSources(
	ctx context.Context,
	allowLocalSources bool,
) (map[string]LockedSource, string, error) {
	locked := make(map[string]LockedSource)
	catalogEntries := make([]string, 0, len(r.sources))

	for _, source := range r.Sources() {
		if !source.IsEnabled() {
			continue
		}
		if source.Type() == "local" && !allowLocalSources {
			return nil, "", fmt.Errorf(
				"local source %q cannot be recorded in a release lock; use the explicit development override",
				source.Name(),
			)
		}

		definitions, err := source.Load(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("failed to load source %s for locking: %w", source.Name(), err)
		}
		definitionEntries := make([]string, 0, len(definitions))
		for _, definition := range definitions {
			if err := r.validateServiceSourceBoundary(
				ctx,
				source,
				definition.Metadata.Name,
				definition,
			); err != nil {
				return nil, "", err
			}
			validationErrors := r.validator.ValidateWithTrustLevel(definition, source.TrustLevel())
			if HasErrors(validationErrors) {
				return nil, "", fmt.Errorf(
					"invalid service %s from source %s: %s",
					definition.Metadata.Name,
					source.Name(),
					formatValidationErrors(validationErrors),
				)
			}
			digest, err := hashServiceDefinition(definition)
			if err != nil {
				return nil, "", err
			}
			definitionEntries = append(
				definitionEntries,
				definition.Metadata.Name+"="+digest,
			)
		}
		if embedded, ok := source.(*EmbeddedSource); ok {
			definitionEntries = append(
				definitionEntries,
				"@images="+embedded.ImageSnapshotDigest(),
			)
		}
		sort.Strings(definitionEntries)
		sourceDigest := hashStrings(definitionEntries)

		trust := source.TrustLevel()
		permissions := append([]string(nil), trust.AllowCatalogPermissions...)
		registries := append([]string(nil), trust.AllowedRegistries...)
		sort.Strings(permissions)
		sort.Strings(registries)
		entry := LockedSource{
			Type:        source.Type(),
			Ref:         source.GetCommit(),
			Commit:      source.GetCommit(),
			Priority:    source.Priority(),
			Permissions: permissions,
			Registries:  registries,
			Digest:      sourceDigest,
			Verified:    source.Type() == "embedded",
		}

		switch typed := source.(type) {
		case *EmbeddedSource:
			entry.Ref = sourceDigest
			entry.Commit = sourceDigest
		case *GitSource:
			entry.URL = typed.GetURL()
			entry.Path = typed.GetSubPath()
			entry.Ref = typed.GetRef()
			entry.SigningKey = typed.GetSigningKey()
			entry.Verified = typed.IsVerified()
		case *LocalSource:
			entry.Path = filepath.Clean(typed.GetPath())
			entry.Ref = sourceDigest
			entry.Commit = sourceDigest
		}
		if !entry.Verified && source.Type() != "local" {
			return nil, "", fmt.Errorf("source %q was not cryptographically verified", source.Name())
		}

		locked[source.Name()] = entry
		catalogEntries = append(
			catalogEntries,
			fmt.Sprintf(
				"%s|%s|%d|%s|%v|%v",
				source.Name(),
				source.Type(),
				source.Priority(),
				sourceDigest,
				permissions,
				registries,
			),
		)
	}

	sort.Strings(catalogEntries)
	return locked, hashStrings(catalogEntries), nil
}

// ValidateLockFile enforces schema-v2 completeness and digest syntax.
func ValidateLockFile(lock *LockFile, requireImageDigests bool) error {
	if lock == nil {
		return fmt.Errorf("lock file is nil")
	}
	if lock.APIVersion != APIVersion || lock.Kind != KindLockFile {
		return fmt.Errorf("invalid lock identity")
	}
	if lock.Metadata.Version != lockSchemaVersion {
		return fmt.Errorf(
			"unsupported lock schema version %d; regenerate with sdbx lock",
			lock.Metadata.Version,
		)
	}
	if lock.Metadata.CLIVersion == "" {
		return fmt.Errorf("lock metadata cliVersion is required")
	}
	if lock.Metadata.GeneratedAt.IsZero() {
		return fmt.Errorf("lock metadata generatedAt is required")
	}
	if !isSHA256Digest(lock.Metadata.CatalogVersion) {
		return fmt.Errorf("lock metadata catalogVersion must be a content-addressed sha256 version")
	}
	if !isSHA256Digest(lock.Metadata.ConfigDigest) {
		return fmt.Errorf("lock metadata configDigest must be a full sha256 digest")
	}
	if !isSHA256Digest(lock.Metadata.CatalogDigest) {
		return fmt.Errorf("lock metadata catalogDigest must be a full sha256 digest")
	}
	if lock.Metadata.CatalogVersion != lock.Metadata.CatalogDigest {
		return fmt.Errorf("lock metadata catalogVersion must match catalogDigest in schema v2")
	}
	if len(lock.Sources) == 0 || len(lock.Services) == 0 {
		return fmt.Errorf("lock must contain at least one source and service")
	}

	for name, source := range lock.Sources {
		if source.Type == "" || source.Ref == "" || source.Commit == "" {
			return fmt.Errorf("locked source %s has incomplete identity", name)
		}
		if !isSHA256Digest(source.Digest) {
			return fmt.Errorf("locked source %s has invalid digest", name)
		}
		switch source.Type {
		case "embedded":
			if !source.Verified ||
				source.Ref != source.Digest ||
				source.Commit != source.Digest {
				return fmt.Errorf("locked embedded source %s is not content-addressed", name)
			}
		case "git":
			if source.Ref != source.Commit {
				return fmt.Errorf("locked Git source %s ref and commit differ", name)
			}
			if !source.Verified || !immutableGitRefPattern.MatchString(source.Ref) ||
				!isValidSigningFingerprint(source.SigningKey) {
				return fmt.Errorf("locked Git source %s is not verifiably immutable", name)
			}
		case "local":
			if source.Ref != source.Digest || source.Commit != source.Digest {
				return fmt.Errorf("locked local source %s identity does not match its digest", name)
			}
		default:
			return fmt.Errorf("locked source %s has unsupported type %q", name, source.Type)
		}
	}

	seenOrder := make(map[string]bool)
	for _, name := range lock.InstallOrder {
		if seenOrder[name] {
			return fmt.Errorf("duplicate service %s in install order", name)
		}
		seenOrder[name] = true
		if _, exists := lock.Services[name]; !exists {
			return fmt.Errorf("install order references unlocked service %s", name)
		}
	}
	if len(seenOrder) != len(lock.Services) {
		return fmt.Errorf("install order does not contain every locked service")
	}

	for name, service := range lock.Services {
		if _, exists := lock.Sources[service.Source]; !exists {
			return fmt.Errorf("locked service %s references missing source %s", name, service.Source)
		}
		if service.DefinitionVersion == "" || service.ResolvedFrom == "" {
			return fmt.Errorf("locked service %s has incomplete definition provenance", name)
		}
		if !isSHA256Digest(service.DefinitionDigest) {
			return fmt.Errorf("locked service %s has invalid definition digest", name)
		}
		if service.Image.Registry == "" ||
			service.Image.Repository == "" ||
			service.Image.Tag == "" {
			return fmt.Errorf("locked service %s has incomplete image identity", name)
		}
		if _, err := imageReference(service.Image.Repository, service.Image.Tag); err != nil {
			return fmt.Errorf("locked service %s has invalid image identity: %w", name, err)
		}
		if actualRegistry := repositoryRegistry(service.Image.Repository); actualRegistry != service.Image.Registry {
			return fmt.Errorf(
				"locked service %s registry %s does not match repository registry %s",
				name,
				service.Image.Registry,
				actualRegistry,
			)
		}
		if requireImageDigests && !isSHA256Digest(service.Image.Digest) {
			return fmt.Errorf("locked service %s is missing an immutable image digest", name)
		}
		if requireImageDigests {
			if !isValidPlatform(service.Image.Platform) {
				return fmt.Errorf("locked service %s has invalid target platform", name)
			}
			if !isSHA256Digest(service.Image.PlatformDigest) {
				return fmt.Errorf("locked service %s is missing a platform digest", name)
			}
			if service.Image.PlatformDigests[service.Image.Platform] != service.Image.PlatformDigest {
				return fmt.Errorf(
					"locked service %s platform digest is not present in the manifest index",
					name,
				)
			}
		}
		for platform, digest := range service.Image.PlatformDigests {
			if !isValidPlatform(platform) || !isSHA256Digest(digest) {
				return fmt.Errorf("locked service %s has invalid platform digest", name)
			}
		}
	}
	for path, digest := range lock.GeneratedFiles {
		if _, _, err := splitGeneratedFileKey(path); err != nil {
			return err
		}
		if !isSHA256Digest(digest) {
			return fmt.Errorf("locked generated file %s has invalid digest", path)
		}
	}
	return nil
}

const generatedConfigPrefix = "@config/"

var requiredGeneratedFiles = []string{
	"compose.yaml",
	".env",
	"@config/authelia/configuration.yml",
	"@config/traefik/traefik.yml",
	"@config/traefik/dynamic/middlewares.yml",
}

// ConfigGeneratedFile returns the logical lock key for a file rooted in the
// project's configured config_path. Logical keys keep lock files portable when
// config_path is absolute or changes between hosts.
func ConfigGeneratedFile(path string) string {
	return generatedConfigPrefix + filepath.ToSlash(path)
}

// GeneratedConfigPaths returns the lock-recorded paths rooted in config_path.
// Restore relocation uses this allowlist to preserve the target host's
// regenerated policy files while moving application-owned state.
func GeneratedConfigPaths(lock *LockFile) ([]string, error) {
	if err := ValidateLockFile(lock, true); err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(lock.GeneratedFiles))
	for key := range lock.GeneratedFiles {
		rootKind, clean, err := splitGeneratedFileKey(key)
		if err != nil {
			return nil, err
		}
		if rootKind == generatedFileRootConfig {
			paths = append(paths, filepath.ToSlash(clean))
		}
	}
	sort.Strings(paths)
	return paths, nil
}

// RecordGeneratedFiles hashes managed runtime files. Plain paths are relative
// to projectDir; @config/ paths are relative to configDir. Both roots are
// opened through os.Root so a malicious relative path cannot escape them.
func RecordGeneratedFiles(
	projectDir string,
	configDir string,
	paths []string,
) (map[string]string, error) {
	projectRoot, configRoot, err := openGeneratedFileRoots(projectDir, configDir)
	if err != nil {
		return nil, err
	}
	defer projectRoot.Close()
	defer configRoot.Close()

	digests := make(map[string]string, len(paths))
	for _, key := range paths {
		rootKind, clean, err := splitGeneratedFileKey(key)
		if err != nil {
			return nil, err
		}
		root := projectRoot
		if rootKind == generatedFileRootConfig {
			root = configRoot
		}
		digest, err := hashGeneratedFile(root, clean)
		if err != nil {
			return nil, fmt.Errorf("hash generated file %s: %w", key, err)
		}
		if rootKind == generatedFileRootConfig {
			digests[ConfigGeneratedFile(clean)] = digest
		} else {
			digests[filepath.ToSlash(clean)] = digest
		}
	}
	return digests, nil
}

// ValidateGeneratedFiles rejects missing, symlinked, oversized, or modified
// managed runtime files before Docker Compose is allowed to start.
func ValidateGeneratedFiles(projectDir, configDir string, lock *LockFile) error {
	if err := ValidateLockFile(lock, true); err != nil {
		return err
	}
	if len(lock.GeneratedFiles) == 0 {
		return fmt.Errorf("lock contains no generated runtime file digests; run 'sdbx generate'")
	}
	for _, required := range requiredGeneratedFiles {
		if _, exists := lock.GeneratedFiles[required]; !exists {
			return fmt.Errorf("lock does not cover %s; run 'sdbx generate'", required)
		}
	}

	projectRoot, configRoot, err := openGeneratedFileRoots(projectDir, configDir)
	if err != nil {
		return err
	}
	defer projectRoot.Close()
	defer configRoot.Close()
	for key, expected := range lock.GeneratedFiles {
		rootKind, clean, err := splitGeneratedFileKey(key)
		if err != nil {
			return err
		}
		root := projectRoot
		if rootKind == generatedFileRootConfig {
			root = configRoot
		}
		actual, err := hashGeneratedFile(root, clean)
		if err != nil {
			return fmt.Errorf("validate generated file %s: %w", key, err)
		}
		if actual != expected {
			return fmt.Errorf(
				"generated runtime file %s differs from .sdbx.lock; run 'sdbx generate'",
				key,
			)
		}
	}
	return nil
}

type generatedFileRoot uint8

const (
	generatedFileRootProject generatedFileRoot = iota
	generatedFileRootConfig
)

func splitGeneratedFileKey(key string) (generatedFileRoot, string, error) {
	root := generatedFileRootProject
	path := key
	if strings.HasPrefix(key, generatedConfigPrefix) {
		root = generatedFileRootConfig
		path = strings.TrimPrefix(key, generatedConfigPrefix)
	}
	clean, err := cleanGeneratedFilePath(path)
	if err != nil {
		return 0, "", fmt.Errorf("invalid generated file key %q: %w", key, err)
	}
	return root, clean, nil
}

func cleanGeneratedFilePath(path string) (string, error) {
	if path == "" || filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be relative")
	}
	clean := filepath.Clean(filepath.FromSlash(path))
	if clean == "." ||
		clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes its managed root")
	}
	return clean, nil
}

func openGeneratedFileRoots(projectDir, configuredConfigDir string) (*os.Root, *os.Root, error) {
	projectRoot, err := os.OpenRoot(projectDir)
	if err != nil {
		return nil, nil, fmt.Errorf("open project root: %w", err)
	}

	configDir := configuredConfigDir
	if configDir == "" {
		configDir = "configs"
	}
	var configRoot *os.Root
	if filepath.IsAbs(configDir) {
		info, statErr := os.Lstat(configDir)
		if statErr != nil {
			_ = projectRoot.Close()
			return nil, nil, fmt.Errorf("inspect config root: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			_ = projectRoot.Close()
			return nil, nil, fmt.Errorf("config root must be a real directory, not a symlink")
		}
		configRoot, err = os.OpenRoot(configDir)
	} else {
		clean, cleanErr := cleanGeneratedFilePath(configDir)
		if cleanErr != nil {
			_ = projectRoot.Close()
			return nil, nil, fmt.Errorf("invalid config root: %w", cleanErr)
		}
		configRoot, err = projectRoot.OpenRoot(clean)
	}
	if err != nil {
		_ = projectRoot.Close()
		return nil, nil, fmt.Errorf("open config root: %w", err)
	}
	return projectRoot, configRoot, nil
}

func hashGeneratedFile(root *os.Root, path string) (string, error) {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for index := range parts {
		component := filepath.FromSlash(strings.Join(parts[:index+1], "/"))
		info, err := root.Lstat(component)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symbolic links are not allowed in managed paths")
		}
		if index < len(parts)-1 && !info.IsDir() {
			return "", fmt.Errorf("managed path component is not a directory")
		}
	}

	file, err := root.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("managed runtime file is not regular")
	}
	if info.Size() > maxGeneratedFileBytes {
		return "", fmt.Errorf("managed runtime file exceeds %d bytes", maxGeneratedFileBytes)
	}

	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, maxGeneratedFileBytes+1))
	if err != nil {
		return "", err
	}
	if written != info.Size() {
		return "", fmt.Errorf("managed runtime file changed while hashing")
	}
	finalInfo, err := file.Stat()
	if err != nil {
		return "", err
	}
	if finalInfo.Size() != info.Size() || !finalInfo.ModTime().Equal(info.ModTime()) {
		return "", fmt.Errorf("managed runtime file changed while hashing")
	}
	return fmt.Sprintf("sha256:%x", hasher.Sum(nil)), nil
}

// DiffLockFiles compares every field that can alter generated runtime output.
func (r *Registry) DiffLockFiles(existing, current *LockFile) []LockFileDiff {
	var diffs []LockFileDiff
	if existing.Metadata.Version != current.Metadata.Version {
		diffs = append(diffs, LockFileDiff{
			Type: "changed",
			Description: fmt.Sprintf(
				"Lock schema: %d -> %d",
				existing.Metadata.Version,
				current.Metadata.Version,
			),
		})
	}
	if existing.Metadata.CLIVersion != current.Metadata.CLIVersion {
		diffs = append(diffs, LockFileDiff{
			Type:        "changed",
			Description: "CLI version changed",
		})
	}
	if existing.Metadata.CatalogVersion != current.Metadata.CatalogVersion {
		diffs = append(diffs, LockFileDiff{
			Type:        "changed",
			Description: "Catalog version changed",
		})
	}
	if existing.Metadata.ConfigDigest != current.Metadata.ConfigDigest {
		diffs = append(diffs, LockFileDiff{
			Type:        "changed",
			Description: "Project configuration digest changed",
		})
	}
	if existing.Metadata.CatalogDigest != current.Metadata.CatalogDigest {
		diffs = append(diffs, LockFileDiff{
			Type:        "changed",
			Description: "Catalog digest changed",
		})
	}

	sourceNames := unionSortedKeys(existing.Sources, current.Sources)
	for _, name := range sourceNames {
		oldSource, oldExists := existing.Sources[name]
		newSource, newExists := current.Sources[name]
		switch {
		case !oldExists:
			diffs = append(diffs, LockFileDiff{Type: "added", Description: "Source " + name + " added"})
		case !newExists:
			diffs = append(diffs, LockFileDiff{Type: "removed", Description: "Source " + name + " removed"})
		case !reflect.DeepEqual(oldSource, newSource):
			diffs = append(diffs, LockFileDiff{Type: "changed", Description: "Source " + name + " identity changed"})
		}
	}

	serviceNames := unionSortedKeys(existing.Services, current.Services)
	for _, name := range serviceNames {
		oldService, oldExists := existing.Services[name]
		newService, newExists := current.Services[name]
		switch {
		case !oldExists:
			diffs = append(diffs, LockFileDiff{Type: "added", Description: "Service " + name + " added"})
		case !newExists:
			diffs = append(diffs, LockFileDiff{Type: "removed", Description: "Service " + name + " removed"})
		case !reflect.DeepEqual(oldService, newService):
			diffs = append(diffs, LockFileDiff{Type: "changed", Description: "Service " + name + " provenance changed"})
		}
	}
	if !reflect.DeepEqual(existing.InstallOrder, current.InstallOrder) {
		diffs = append(diffs, LockFileDiff{Type: "changed", Description: "Service install order changed"})
	}
	return diffs
}

func calculateLockConfigDigest(cfg *config.Config) (string, error) {
	type lockTLSConfig struct {
		Provider string `json:"provider"`
		Email    string `json:"email"`
		CertFile string `json:"certFile"`
		KeyFile  string `json:"keyFile"`
	}
	type lockConfig struct {
		Domain          string                            `json:"domain"`
		Timezone        string                            `json:"timezone"`
		ExposeMode      string                            `json:"exposeMode"`
		TLS             lockTLSConfig                     `json:"tls"`
		Routing         config.RoutingConfig              `json:"routing"`
		ConfigPath      string                            `json:"configPath"`
		DataPath        string                            `json:"dataPath"`
		DownloadsPath   string                            `json:"downloadsPath"`
		MediaPath       string                            `json:"mediaPath"`
		SecretsPath     string                            `json:"secretsPath"`
		PlexEnabled     bool                              `json:"plexEnabled"`
		JellyfinEnabled bool                              `json:"jellyfinEnabled"`
		PUID            int                               `json:"puid"`
		PGID            int                               `json:"pgid"`
		Umask           string                            `json:"umask"`
		VPNEnabled      bool                              `json:"vpnEnabled"`
		VPNProvider     string                            `json:"vpnProvider"`
		VPNCountry      string                            `json:"vpnCountry"`
		TorrentPort     int                               `json:"torrentPeerPort"`
		Addons          []string                          `json:"addons"`
		Services        map[string]config.ServiceOverride `json:"services"`
	}

	addons := append([]string(nil), cfg.Addons...)
	sort.Strings(addons)
	view := lockConfig{
		Domain:     cfg.Domain,
		Timezone:   cfg.Timezone,
		ExposeMode: cfg.Expose.Mode,
		TLS: lockTLSConfig{
			Provider: cfg.Expose.TLS.Provider,
			Email:    cfg.Expose.TLS.Email,
			CertFile: cfg.Expose.TLS.CertFile,
			KeyFile:  cfg.Expose.TLS.KeyFile,
		},
		Routing:         cfg.Routing,
		ConfigPath:      cfg.ConfigPath,
		DataPath:        cfg.DataPath,
		DownloadsPath:   cfg.DownloadsPath,
		MediaPath:       cfg.MediaPath,
		SecretsPath:     cfg.SecretsPath,
		PlexEnabled:     cfg.PlexEnabled,
		JellyfinEnabled: cfg.JellyfinEnabled,
		PUID:            cfg.PUID,
		PGID:            cfg.PGID,
		Umask:           cfg.Umask,
		VPNEnabled:      cfg.VPNEnabled,
		VPNProvider:     cfg.VPNProvider,
		VPNCountry:      cfg.VPNCountry,
		TorrentPort:     cfg.TorrentPort,
		Addons:          addons,
		Services:        cfg.Services,
	}
	data, err := json.Marshal(view)
	if err != nil {
		return "", err
	}
	return hashBytes(data), nil
}

func hashServiceDefinition(definition *ServiceDefinition) (string, error) {
	data, err := yaml.Marshal(definition)
	if err != nil {
		return "", fmt.Errorf("failed to hash service definition: %w", err)
	}
	return hashBytes(data), nil
}

func hashStrings(values []string) string {
	data, _ := json.Marshal(values)
	return hashBytes(data)
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum[:])
}

func isSHA256Digest(value string) bool {
	return len(value) == len("sha256:")+64 &&
		value[:len("sha256:")] == "sha256:" &&
		immutableGitRefPattern.MatchString(value[len("sha256:"):])
}

func isValidPlatform(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || !imageTagPattern.MatchString(part) {
			return false
		}
	}
	return true
}

func selectPlatformDigest(
	target string,
	platformDigests map[string]string,
) (string, string, error) {
	if digest := platformDigests[target]; isSHA256Digest(digest) {
		return target, digest, nil
	}
	prefix := target + "/"
	var matchedPlatform string
	var matchedDigest string
	for platform, digest := range platformDigests {
		if !strings.HasPrefix(platform, prefix) || !isSHA256Digest(digest) {
			continue
		}
		if matchedPlatform != "" {
			return "", "", fmt.Errorf(
				"platform %s has multiple variant manifests (%s and %s)",
				target,
				matchedPlatform,
				platform,
			)
		}
		matchedPlatform = platform
		matchedDigest = digest
	}
	if matchedPlatform == "" {
		return "", "", fmt.Errorf("platform %s is not present in the image index", target)
	}
	return matchedPlatform, matchedDigest, nil
}

func cloneSortedMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func unionSortedKeys[T any](left, right map[string]T) []string {
	seen := make(map[string]bool, len(left)+len(right))
	for key := range left {
		seen[key] = true
	}
	for key := range right {
		seen[key] = true
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
