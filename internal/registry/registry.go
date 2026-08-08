package registry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/get-sdbx/sdbx/internal/config"
)

const currentSourceConfigVersion = 2

// ErrServiceNotFound distinguishes a normal source miss from a source loading,
// verification, or parsing failure. Callers must never silently fall back on
// the latter.
var ErrServiceNotFound = errors.New("service not found")

// Registry manages service definitions from multiple sources
type Registry struct {
	sources   []SourceProvider
	cache     *Cache
	validator *Validator
	resolver  *Resolver
	mu        sync.RWMutex
}

// SourceProvider is the interface for service definition sources
type SourceProvider interface {
	// Name returns the source name
	Name() string

	// Type returns the source type (local, git)
	Type() string

	// Priority returns the source priority (higher = checked first)
	Priority() int

	// IsEnabled returns whether the source is enabled
	IsEnabled() bool

	// TrustLevel returns the capabilities granted to definitions from this source
	TrustLevel() TrustLevel

	// Load loads all service definitions from the source
	Load(ctx context.Context) ([]*ServiceDefinition, error)

	// LoadService loads a specific service definition
	LoadService(ctx context.Context, name string) (*ServiceDefinition, error)

	// ListServices returns names of all available services
	ListServices(ctx context.Context) ([]string, error)

	// GetServicePath returns the path to a service definition
	GetServicePath(name string) string

	// Update updates the source (e.g., git pull)
	Update(ctx context.Context) error

	// GetCommit returns the current commit hash (for git sources)
	GetCommit() string
}

// New creates a new Registry with the given configuration
func New(cfg *SourceConfig) (*Registry, error) {
	if cfg == nil {
		return nil, fmt.Errorf("source configuration is required")
	}
	cacheTTL, err := parseSourceCacheTTL(cfg.Cache.TTL)
	if err != nil {
		return nil, err
	}
	if err := validateConfiguredSources(cfg.Sources); err != nil {
		return nil, err
	}
	r := &Registry{
		sources:   make([]SourceProvider, 0),
		validator: NewValidator(),
	}

	// Initialize cache
	cacheDir := cfg.Cache.Directory
	if cacheDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		cacheDir = filepath.Join(home, ".cache", "sdbx", "sources")
	}
	r.cache = NewCache(cacheDir)
	r.cache.SetTTL(cacheTTL)

	// Source identity is security-sensitive because trust grants are resolved
	// by name. The complete set was validated before any cache path was
	// created; instantiate only enabled providers here.
	for _, src := range cfg.Sources {
		if !src.Enabled {
			continue
		}

		provider, err := r.createSourceProvider(src)
		if err != nil {
			return nil, fmt.Errorf("failed to create source %s: %w", src.Name, err)
		}
		r.sources = append(r.sources, provider)
	}

	// Always add the embedded official catalog below explicit user sources.
	embeddedSource := NewEmbeddedSource()
	r.sources = append(r.sources, embeddedSource)

	// Sort sources by priority (highest first)
	sort.Slice(r.sources, func(i, j int) bool {
		return r.sources[i].Priority() > r.sources[j].Priority()
	})

	// Initialize resolver
	r.resolver = NewResolver(r)

	return r, nil
}

// NewWithDefaults creates a Registry with default configuration
func NewWithDefaults() (*Registry, error) {
	cfg, err := LoadDefaultSourceConfig()
	if err != nil {
		return nil, err
	}
	return New(cfg)
}

// DefaultSourceConfigPath returns the user source configuration path.
func DefaultSourceConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "sdbx", "sources.yaml")
}

// LoadDefaultSourceConfig loads the user source configuration or returns defaults.
func LoadDefaultSourceConfig() (*SourceConfig, error) {
	configPath := DefaultSourceConfigPath()
	loader := NewLoader()

	cfg, err := loader.LoadSourceConfig(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DefaultSourceConfig(), nil
		}
		return nil, err
	}

	defaults := DefaultSourceConfig()
	if cfg.Metadata.Version > currentSourceConfigVersion ||
		cfg.Metadata.Version < 0 {
		return nil, fmt.Errorf(
			"unsupported source configuration version %d",
			cfg.Metadata.Version,
		)
	}
	if cfg.Cache.Directory == "" {
		cfg.Cache.Directory = defaults.Cache.Directory
	}
	if cfg.Cache.TTL == "" {
		cfg.Cache.TTL = defaults.Cache.TTL
	}
	if !cfg.Security.AllowUnverified && !cfg.Security.RequireSignatures && len(cfg.Security.TrustLevels) == 0 {
		cfg.Security = defaults.Security
	}
	migrateLegacySourceConfig(cfg)
	if err := validateSourceConfiguration(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// DefaultSourceConfig returns the default source configuration
func DefaultSourceConfig() *SourceConfig {
	home, _ := os.UserHomeDir()

	return &SourceConfig{
		APIVersion: APIVersion,
		Kind:       KindSourceConfig,
		Metadata: SourceConfigMetadata{
			Version: currentSourceConfigVersion,
		},
		Sources: nil,
		Cache: CacheConfig{
			Directory: filepath.Join(home, ".cache", "sdbx", "sources"),
			TTL:       "24h",
		},
		Security: SecurityConfig{},
	}
}

// migrateLegacySourceConfig removes the obsolete private official source from
// configuration loaded from older releases. The complete official catalog is
// embedded in the binary. Explicit user-defined sources are preserved.
func migrateLegacySourceConfig(cfg *SourceConfig) {
	if cfg == nil {
		return
	}

	legacyConfig := cfg.Metadata.Version < 2
	sources := cfg.Sources[:0]
	for _, src := range cfg.Sources {
		if legacyConfig &&
			src.Name == "official" &&
			src.Type == "git" &&
			src.Path == "services" &&
			src.Priority == 0 &&
			src.Enabled &&
			src.Ref == "" &&
			src.SigningKey == "" &&
			src.LegacyBranch == "main" &&
			src.LegacyVerified {
			continue
		}
		sources = append(sources, src)
	}

	cfg.Sources = sources
	if cfg.Metadata.Version < 2 {
		cfg.Metadata.Version = currentSourceConfigVersion
	}
}

func parseSourceCacheTTL(raw string) (time.Duration, error) {
	if raw == "" {
		return 24 * time.Hour, nil
	}
	ttl, err := time.ParseDuration(raw)
	if err != nil || ttl <= 0 {
		return 0, fmt.Errorf(
			"source cache TTL must be a positive duration: %q",
			raw,
		)
	}
	return ttl, nil
}

func validateConfiguredSources(sources []Source) error {
	sourceNames := map[string]bool{"embedded": true}
	for _, source := range sources {
		if sourceNames[source.Name] {
			return fmt.Errorf("duplicate or reserved source name: %s", source.Name)
		}
		sourceNames[source.Name] = true
		if err := ValidateSourceConfig(source); err != nil {
			return fmt.Errorf("invalid source %s: %w", source.Name, err)
		}
	}
	return nil
}

func validateSourceConfiguration(cfg *SourceConfig) error {
	if cfg == nil {
		return fmt.Errorf("source configuration is required")
	}
	if cfg.APIVersion != APIVersion {
		return fmt.Errorf(
			"unsupported API version: %s (expected %s)",
			cfg.APIVersion,
			APIVersion,
		)
	}
	if cfg.Kind != KindSourceConfig {
		return fmt.Errorf(
			"unexpected kind: %s (expected %s)",
			cfg.Kind,
			KindSourceConfig,
		)
	}
	if cfg.Metadata.Version != currentSourceConfigVersion {
		return fmt.Errorf(
			"unsupported source configuration version %d",
			cfg.Metadata.Version,
		)
	}
	if _, err := parseSourceCacheTTL(cfg.Cache.TTL); err != nil {
		return err
	}
	return validateConfiguredSources(cfg.Sources)
}

// createSourceProvider creates a source provider based on source config
func (r *Registry) createSourceProvider(src Source) (SourceProvider, error) {
	if err := ValidateSourceConfig(src); err != nil {
		return nil, err
	}
	switch src.Type {
	case "local":
		return NewLocalSource(src), nil
	case "git":
		return NewGitSource(src, r.cache)
	default:
		return nil, fmt.Errorf("unsupported configurable source type %q", src.Type)
	}
}

// Sources returns all configured source providers
func (r *Registry) Sources() []SourceProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]SourceProvider(nil), r.sources...)
}

// AddSource adds a new source to the registry
func (r *Registry) AddSource(src Source) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate
	for _, existing := range r.sources {
		if existing.Name() == src.Name {
			return fmt.Errorf("source %s already exists", src.Name)
		}
	}

	provider, err := r.createSourceProvider(src)
	if err != nil {
		return err
	}

	r.sources = append(r.sources, provider)

	// Re-sort by priority
	sort.Slice(r.sources, func(i, j int) bool {
		return r.sources[i].Priority() > r.sources[j].Priority()
	})

	return nil
}

// RemoveSource removes a source from the registry
func (r *Registry) RemoveSource(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, src := range r.sources {
		if src.Name() == name {
			if src.Type() == "embedded" {
				return fmt.Errorf("cannot remove built-in source: %s", name)
			}
			r.sources = append(r.sources[:i], r.sources[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("source %s not found", name)
}

// GetSource returns a source by name
func (r *Registry) GetSource(name string) (SourceProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, src := range r.sources {
		if src.Name() == name {
			return src, nil
		}
	}

	return nil, fmt.Errorf("source %s not found", name)
}

// Update updates all sources
func (r *Registry) Update(ctx context.Context) error {
	r.mu.RLock()
	sources := r.sources
	r.mu.RUnlock()

	var errs []error
	for _, src := range sources {
		if err := src.Update(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", src.Name(), err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("update errors: %v", errs)
	}
	return nil
}

// Resolve resolves all services based on the project configuration
func (r *Registry) Resolve(ctx context.Context, cfg *config.Config) (*ResolutionGraph, error) {
	return r.resolver.Resolve(ctx, cfg)
}

// GetService returns a service definition by name (searches all sources by priority)
func (r *Registry) GetService(ctx context.Context, name string) (*ServiceDefinition, string, error) {
	if err := validateServiceLookupName(name); err != nil {
		return nil, "", err
	}
	r.mu.RLock()
	sources := r.sources
	r.mu.RUnlock()

	for _, src := range sources {
		if !src.IsEnabled() {
			continue
		}

		def, err := src.LoadService(ctx, name)
		if err == nil && def != nil {
			if err := r.validateServiceSourceBoundary(ctx, src, name, def); err != nil {
				return nil, "", err
			}
			return def, src.Name(), nil
		}
		if err != nil && !errors.Is(err, ErrServiceNotFound) {
			return nil, "", fmt.Errorf("failed to load service %s from source %s: %w", name, src.Name(), err)
		}
	}

	return nil, "", fmt.Errorf("service %s not found in any source", name)
}

// ListServices returns all available services across all sources
func (r *Registry) ListServices(ctx context.Context) ([]ServiceInfo, error) {
	r.mu.RLock()
	sources := r.sources
	r.mu.RUnlock()

	seen := make(map[string]bool)
	var services []ServiceInfo

	for _, src := range sources {
		if !src.IsEnabled() {
			continue
		}

		names, err := src.ListServices(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list services from source %s: %w", src.Name(), err)
		}

		for _, name := range names {
			if seen[name] {
				continue
			}

			def, err := src.LoadService(ctx, name)
			if err != nil {
				return nil, fmt.Errorf("failed to load service %s from source %s: %w", name, src.Name(), err)
			}
			if err := r.validateServiceSourceBoundary(ctx, src, name, def); err != nil {
				return nil, err
			}
			validationErrors := r.validator.ValidateWithTrustLevel(def, src.TrustLevel())
			if HasErrors(validationErrors) {
				return nil, fmt.Errorf(
					"invalid service %s from source %s: %s",
					name,
					src.Name(),
					formatValidationErrors(validationErrors),
				)
			}
			seen[name] = true

			services = append(services, ServiceInfo{
				Name:        def.Metadata.Name,
				Description: def.Metadata.Description,
				Category:    def.Metadata.Category,
				Version:     def.Metadata.Version,
				Source:      src.Name(),
				IsAddon:     def.Conditions.RequireAddon,
			})
		}
	}

	// Sort by name
	sort.Slice(services, func(i, j int) bool {
		return services[i].Name < services[j].Name
	})

	return services, nil
}

func (r *Registry) validateServiceSourceBoundary(
	ctx context.Context,
	source SourceProvider,
	name string,
	definition *ServiceDefinition,
) error {
	if definition.Metadata.Name != name {
		return fmt.Errorf(
			"service %s from source %s declares metadata name %s",
			name,
			source.Name(),
			definition.Metadata.Name,
		)
	}
	if source.Type() == "embedded" {
		return nil
	}

	permission := "service-override:" + name
	declared := false
	for _, candidate := range definition.Permissions {
		if candidate == permission {
			declared = true
			break
		}
	}

	embedded, err := r.embeddedServiceExists(ctx, name)
	if err != nil {
		return err
	}
	if !embedded {
		if declared {
			return fmt.Errorf(
				"service %s from source %s declares unused catalog permission %q",
				name,
				source.Name(),
				permission,
			)
		}
		return nil
	}
	if !declared {
		return fmt.Errorf(
			"service %s from source %s overrides the embedded catalog without declaring catalog permission %q",
			name,
			source.Name(),
			permission,
		)
	}
	if !catalogPermissionGranted(
		permission,
		source.TrustLevel().AllowCatalogPermissions,
	) {
		return fmt.Errorf(
			"service %s from source %s requires ungranted catalog permission %q",
			name,
			source.Name(),
			permission,
		)
	}
	return nil
}

func (r *Registry) embeddedServiceExists(
	ctx context.Context,
	name string,
) (bool, error) {
	for _, source := range r.Sources() {
		if source.Type() != "embedded" {
			continue
		}
		_, err := source.LoadService(ctx, name)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, ErrServiceNotFound):
			return false, nil
		default:
			return false, fmt.Errorf(
				"load embedded service identity %s: %w",
				name,
				err,
			)
		}
	}
	return false, fmt.Errorf("embedded catalog source is missing")
}

// SearchServices searches for services matching a query
func (r *Registry) SearchServices(ctx context.Context, query string, category ServiceCategory) ([]ServiceInfo, error) {
	all, err := r.ListServices(ctx)
	if err != nil {
		return nil, err
	}

	var results []ServiceInfo
	for _, svc := range all {
		if category != "" && svc.Category != category {
			continue
		}

		if matchesQuery(svc, query) {
			results = append(results, svc)
		}
	}

	return results, nil
}

// Validate validates a service definition
func (r *Registry) Validate(def *ServiceDefinition) []ValidationError {
	return r.validator.Validate(def)
}

// ValidateForSource validates both the service definition and the permissions
// granted to the source that supplied it.
func (r *Registry) ValidateForSource(def *ServiceDefinition, sourceName string) []ValidationError {
	source, err := r.GetSource(sourceName)
	if err != nil {
		return []ValidationError{{
			Field:    "source",
			Message:  err.Error(),
			Severity: "error",
		}}
	}
	return r.validator.ValidateWithTrustLevel(def, source.TrustLevel())
}

// ServiceInfo provides summary information about a service
type ServiceInfo struct {
	Name        string
	Description string
	Category    ServiceCategory
	Version     string
	Source      string
	IsAddon     bool
}

// matchesQuery checks if a service matches a search query
func matchesQuery(svc ServiceInfo, query string) bool {
	if query == "" {
		return true
	}

	// Simple case-insensitive substring match
	query = toLower(query)
	if contains(toLower(svc.Name), query) {
		return true
	}
	if contains(toLower(svc.Description), query) {
		return true
	}
	if contains(toLower(string(svc.Category)), query) {
		return true
	}

	return false
}

// toLower converts string to lowercase
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		result[i] = c
	}
	return string(result)
}

// contains checks if s contains substr
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || findSubstring(s, substr) >= 0)
}

// findSubstring finds substr in s
func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
