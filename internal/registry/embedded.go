package registry

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	officialservices "github.com/get-sdbx/sdbx/services"
)

// EmbeddedSource implements SourceProvider for embedded service definitions
type EmbeddedSource struct {
	BaseSource
	fs       fs.FS
	services map[string]*ServiceDefinition
	loaded   bool
}

// NewEmbeddedSource creates a new embedded source
func NewEmbeddedSource() *EmbeddedSource {
	return &EmbeddedSource{
		BaseSource: BaseSource{
			name:     "embedded",
			srcType:  "embedded",
			priority: -1, // Explicit user sources may deliberately override it.
			enabled:  true,
			trust: TrustLevel{
				AllowCatalogPermissions: []string{"*"},
				AllowedRegistries:       []string{"*"},
			},
			loader: NewLoader(),
		},
		fs:       officialservices.Catalog,
		services: make(map[string]*ServiceDefinition),
	}
}

// ImageSnapshotDigest binds the embedded catalog source identity to the exact
// reviewed OCI snapshot shipped beside its service definitions.
func (s *EmbeddedSource) ImageSnapshotDigest() string {
	return hashBytes(officialservices.ImageLock)
}

// Load loads all service definitions from embedded filesystem
func (s *EmbeddedSource) Load(ctx context.Context) ([]*ServiceDefinition, error) {
	if err := s.ensureLoaded(); err != nil {
		return nil, err
	}

	defs := make([]*ServiceDefinition, 0, len(s.services))
	for _, def := range s.services {
		defs = append(defs, def)
	}
	return defs, nil
}

// LoadService loads a specific service definition
func (s *EmbeddedSource) LoadService(ctx context.Context, name string) (*ServiceDefinition, error) {
	if err := s.ensureLoaded(); err != nil {
		return nil, err
	}

	def, exists := s.services[name]
	if !exists {
		return nil, fmt.Errorf("%w: service %s in embedded source", ErrServiceNotFound, name)
	}
	return def, nil
}

// ListServices returns names of all available services
func (s *EmbeddedSource) ListServices(ctx context.Context) ([]string, error) {
	if err := s.ensureLoaded(); err != nil {
		return nil, err
	}

	names := make([]string, 0, len(s.services))
	for name := range s.services {
		names = append(names, name)
	}
	return names, nil
}

// GetServicePath returns the embedded path to a service definition
func (s *EmbeddedSource) GetServicePath(name string) string {
	// Check core first, then addons
	corePath := filepath.Join("core", name, "service.yaml")
	if _, err := fs.Stat(s.fs, corePath); err == nil {
		return "embedded://services/" + corePath
	}

	addonPath := filepath.Join("addons", name, "service.yaml")
	return "embedded://services/" + addonPath
}

// Update is a no-op for embedded sources
func (s *EmbeddedSource) Update(ctx context.Context) error {
	return nil
}

// GetCommit returns empty string for embedded sources
func (s *EmbeddedSource) GetCommit() string {
	return "embedded"
}

// ensureLoaded loads all services from embedded filesystem
func (s *EmbeddedSource) ensureLoaded() error {
	if s.loaded {
		return nil
	}

	// Walk embedded filesystem and load all service.yaml files
	err := fs.WalkDir(s.fs, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Only process service.yaml files
		if d.Name() != "service.yaml" {
			return nil
		}

		// Read and parse the service definition
		data, err := fs.ReadFile(s.fs, path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		def, err := s.loader.ParseServiceDefinition(data)
		if err != nil {
			return fmt.Errorf("failed to parse %s: %w", path, err)
		}

		dirName := filepath.Base(filepath.Dir(path))
		if def.Metadata.Name != dirName {
			return fmt.Errorf(
				"service metadata name %q does not match directory %q in %s",
				def.Metadata.Name,
				dirName,
				path,
			)
		}
		if existing, ok := s.services[def.Metadata.Name]; ok {
			return fmt.Errorf(
				"duplicate embedded service %q in %s and %s",
				def.Metadata.Name,
				s.GetServicePath(existing.Metadata.Name),
				path,
			)
		}

		s.services[def.Metadata.Name] = def
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to load embedded services: %w", err)
	}

	s.loaded = true
	return nil
}

// HasService checks if a service exists in embedded source
func (s *EmbeddedSource) HasService(name string) bool {
	if err := s.ensureLoaded(); err != nil {
		return false
	}
	_, exists := s.services[name]
	return exists
}

// GetServiceCategories returns all unique categories from embedded services
func (s *EmbeddedSource) GetServiceCategories() ([]ServiceCategory, error) {
	if err := s.ensureLoaded(); err != nil {
		return nil, err
	}

	categories := make(map[ServiceCategory]bool)
	for _, def := range s.services {
		categories[def.Metadata.Category] = true
	}

	result := make([]ServiceCategory, 0, len(categories))
	for cat := range categories {
		result = append(result, cat)
	}
	return result, nil
}

// GetCoreServices returns all core (non-addon) services
func (s *EmbeddedSource) GetCoreServices() ([]*ServiceDefinition, error) {
	if err := s.ensureLoaded(); err != nil {
		return nil, err
	}

	var core []*ServiceDefinition
	for _, def := range s.services {
		if !def.Conditions.RequireAddon {
			core = append(core, def)
		}
	}
	return core, nil
}

// GetAddonServices returns all addon services
func (s *EmbeddedSource) GetAddonServices() ([]*ServiceDefinition, error) {
	if err := s.ensureLoaded(); err != nil {
		return nil, err
	}

	var addons []*ServiceDefinition
	for _, def := range s.services {
		if def.Conditions.RequireAddon {
			addons = append(addons, def)
		}
	}
	return addons, nil
}

// GetServicesByCategory returns services filtered by category
func (s *EmbeddedSource) GetServicesByCategory(category ServiceCategory) ([]*ServiceDefinition, error) {
	if err := s.ensureLoaded(); err != nil {
		return nil, err
	}

	var services []*ServiceDefinition
	for _, def := range s.services {
		if def.Metadata.Category == category {
			services = append(services, def)
		}
	}
	return services, nil
}

// GetServicesByTag returns services that have a specific tag
func (s *EmbeddedSource) GetServicesByTag(tag string) ([]*ServiceDefinition, error) {
	if err := s.ensureLoaded(); err != nil {
		return nil, err
	}

	var services []*ServiceDefinition
	for _, def := range s.services {
		for _, t := range def.Metadata.Tags {
			if strings.EqualFold(t, tag) {
				services = append(services, def)
				break
			}
		}
	}
	return services, nil
}

// NewDefaultRegistry creates a Registry with the embedded official catalog.
func NewDefaultRegistry() (*Registry, error) {
	return New(DefaultSourceConfig())
}

// NewEmbeddedOnlyRegistry creates a Registry with only embedded source
func NewEmbeddedOnlyRegistry() *Registry {
	embedded := NewEmbeddedSource()

	return &Registry{
		sources:   []SourceProvider{embedded},
		validator: NewValidator(),
		resolver:  nil, // Will be set after creation
	}
}
