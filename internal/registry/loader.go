package registry

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/get-sdbx/sdbx/internal/securefs"
	"gopkg.in/yaml.v3"
)

// Loader handles loading and parsing of YAML service definitions
type Loader struct{}

const (
	maxServiceDefinitionSize  = 1 << 20 // 1 MiB
	maxCatalogTraversalFile   = 4 << 20
	maxCatalogTreeBytes       = 32 << 20
	maxCatalogDefinitionBytes = 16 << 20
	maxCatalogEntries         = 4_096
	maxCatalogDefinitions     = 512
	maxCatalogTraversalDepth  = 8
)

// NewLoader creates a new Loader
func NewLoader() *Loader {
	return &Loader{}
}

// LoadServiceDefinition loads a service definition from a file
func (l *Loader) LoadServiceDefinition(path string) (*ServiceDefinition, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect file %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("service definition must not be a symbolic link: %s", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("service definition must be a regular file: %s", path)
	}
	if info.Size() > maxServiceDefinitionSize {
		return nil, fmt.Errorf(
			"service definition exceeds %d-byte limit: %s",
			maxServiceDefinitionSize,
			path,
		)
	}

	data, err := securefs.ReadRegularFile(path, maxServiceDefinitionSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}

	return l.ParseServiceDefinition(data)
}

// ParseServiceDefinition parses a service definition from YAML data
func (l *Loader) ParseServiceDefinition(data []byte) (*ServiceDefinition, error) {
	var def ServiceDefinition
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&def); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("failed to parse YAML: multiple documents are not allowed")
		}
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Validate API version and kind
	if def.APIVersion != APIVersion {
		return nil, fmt.Errorf("unsupported API version: %s (expected %s)", def.APIVersion, APIVersion)
	}
	if def.Kind != KindService {
		return nil, fmt.Errorf("unexpected kind: %s (expected %s)", def.Kind, KindService)
	}

	// Apply defaults
	l.applyDefaults(&def)

	return &def, nil
}

// LoadSourceConfig loads a source configuration from a file
func (l *Loader) LoadSourceConfig(path string) (*SourceConfig, error) {
	data, err := securefs.ReadRegularFile(path, maxServiceDefinitionSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}

	return l.ParseSourceConfig(data)
}

// ParseSourceConfig parses a source configuration from YAML data
func (l *Loader) ParseSourceConfig(data []byte) (*SourceConfig, error) {
	var cfg SourceConfig
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("failed to parse YAML: multiple documents are not allowed")
		}
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}
	if cfg.APIVersion != APIVersion {
		return nil, fmt.Errorf(
			"unsupported API version: %s (expected %s)",
			cfg.APIVersion,
			APIVersion,
		)
	}
	if cfg.Kind != KindSourceConfig {
		return nil, fmt.Errorf(
			"unexpected kind: %s (expected %s)",
			cfg.Kind,
			KindSourceConfig,
		)
	}

	return &cfg, nil
}

// LoadLockFile loads a lock file
func (l *Loader) LoadLockFile(path string) (*LockFile, error) {
	data, err := securefs.ReadRegularFile(path, 16<<20)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}

	return l.ParseLockFile(data)
}

// ParseLockFile parses a lock file from YAML data
func (l *Loader) ParseLockFile(data []byte) (*LockFile, error) {
	var lock LockFile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if lock.APIVersion != APIVersion {
		return nil, fmt.Errorf("unsupported API version: %s", lock.APIVersion)
	}
	if lock.Kind != KindLockFile {
		return nil, fmt.Errorf("unexpected kind: %s (expected %s)", lock.Kind, KindLockFile)
	}
	if err := ValidateLockFile(&lock, false); err != nil {
		return nil, fmt.Errorf("invalid lock file: %w", err)
	}

	return &lock, nil
}

// LoadSourceRepository loads source repository metadata
func (l *Loader) LoadSourceRepository(path string) (*SourceRepository, error) {
	data, err := securefs.ReadRegularFile(path, maxServiceDefinitionSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}

	var repo SourceRepository
	if err := yaml.Unmarshal(data, &repo); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &repo, nil
}

// SaveServiceDefinition saves a service definition to a file
func (l *Loader) SaveServiceDefinition(path string, def *ServiceDefinition) error {
	return l.saveYAML(path, def, 0o644)
}

// SaveSourceConfig saves a source configuration to a file
func (l *Loader) SaveSourceConfig(path string, cfg *SourceConfig) error {
	if err := validateSourceConfiguration(cfg); err != nil {
		return fmt.Errorf("refusing to save invalid source configuration: %w", err)
	}
	return l.saveYAML(path, cfg, 0o600)
}

// SaveLockFile saves a lock file
func (l *Loader) SaveLockFile(path string, lock *LockFile) error {
	if err := ValidateLockFile(lock, true); err != nil {
		return fmt.Errorf("refusing to save invalid lock file: %w", err)
	}
	return l.saveYAML(path, lock, 0o644)
}

// saveYAML saves data as YAML to a file
func (l *Loader) saveYAML(path string, data interface{}, mode fs.FileMode) error {
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode YAML: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("failed to finalize YAML: %w", err)
	}
	if err := securefs.WriteFileAtomic(path, output.Bytes(), 0o755, mode); err != nil {
		return fmt.Errorf("failed to save YAML %s: %w", path, err)
	}
	return nil
}

// applyDefaults applies default values to a service definition
func (l *Loader) applyDefaults(def *ServiceDefinition) {
	if def.Spec.HealthCheck == nil && def.Spec.HealthCheckCamel != nil {
		def.Spec.HealthCheck = def.Spec.HealthCheckCamel
	}

	// Default container settings
	if def.Spec.Container.Restart == "" {
		def.Spec.Container.Restart = "unless-stopped"
	}
	if def.Spec.Container.NameTemplate == "" {
		def.Spec.Container.NameTemplate = "sdbx-{{ .Name }}"
	}

	// Default image registry
	if def.Spec.Image.Registry == "" {
		def.Spec.Image.Registry = "docker.io"
	}
	if def.Spec.Image.Tag == "" {
		def.Spec.Image.Tag = "latest"
	}

	// Default network mode
	if def.Spec.Networking.Mode == "" && def.Spec.Networking.ModeTemplate == "" {
		def.Spec.Networking.Mode = "bridge"
	}

	// Default routing path based on name
	if def.Routing.Enabled {
		if def.Routing.Subdomain == "" {
			def.Routing.Subdomain = def.Metadata.Name
		}
		if def.Routing.Path == "" {
			def.Routing.Path = "/" + def.Metadata.Name
		}
		if def.Routing.PathRouting.Strategy == "" {
			def.Routing.PathRouting.Strategy = "stripPrefix"
		}
	}

}

// DiscoverServices finds all service definitions in a directory
func (l *Loader) DiscoverServices(root string) ([]string, error) {
	var services []string
	seen := make(map[string]string)
	budget := catalogDiscoveryBudget{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != root {
			if err := budget.Observe(root, path, d); err != nil {
				return err
			}
		}

		// Skip hidden directories
		if path != root && d.IsDir() && strings.HasPrefix(d.Name(), ".") {
			return filepath.SkipDir
		}

		// Look for service.yaml files
		if !d.IsDir() && d.Name() == "service.yaml" {
			relativePath, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			components := strings.Split(relativePath, string(filepath.Separator))
			if !isCanonicalServiceDefinitionPath(components) {
				return fmt.Errorf(
					"service definition must use <name>/service.yaml, core/<name>/service.yaml, or addons/<name>/service.yaml: %s",
					path,
				)
			}
			// Get service name from parent directory
			serviceName := filepath.Base(filepath.Dir(path))
			if previousPath, exists := seen[serviceName]; exists {
				return fmt.Errorf(
					"duplicate service directory name %q in %s and %s",
					serviceName,
					previousPath,
					path,
				)
			}
			seen[serviceName] = path
			services = append(services, serviceName)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to discover services: %w", err)
	}

	return services, nil
}

type catalogDiscoveryBudget struct {
	entries         int
	definitions     int
	treeBytes       int64
	definitionBytes int64
}

func (b *catalogDiscoveryBudget) Observe(
	root string,
	path string,
	entry fs.DirEntry,
) error {
	b.entries++
	if b.entries > maxCatalogEntries {
		return fmt.Errorf("catalog exceeds the %d-entry discovery limit", maxCatalogEntries)
	}

	relativePath, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	depth := len(strings.Split(relativePath, string(filepath.Separator)))
	if depth > maxCatalogTraversalDepth {
		return fmt.Errorf(
			"catalog path exceeds the %d-component discovery depth limit: %s",
			maxCatalogTraversalDepth,
			relativePath,
		)
	}
	if entry.Type()&os.ModeSymlink != 0 {
		return fmt.Errorf("catalog entries must not be symbolic links: %s", path)
	}
	if !entry.Type().IsRegular() {
		return nil
	}
	info, err := entry.Info()
	if err != nil {
		return err
	}
	size := info.Size()
	if size > maxCatalogTraversalFile {
		return fmt.Errorf(
			"catalog file exceeds the %d-byte traversal limit: %s",
			maxCatalogTraversalFile,
			path,
		)
	}
	if size > maxCatalogTreeBytes-b.treeBytes {
		return fmt.Errorf("catalog exceeds the %d-byte tree limit", maxCatalogTreeBytes)
	}
	b.treeBytes += size

	if entry.Name() != "service.yaml" {
		return nil
	}
	if size > maxServiceDefinitionSize {
		return fmt.Errorf(
			"service definition exceeds %d-byte limit: %s",
			maxServiceDefinitionSize,
			path,
		)
	}
	b.definitions++
	if b.definitions > maxCatalogDefinitions {
		return fmt.Errorf(
			"catalog exceeds the %d-definition parse limit",
			maxCatalogDefinitions,
		)
	}
	if size > maxCatalogDefinitionBytes-b.definitionBytes {
		return fmt.Errorf(
			"catalog exceeds the %d-byte definition parse limit",
			maxCatalogDefinitionBytes,
		)
	}
	b.definitionBytes += size
	return nil
}

func isCanonicalServiceDefinitionPath(components []string) bool {
	if len(components) == 2 && components[1] == "service.yaml" {
		return true
	}
	return len(components) == 3 &&
		(components[0] == "core" || components[0] == "addons") &&
		components[2] == "service.yaml"
}

// LoadServicesFromDir loads all service definitions from a directory
func (l *Loader) LoadServicesFromDir(root string) ([]*ServiceDefinition, error) {
	services, err := l.DiscoverServices(root)
	if err != nil {
		return nil, err
	}

	var defs []*ServiceDefinition
	seenDefinitions := make(map[string]string)
	for _, name := range services {
		path := filepath.Join(root, name, "service.yaml")
		// Also check in core/ and addons/ subdirectories
		if _, err := os.Stat(path); os.IsNotExist(err) {
			path = filepath.Join(root, "core", name, "service.yaml")
			if _, err := os.Stat(path); os.IsNotExist(err) {
				path = filepath.Join(root, "addons", name, "service.yaml")
			}
		}

		def, err := l.LoadServiceDefinition(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load service %s: %w", name, err)
		}
		if def.Metadata.Name != name {
			return nil, fmt.Errorf(
				"service metadata name %q does not match directory %q in %s",
				def.Metadata.Name,
				name,
				path,
			)
		}
		if previousPath, exists := seenDefinitions[def.Metadata.Name]; exists {
			return nil, fmt.Errorf(
				"duplicate service metadata name %q in %s and %s",
				def.Metadata.Name,
				previousPath,
				path,
			)
		}
		seenDefinitions[def.Metadata.Name] = path
		defs = append(defs, def)
	}

	return defs, nil
}

// WriteYAML writes data as YAML to a writer
func WriteYAML(w io.Writer, data interface{}) error {
	encoder := yaml.NewEncoder(w)
	encoder.SetIndent(2)
	return encoder.Encode(data)
}
