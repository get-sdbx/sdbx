// Package registry provides a service registry for managing SDBX service definitions.
// It supports multiple sources (Git, local), YAML-based service definitions,
// and version pinning through lock files.
package registry

import "time"

// API version for service definitions
const (
	APIVersion           = "sdbx.one/v1"
	KindService          = "Service"
	KindSourceRepository = "SourceRepository"
	KindSourceConfig     = "SourceConfig"
	KindLockFile         = "LockFile"
)

// ServiceCategory defines the category of a service
type ServiceCategory string

const (
	CategoryMedia      ServiceCategory = "media"
	CategoryDownloads  ServiceCategory = "downloads"
	CategoryManagement ServiceCategory = "management"
	CategoryUtility    ServiceCategory = "utility"
	CategoryNetworking ServiceCategory = "networking"
	CategoryAuth       ServiceCategory = "auth"
)

// ServiceDefinition represents a complete service definition loaded from YAML
type ServiceDefinition struct {
	APIVersion      string                `yaml:"apiVersion"`
	Kind            string                `yaml:"kind"`
	Metadata        ServiceMetadata       `yaml:"metadata"`
	ApplicationAuth ApplicationAuthConfig `yaml:"applicationAuth"`
	Presentation    Presentation          `yaml:"presentation,omitempty"`
	Permissions     []string              `yaml:"permissions,omitempty"`
	Spec            ServiceSpec           `yaml:"spec"`
	Routing         RoutingConfig         `yaml:"routing,omitempty"`
	Secrets         []SecretDef           `yaml:"secrets,omitempty"`
	Integrations    Integrations          `yaml:"integrations,omitempty"`
	Conditions      Conditions            `yaml:"conditions,omitempty"`
}

// ApplicationAuthMode records the credential boundary implemented by the
// application itself, independently from the route's Authelia ownership.
type ApplicationAuthMode string

const (
	ApplicationAuthNone                ApplicationAuthMode = "none"
	ApplicationAuthIdentityProvider    ApplicationAuthMode = "identity-provider"
	ApplicationAuthSDBXManagedForms    ApplicationAuthMode = "sdbx-managed-forms"
	ApplicationAuthSDBXManagedPassword ApplicationAuthMode = "sdbx-managed-password" // #nosec G101 -- public enum label, not a credential.
	ApplicationAuthSDBXManagedAPIKey   ApplicationAuthMode = "sdbx-managed-api-key"  // #nosec G101 -- public enum label, not a credential.
	ApplicationAuthServiceManaged      ApplicationAuthMode = "service-managed"
	ApplicationAuthUpstreamDefault     ApplicationAuthMode = "upstream-default"
)

// ApplicationAuthConfig declares who owns the application's native login or
// API credential. Every official definition must set it explicitly.
type ApplicationAuthConfig struct {
	Mode ApplicationAuthMode `yaml:"mode"`
}

// ServiceMetadata contains service identification and descriptive information
type ServiceMetadata struct {
	Name          string          `yaml:"name"`
	Version       string          `yaml:"version"`
	Category      ServiceCategory `yaml:"category"`
	Description   string          `yaml:"description"`
	Homepage      string          `yaml:"homepage,omitempty"`
	Documentation string          `yaml:"documentation,omitempty"`
	Maintainer    string          `yaml:"maintainer,omitempty"`
	Tags          []string        `yaml:"tags,omitempty"`
}

// Presentation contains bounded, non-secret hints for first-party operator
// surfaces. It never changes runtime activation, routing, or permissions.
type Presentation struct {
	Launcher *LauncherPresentation `yaml:"launcher,omitempty"`
}

// LauncherPresentation controls whether a routed service appears in the
// built-in management dashboard launcher.
type LauncherPresentation struct {
	Enabled  bool   `yaml:"enabled"`
	Group    string `yaml:"group"`
	Icon     string `yaml:"icon,omitempty"`
	Subtitle string `yaml:"subtitle,omitempty"`
}

// ServiceSpec defines the container and runtime configuration
type ServiceSpec struct {
	Image            ImageSpec       `yaml:"image"`
	Container        ContainerSpec   `yaml:"container"`
	Environment      EnvironmentSpec `yaml:"environment,omitempty"`
	Volumes          []VolumeMount   `yaml:"volumes,omitempty"`
	Ports            PortSpec        `yaml:"ports,omitempty"`
	Networking       NetworkSpec     `yaml:"networking,omitempty"`
	HealthCheck      *HealthCheck    `yaml:"healthcheck,omitempty"`
	HealthCheckCamel *HealthCheck    `yaml:"healthCheck,omitempty"`
	Dependencies     DependencySpec  `yaml:"dependencies,omitempty"`
}

// ImageSpec defines the container image configuration
type ImageSpec struct {
	Repository string `yaml:"repository"`
	Tag        string `yaml:"tag"`
	Registry   string `yaml:"registry,omitempty"`
}

// ContainerSpec defines container runtime settings
type ContainerSpec struct {
	NameTemplate string `yaml:"name_template"`
	Restart      string `yaml:"restart,omitempty"`
	// Hostname sets a stable RFC 1123 hostname for applications that persist
	// the container hostname as their instance identity.
	Hostname string `yaml:"hostname,omitempty"`
	// User overrides the runtime UID:GID and supports catalog templates.
	// SDBX accepts only non-root numeric identities after rendering.
	User    string `yaml:"user,omitempty"`
	Command string `yaml:"command,omitempty"`
	// WorkingDir overrides the container's WORKDIR and supports templates.
	WorkingDir         string              `yaml:"working_dir,omitempty"`
	ShmSize            string              `yaml:"shm_size,omitempty"`
	Sysctls            map[string]string   `yaml:"sysctls,omitempty"`
	CustomLabels       map[string]string   `yaml:"customLabels,omitempty"`
	Privileged         bool                `yaml:"privileged,omitempty"`
	ReadOnlyRoot       bool                `yaml:"readOnlyRootFilesystem,omitempty"`
	Tmpfs              []string            `yaml:"tmpfs,omitempty"`
	PidsLimit          int                 `yaml:"pidsLimit,omitempty"`
	StopGrace          string              `yaml:"stopGracePeriod,omitempty"`
	Capabilities       CapabilitiesSpec    `yaml:"capabilities,omitempty"`
	Devices            []string            `yaml:"devices,omitempty"`
	ConditionalDevices []ConditionalDevice `yaml:"conditional_devices,omitempty"`
	// Init, when true, runs an init process (PID 1) inside the container that
	// reaps zombies and forwards signals. Required by some images that don't
	// ship their own init (e.g. Seerr).
	Init bool `yaml:"init,omitempty"`
}

// ConditionalDevice declares bounded device access behind an explicit condition.
type ConditionalDevice struct {
	Device string `yaml:"device"`
	When   string `yaml:"when"`
}

// CapabilitiesSpec defines Linux capabilities to add or drop
type CapabilitiesSpec struct {
	Add  []string `yaml:"add,omitempty"`
	Drop []string `yaml:"drop,omitempty"`
}

// EnvironmentSpec defines environment variables for the service
type EnvironmentSpec struct {
	Static      []EnvVar            `yaml:"static,omitempty"`
	Conditional []ConditionalEnvVar `yaml:"conditional,omitempty"`
	EnvFile     []string            `yaml:"envFile,omitempty"`
}

// EnvVar represents a single environment variable
type EnvVar struct {
	Name      string       `yaml:"name"`
	Value     string       `yaml:"value,omitempty"`
	ValueFrom *ValueSource `yaml:"valueFrom,omitempty"`
}

// ConditionalEnvVar is an environment variable with a condition
type ConditionalEnvVar struct {
	EnvVar `yaml:",inline"`
	When   string `yaml:"when,omitempty"`
}

// ValueSource defines where to get a value from
type ValueSource struct {
	SecretRef string `yaml:"secretRef,omitempty"`
	ConfigRef string `yaml:"configRef,omitempty"`
}

// VolumeMount defines a volume mount for the container
type VolumeMount struct {
	Name          string `yaml:"name,omitempty"`
	HostPath      string `yaml:"hostPath"`
	ContainerPath string `yaml:"containerPath"`
	ReadOnly      bool   `yaml:"readOnly,omitempty"`
	When          string `yaml:"when,omitempty"`
	// Chown, when true, makes the generator chown the resolved host path to
	// the project's PUID:PGID after creating it. Use for images that run as a
	// non-root user (e.g. filebrowser) and need to write to a host-managed
	// volume that sdbx mkdir'd as root.
	Chown bool `yaml:"chown,omitempty"`
	// ChownUID and ChownGID override the project PUID:PGID for images whose
	// documented non-root identity is fixed. They must be set together and
	// require Chown.
	ChownUID int `yaml:"chownUID,omitempty"`
	ChownGID int `yaml:"chownGID,omitempty"`
}

// PortSpec defines port mappings
type PortSpec struct {
	Static      []string          `yaml:"static,omitempty"`
	Conditional []ConditionalPort `yaml:"conditional,omitempty"`
}

// ConditionalPort is a port mapping with a condition
type ConditionalPort struct {
	Port string `yaml:"port"`
	When string `yaml:"when"`
}

// NetworkSpec defines network configuration
type NetworkSpec struct {
	Networks     []NetworkRef `yaml:"networks,omitempty"`
	Mode         string       `yaml:"mode,omitempty"`
	ModeTemplate string       `yaml:"modeTemplate,omitempty"`
}

// NetworkRef is a network reference with optional condition
type NetworkRef struct {
	Name string `yaml:"name,omitempty"`
	When string `yaml:"when,omitempty"`
}

// HealthCheck defines container health check configuration
type HealthCheck struct {
	Test        []string `yaml:"test"`
	Interval    string   `yaml:"interval,omitempty"`
	Timeout     string   `yaml:"timeout,omitempty"`
	Retries     int      `yaml:"retries,omitempty"`
	StartPeriod string   `yaml:"start_period,omitempty"`
}

// DependencySpec defines service dependencies
type DependencySpec struct {
	Required    []string                `yaml:"required,omitempty"`
	Conditional []ConditionalDependency `yaml:"conditional,omitempty"`
}

// ConditionalDependency is a dependency with conditions
type ConditionalDependency struct {
	Name      string `yaml:"name"`
	Condition string `yaml:"condition,omitempty"`
	When      string `yaml:"when,omitempty"`
}

// RoutingConfig defines how the service is exposed via Traefik
type RoutingConfig struct {
	Enabled        bool              `yaml:"enabled"`
	Port           int               `yaml:"port,omitempty"`
	Subdomain      string            `yaml:"subdomain,omitempty"`
	Path           string            `yaml:"path,omitempty"`
	PathRouting    PathRoutingConfig `yaml:"pathRouting,omitempty"`
	Auth           AuthConfig        `yaml:"auth,omitempty"`
	ForceSubdomain bool              `yaml:"forceSubdomain,omitempty"`
	Traefik        TraefikConfig     `yaml:"traefik,omitempty"`
}

// PathRoutingConfig defines path-based routing behavior
type PathRoutingConfig struct {
	Strategy      string `yaml:"strategy,omitempty"`
	URLBaseEnvVar string `yaml:"urlBaseEnvVar,omitempty"`
}

// AuthMode declares which layer owns authentication for a routed service.
type AuthMode string

const (
	AuthModeAdminOnly AuthMode = "admin-only"
	AuthModeProtected AuthMode = "protected"
	AuthModeNative    AuthMode = "native-auth"
	AuthModePublic    AuthMode = "public"
)

// AuthConfig defines the mandatory security classification for a route.
type AuthConfig struct {
	Mode AuthMode `yaml:"mode"`
}

// RequiresForwardAuth reports whether Traefik must invoke Authelia.
func (a AuthConfig) RequiresForwardAuth() bool {
	return a.Mode == AuthModeAdminOnly || a.Mode == AuthModeProtected
}

// TraefikConfig selects the trust-boundary network Traefik uses to reach a
// routed service. Router priorities and middleware chains are generated by
// SDBX and are intentionally not extensible from catalog definitions.
type TraefikConfig struct {
	Network string `yaml:"network,omitempty"`
}

// SecretDef defines a secret required by the service
type SecretDef struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	Length      int    `yaml:"length,omitempty"`
	Optional    bool   `yaml:"optional,omitempty"`
	Description string `yaml:"description,omitempty"`
}

// Integrations defines how the service integrates with other components
type Integrations struct {
	Cloudflared *CloudflaredIntegration `yaml:"cloudflared,omitempty"`
	Unpackerr   *UnpackerrIntegration   `yaml:"unpackerr,omitempty"`
}

// CloudflaredIntegration defines Cloudflare Tunnel integration
type CloudflaredIntegration struct {
	Enabled bool `yaml:"enabled"`
}

// UnpackerrIntegration defines Unpackerr integration for *arr services
type UnpackerrIntegration struct {
	Enabled      bool   `yaml:"enabled"`
	URLEnvVar    string `yaml:"urlEnvVar,omitempty"`
	APIKeyEnvVar string `yaml:"apiKeyEnvVar,omitempty"`
	InternalURL  string `yaml:"internalUrl,omitempty"`
}

// Conditions defines when a service should be included
type Conditions struct {
	Always        bool   `yaml:"always,omitempty"`
	RequireAddon  bool   `yaml:"requireAddon,omitempty"`
	RequireConfig string `yaml:"requireConfig,omitempty"`
}

// SourceConfig defines the user's source configuration
type SourceConfig struct {
	APIVersion string               `yaml:"apiVersion"`
	Kind       string               `yaml:"kind"`
	Metadata   SourceConfigMetadata `yaml:"metadata"`
	Sources    []Source             `yaml:"sources"`
	Cache      CacheConfig          `yaml:"cache,omitempty"`
	Security   SecurityConfig       `yaml:"security,omitempty"`
}

// SourceConfigMetadata contains version info
type SourceConfigMetadata struct {
	Version int `yaml:"version"`
}

// Source defines a service definition source
type Source struct {
	Name           string     `yaml:"name"`
	Type           string     `yaml:"type"`
	URL            string     `yaml:"url,omitempty"`
	Path           string     `yaml:"path,omitempty"`
	Ref            string     `yaml:"ref,omitempty"`
	SigningKey     string     `yaml:"signingKey,omitempty"`
	SSHKey         string     `yaml:"sshKey,omitempty"`
	Priority       int        `yaml:"priority"`
	Enabled        bool       `yaml:"enabled"`
	Trust          TrustLevel `yaml:"trust,omitempty"`
	LegacyBranch   string     `yaml:"branch,omitempty"`
	LegacySSHKey   string     `yaml:"ssh_key,omitempty"`
	LegacyVerified bool       `yaml:"verified,omitempty"`
}

// CacheConfig defines source caching settings
type CacheConfig struct {
	Directory string `yaml:"directory,omitempty"`
	TTL       string `yaml:"ttl,omitempty"`
}

// SecurityConfig defines security settings for sources
type SecurityConfig struct {
	AllowUnverified   bool                  `yaml:"allowUnverified,omitempty"`
	RequireSignatures bool                  `yaml:"requireSignatures,omitempty"`
	TrustLevels       map[string]TrustLevel `yaml:"trustLevels,omitempty"`
}

// TrustLevel defines what a source is allowed to do
type TrustLevel struct {
	AllowCatalogPermissions []string `yaml:"allowCatalogPermissions,omitempty"`
	AllowedRegistries       []string `yaml:"allowedRegistries,omitempty"`
}

// SourceRepository is metadata for a service repository
type SourceRepository struct {
	APIVersion    string               `yaml:"apiVersion"`
	Kind          string               `yaml:"kind"`
	Metadata      SourceRepositoryMeta `yaml:"metadata"`
	SchemaVersion string               `yaml:"schemaVersion"`
	MinCLIVersion string               `yaml:"minCliVersion,omitempty"`
	Categories    []string             `yaml:"categories,omitempty"`
}

// SourceRepositoryMeta contains repository identification
type SourceRepositoryMeta struct {
	Name        string       `yaml:"name"`
	Version     string       `yaml:"version"`
	Description string       `yaml:"description,omitempty"`
	Maintainers []Maintainer `yaml:"maintainers,omitempty"`
	License     string       `yaml:"license,omitempty"`
}

// Maintainer represents a repository maintainer
type Maintainer struct {
	Name  string `yaml:"name"`
	Email string `yaml:"email,omitempty"`
}

// LockFile represents a lock file for reproducible builds
type LockFile struct {
	APIVersion     string                   `yaml:"apiVersion"`
	Kind           string                   `yaml:"kind"`
	Metadata       LockFileMetadata         `yaml:"metadata"`
	Sources        map[string]LockedSource  `yaml:"sources"`
	Services       map[string]LockedService `yaml:"services"`
	InstallOrder   []string                 `yaml:"installOrder,omitempty"`
	GeneratedFiles map[string]string        `yaml:"generatedFiles,omitempty"`
}

// LockFileMetadata contains lock file version info
type LockFileMetadata struct {
	Version        int       `yaml:"version"`
	GeneratedAt    time.Time `yaml:"generatedAt"`
	CLIVersion     string    `yaml:"cliVersion"`
	CatalogVersion string    `yaml:"catalogVersion"`
	ConfigDigest   string    `yaml:"configDigest"`
	CatalogDigest  string    `yaml:"catalogDigest"`
}

// LockedSource represents a pinned source
type LockedSource struct {
	Type        string   `yaml:"type"`
	URL         string   `yaml:"url,omitempty"`
	Path        string   `yaml:"path,omitempty"`
	Ref         string   `yaml:"ref"`
	Commit      string   `yaml:"commit"`
	SigningKey  string   `yaml:"signingKey,omitempty"`
	Priority    int      `yaml:"priority"`
	Permissions []string `yaml:"permissions,omitempty"`
	Registries  []string `yaml:"registries,omitempty"`
	Digest      string   `yaml:"digest"`
	Verified    bool     `yaml:"verified"`
}

// LockedService represents a pinned service
type LockedService struct {
	Source            string      `yaml:"source"`
	DefinitionVersion string      `yaml:"definitionVersion"`
	DefinitionDigest  string      `yaml:"definitionDigest"`
	Image             LockedImage `yaml:"image"`
	ResolvedFrom      string      `yaml:"resolvedFrom"`
}

// LockedImage represents a pinned container image
type LockedImage struct {
	Registry        string            `yaml:"registry"`
	Repository      string            `yaml:"repository"`
	Tag             string            `yaml:"tag"`
	Digest          string            `yaml:"digest,omitempty"`
	Platform        string            `yaml:"platform"`
	PlatformDigest  string            `yaml:"platformDigest"`
	PlatformDigests map[string]string `yaml:"platformDigests,omitempty"`
}

// ResolvedService represents a fully resolved service ready for generation
type ResolvedService struct {
	Name            string
	Source          string
	SourcePath      string
	Definition      *ServiceDefinition
	DefinitionHash  string
	FinalDefinition *ServiceDefinition
	Dependencies    []string
	Enabled         bool
}

// ResolutionGraph represents the resolved dependency graph of services
type ResolutionGraph struct {
	Services map[string]*ResolvedService
	Order    []string
	Errors   []ResolutionError
	Warnings []ResolutionWarning
}

// ResolutionWarning represents a non-fatal warning during service resolution.
type ResolutionWarning struct {
	Service string
	Field   string
	Message string
}

// ResolutionError represents an error during service resolution
type ResolutionError struct {
	Service string
	Message string
	Cause   error
}

func (e ResolutionError) Error() string {
	if e.Cause != nil {
		return e.Service + ": " + e.Message + ": " + e.Cause.Error()
	}
	return e.Service + ": " + e.Message
}

// ValidationError represents a service definition validation error
type ValidationError struct {
	Field    string
	Message  string
	Severity string
}

func (e ValidationError) Error() string {
	return e.Field + ": " + e.Message
}
