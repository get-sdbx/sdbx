package registry

import (
	"fmt"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	PermissionPrivileged  = "privileged"
	PermissionHostNetwork = "host-network"
	PermissionDevice      = "device"
	PermissionHostChown   = "host-chown"
	PermissionHostMount   = "host-mount"
	PermissionConfigPath  = "config-path"
	PermissionDataPath    = "data-path"
	PermissionDownloads   = "downloads-path"
	PermissionHostPort    = "host-port"
	PermissionMediaPath   = "media-path"
	PermissionProjectPath = "project-path"
	PermissionRoute       = "route"
	PermissionSecretsPath = "secrets-path"
	NetworkEdge           = "edge"
	NetworkApplication    = "app"
	NetworkDownload       = "download"
	NetworkManagement     = "management"
)

var routePathRegex = regexp.MustCompile(`^/(?:[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)?$`)

var (
	capabilityPermissionPattern     = regexp.MustCompile(`^capability:[A-Z][A-Z0-9_]*$`)
	secretPermissionPattern         = regexp.MustCompile(`^secret:[a-z][a-z0-9_]*$`)
	networkPermissionPattern        = regexp.MustCompile(`^network:(?:edge|app|download|management)$`)
	serviceNetworkPermissionPattern = regexp.MustCompile(
		`^service-network:[a-z0-9][a-z0-9-]{0,62}$`,
	)
	serviceOverridePermissionPattern = regexp.MustCompile(
		`^service-override:[a-z0-9][a-z0-9-]{0,62}$`,
	)
	routePermissionPattern = regexp.MustCompile(
		`^route:(?:admin-only|protected|native-auth|public)$`,
	)
	serviceNetworkReferencePattern = regexp.MustCompile(
		`service:([a-z0-9][a-z0-9-]{0,62})`,
	)
	launcherIconPattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	catalogConfigReference  = regexp.MustCompile(`\.Config\.([A-Za-z][A-Za-z0-9_]*)`)
	catalogSecretsReference = regexp.MustCompile(`\.Secrets(?:[.\s}\[])`)
	catalogRootReference    = regexp.MustCompile(
		`(?:^|[\s({])\.([A-Z][A-Za-z0-9_]*)`,
	)
)

// Validator validates service definitions
type Validator struct {
	allowedRegistries map[string]bool
	dangerousCaps     map[string]bool
}

// NewValidator creates a new Validator
func NewValidator() *Validator {
	return &Validator{
		allowedRegistries: map[string]bool{
			"docker.io":       true,
			"ghcr.io":         true,
			"lscr.io":         true,
			"quay.io":         true,
			"registry.k8s.io": true,
		},
		dangerousCaps: map[string]bool{
			"NET_ADMIN":       true,
			"SYS_ADMIN":       true,
			"SYS_PTRACE":      true,
			"SYS_MODULE":      true,
			"SYS_RAWIO":       true,
			"SYS_TIME":        true,
			"DAC_READ_SEARCH": true,
		},
	}
}

// Validate validates a service definition and returns all errors
func (v *Validator) Validate(def *ServiceDefinition) []ValidationError {
	var errors []ValidationError

	// Validate metadata
	errors = append(errors, v.validateMetadata(def)...)

	// Validate bounded presentation hints before they reach operator UIs.
	errors = append(errors, v.validatePresentation(def)...)

	// Validate spec
	errors = append(errors, v.validateSpec(def)...)

	// Validate activation selectors, conditional fields, and dependency policy.
	errors = append(errors, v.validateConditions(def)...)

	// Validate routing
	errors = append(errors, v.validateRouting(def)...)

	// Validate bounded cross-service integration metadata before generators use
	// it to construct environment variables or internal network endpoints.
	errors = append(errors, v.validateIntegrations(def)...)

	// Validate least-privilege network placement.
	errors = append(errors, v.validateNetworking(def)...)

	// Catalog templates only receive an explicit, non-secret configuration DTO.
	errors = append(errors, v.validateCatalogTemplates(def)...)

	// Validate explicit catalog permissions before evaluating security warnings.
	errors = append(errors, v.validatePermissions(def)...)

	// Validate security
	errors = append(errors, v.validateSecurity(def)...)

	return errors
}

func (v *Validator) validatePresentation(def *ServiceDefinition) []ValidationError {
	launcher := def.Presentation.Launcher
	if launcher == nil {
		return nil
	}

	var errors []ValidationError
	if !launcher.Enabled {
		errors = append(errors, ValidationError{
			Field:    "presentation.launcher.enabled",
			Message:  "declared launcher entries must be enabled; omit the block to hide a service",
			Severity: "error",
		})
	}
	if !def.Routing.Enabled {
		errors = append(errors, ValidationError{
			Field:    "presentation.launcher",
			Message:  "launcher entries require a routed service",
			Severity: "error",
		})
	}
	switch launcher.Group {
	case "media", "downloads", "management", "utilities":
	default:
		errors = append(errors, ValidationError{
			Field:    "presentation.launcher.group",
			Message:  "must be one of media, downloads, management, or utilities",
			Severity: "error",
		})
	}
	if launcher.Icon != "" && !launcherIconPattern.MatchString(launcher.Icon) {
		errors = append(errors, ValidationError{
			Field:    "presentation.launcher.icon",
			Message:  "must be a lowercase icon token without a path, URL, extension, or markup",
			Severity: "error",
		})
	}
	if utf8.RuneCountInString(launcher.Subtitle) > 80 {
		errors = append(errors, ValidationError{
			Field:    "presentation.launcher.subtitle",
			Message:  "must not exceed 80 characters",
			Severity: "error",
		})
	}
	if strings.Contains(launcher.Subtitle, "{{") ||
		strings.Contains(launcher.Subtitle, "}}") ||
		strings.IndexFunc(launcher.Subtitle, unicode.IsControl) >= 0 {
		errors = append(errors, ValidationError{
			Field:    "presentation.launcher.subtitle",
			Message:  "must not contain templates or control characters",
			Severity: "error",
		})
	}
	return errors
}

func (v *Validator) validateIntegrations(def *ServiceDefinition) []ValidationError {
	integration := def.Integrations.Unpackerr
	if integration == nil {
		return nil
	}

	var errors []ValidationError
	if !integration.Enabled {
		errors = append(errors, ValidationError{
			Field:    "integrations.unpackerr.enabled",
			Message:  "declared Unpackerr integrations must be enabled; omit the block otherwise",
			Severity: "error",
		})
	}

	type unpackerrContract struct {
		urlEnvVar    string
		apiKeyEnvVar string
		internalURL  string
	}
	// #nosec G101 -- these are public environment-variable names, not credential values.
	contracts := map[string]unpackerrContract{
		"sonarr": {
			urlEnvVar:    "UN_SONARR_0_URL",
			apiKeyEnvVar: "UN_SONARR_0_API_KEY",
			internalURL:  "http://sdbx-sonarr:8989",
		},
		"radarr": {
			urlEnvVar:    "UN_RADARR_0_URL",
			apiKeyEnvVar: "UN_RADARR_0_API_KEY",
			internalURL:  "http://sdbx-radarr:7878",
		},
		"lidarr": {
			urlEnvVar:    "UN_LIDARR_0_URL",
			apiKeyEnvVar: "UN_LIDARR_0_API_KEY",
			internalURL:  "http://sdbx-lidarr:8686",
		},
		"whisparr": {
			urlEnvVar:    "UN_WHISPARR_0_URL",
			apiKeyEnvVar: "UN_WHISPARR_0_API_KEY",
			internalURL:  "http://sdbx-whisparr:6969",
		},
	}
	contract, supported := contracts[def.Metadata.Name]
	if !supported {
		errors = append(errors, ValidationError{
			Field:    "integrations.unpackerr",
			Message:  "is supported only for sonarr, radarr, lidarr, or whisparr",
			Severity: "error",
		})
		return errors
	}
	for _, field := range []struct {
		path string
		got  string
		want string
	}{
		{
			path: "integrations.unpackerr.urlEnvVar",
			got:  integration.URLEnvVar,
			want: contract.urlEnvVar,
		},
		{
			path: "integrations.unpackerr.apiKeyEnvVar",
			got:  integration.APIKeyEnvVar,
			want: contract.apiKeyEnvVar,
		},
		{
			path: "integrations.unpackerr.internalUrl",
			got:  integration.InternalURL,
			want: contract.internalURL,
		},
	} {
		if field.got != field.want {
			errors = append(errors, ValidationError{
				Field:    field.path,
				Message:  fmt.Sprintf("must be %q for %s", field.want, def.Metadata.Name),
				Severity: "error",
			})
		}
	}
	return errors
}

// validateMetadata validates service metadata
func (v *Validator) validateMetadata(def *ServiceDefinition) []ValidationError {
	var errors []ValidationError

	if def.Metadata.Name == "" {
		errors = append(errors, ValidationError{
			Field:    "metadata.name",
			Message:  "name is required",
			Severity: "error",
		})
	} else if !isValidServiceName(def.Metadata.Name) {
		errors = append(errors, ValidationError{
			Field:    "metadata.name",
			Message:  "name must be lowercase alphanumeric with hyphens",
			Severity: "error",
		})
	}

	if def.Metadata.Version == "" {
		errors = append(errors, ValidationError{
			Field:    "metadata.version",
			Message:  "version is required",
			Severity: "error",
		})
	}

	if def.Metadata.Category == "" {
		errors = append(errors, ValidationError{
			Field:    "metadata.category",
			Message:  "category is required",
			Severity: "error",
		})
	} else if !isValidCategory(def.Metadata.Category) {
		errors = append(errors, ValidationError{
			Field:    "metadata.category",
			Message:  fmt.Sprintf("invalid category: %s", def.Metadata.Category),
			Severity: "error",
		})
	}

	if def.Metadata.Description == "" {
		errors = append(errors, ValidationError{
			Field:    "metadata.description",
			Message:  "description is recommended",
			Severity: "warning",
		})
	}

	return errors
}

// validateSpec validates the service spec
func (v *Validator) validateSpec(def *ServiceDefinition) []ValidationError {
	var errors []ValidationError

	// Validate image
	if def.Spec.Image.Repository == "" {
		errors = append(errors, ValidationError{
			Field:    "spec.image.repository",
			Message:  "image repository is required",
			Severity: "error",
		})
	}

	// Validate container name template
	if def.Spec.Container.NameTemplate == "" {
		errors = append(errors, ValidationError{
			Field:    "spec.container.name_template",
			Message:  "container name template is required",
			Severity: "error",
		})
	} else if !strings.Contains(def.Spec.Container.NameTemplate, "{{") {
		errors = append(errors, ValidationError{
			Field:    "spec.container.name_template",
			Message:  "container name template should use Go template syntax",
			Severity: "warning",
		})
	}

	if def.Spec.Container.PidsLimit < 0 {
		errors = append(errors, ValidationError{
			Field:    "spec.container.pidsLimit",
			Message:  "process limit must be positive",
			Severity: "error",
		})
	}
	if def.Spec.Container.StopGrace != "" {
		duration, err := time.ParseDuration(def.Spec.Container.StopGrace)
		if err != nil || duration <= 0 {
			errors = append(errors, ValidationError{
				Field:    "spec.container.stopGracePeriod",
				Message:  "must be a positive Go duration such as 30s",
				Severity: "error",
			})
		}
	}
	seenTmpfs := make(map[string]bool, len(def.Spec.Container.Tmpfs))
	for i, mount := range def.Spec.Container.Tmpfs {
		mountPath, _, _ := strings.Cut(mount, ":")
		if !strings.HasPrefix(mountPath, "/") || path.Clean(mountPath) != mountPath {
			errors = append(errors, ValidationError{
				Field:    fmt.Sprintf("spec.container.tmpfs[%d]", i),
				Message:  "tmpfs mount must use a clean absolute container path",
				Severity: "error",
			})
		}
		if seenTmpfs[mountPath] {
			errors = append(errors, ValidationError{
				Field:    fmt.Sprintf("spec.container.tmpfs[%d]", i),
				Message:  fmt.Sprintf("tmpfs path %s is declared more than once", mountPath),
				Severity: "error",
			})
		}
		seenTmpfs[mountPath] = true
	}

	// Validate volumes
	for i, vol := range def.Spec.Volumes {
		if vol.HostPath == "" {
			errors = append(errors, ValidationError{
				Field:    fmt.Sprintf("spec.volumes[%d].hostPath", i),
				Message:  "hostPath is required",
				Severity: "error",
			})
		}
		if vol.ContainerPath == "" {
			errors = append(errors, ValidationError{
				Field:    fmt.Sprintf("spec.volumes[%d].containerPath", i),
				Message:  "containerPath is required",
				Severity: "error",
			})
		}
		if (vol.ChownUID == 0) != (vol.ChownGID == 0) {
			errors = append(errors, ValidationError{
				Field:    fmt.Sprintf("spec.volumes[%d]", i),
				Message:  "chownUID and chownGID must be set together",
				Severity: "error",
			})
		}
		if (vol.ChownUID != 0 || vol.ChownGID != 0) && !vol.Chown {
			errors = append(errors, ValidationError{
				Field:    fmt.Sprintf("spec.volumes[%d]", i),
				Message:  "fixed ownership requires chown: true",
				Severity: "error",
			})
		}
		if vol.ChownUID < 0 || vol.ChownGID < 0 {
			errors = append(errors, ValidationError{
				Field:    fmt.Sprintf("spec.volumes[%d]", i),
				Message:  "fixed ownership IDs must be positive",
				Severity: "error",
			})
		}
	}

	// Validate environment variables
	for i, env := range def.Spec.Environment.Static {
		if env.Name == "" {
			errors = append(errors, ValidationError{
				Field:    fmt.Sprintf("spec.environment.static[%d].name", i),
				Message:  "environment variable name is required",
				Severity: "error",
			})
		}
		if env.Value == "" && env.ValueFrom == nil {
			errors = append(errors, ValidationError{
				Field:    fmt.Sprintf("spec.environment.static[%d]", i),
				Message:  "environment variable must have value or valueFrom",
				Severity: "error",
			})
		}
		errors = append(errors, validateEnvironmentValueSource(
			fmt.Sprintf("spec.environment.static[%d]", i),
			env,
		)...)
	}

	// Validate conditional environment variables
	for i, env := range def.Spec.Environment.Conditional {
		if env.Name == "" {
			errors = append(errors, ValidationError{
				Field:    fmt.Sprintf("spec.environment.conditional[%d].name", i),
				Message:  "environment variable name is required",
				Severity: "error",
			})
		}
		if env.When == "" {
			errors = append(errors, ValidationError{
				Field:    fmt.Sprintf("spec.environment.conditional[%d].when", i),
				Message:  "conditional environment variable must have 'when' condition",
				Severity: "error",
			})
		}
		errors = append(errors, validateEnvironmentValueSource(
			fmt.Sprintf("spec.environment.conditional[%d]", i),
			env.EnvVar,
		)...)
	}

	// Validate health check
	if def.Spec.HealthCheck != nil {
		if len(def.Spec.HealthCheck.Test) == 0 {
			errors = append(errors, ValidationError{
				Field:    "spec.healthcheck.test",
				Message:  "health check test command is required",
				Severity: "error",
			})
		}
	}

	return errors
}

func validateEnvironmentValueSource(field string, env EnvVar) []ValidationError {
	if env.ValueFrom == nil {
		return nil
	}
	var errors []ValidationError
	if env.Value != "" {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "environment variable cannot set both value and valueFrom",
			Severity: "error",
		})
	}
	if env.ValueFrom.SecretRef != "" {
		errors = append(errors, ValidationError{
			Field: field + ".valueFrom.secretRef",
			Message: "inline secret environment values are forbidden; mount a declared Compose secret " +
				"and use the application's file-backed secret option",
			Severity: "error",
		})
	}
	if env.ValueFrom.ConfigRef != "" {
		errors = append(errors, ValidationError{
			Field:    field + ".valueFrom.configRef",
			Message:  "configRef environment values are not implemented",
			Severity: "error",
		})
	}
	return errors
}

func (v *Validator) validateConditions(def *ServiceDefinition) []ValidationError {
	var errors []ValidationError

	selectors := 0
	if def.Conditions.Always {
		selectors++
	}
	if def.Conditions.RequireAddon {
		selectors++
	}
	if def.Conditions.RequireConfig != "" {
		selectors++
		if _, ok := supportedRequireConfig[def.Conditions.RequireConfig]; !ok {
			errors = append(errors, ValidationError{
				Field:    "conditions.requireConfig",
				Message:  fmt.Sprintf("unsupported config selector %q", def.Conditions.RequireConfig),
				Severity: "error",
			})
		}
	}
	if selectors != 1 {
		errors = append(errors, ValidationError{
			Field: "conditions",
			Message: "exactly one activation selector is required: always, " +
				"requireAddon, or requireConfig",
			Severity: "error",
		})
	}

	validateWhen := func(field, condition string, required, dependency bool) {
		condition = canonicalCatalogCondition(condition)
		if condition == "" {
			if required {
				errors = append(errors, ValidationError{
					Field:    field,
					Message:  "conditional field must declare a when expression",
					Severity: "error",
				})
			}
			return
		}
		supported := isSupportedCatalogCondition(condition)
		if dependency {
			supported = isSupportedDependencyCondition(condition)
		}
		if !supported {
			errors = append(errors, ValidationError{
				Field:    field,
				Message:  fmt.Sprintf("unsupported catalog condition %q", condition),
				Severity: "error",
			})
		}
	}

	for i, env := range def.Spec.Environment.Conditional {
		validateWhen(
			fmt.Sprintf("spec.environment.conditional[%d].when", i),
			env.When,
			false,
			false,
		)
	}
	for i, volume := range def.Spec.Volumes {
		validateWhen(
			fmt.Sprintf("spec.volumes[%d].when", i),
			volume.When,
			false,
			false,
		)
	}
	for i, port := range def.Spec.Ports.Conditional {
		validateWhen(
			fmt.Sprintf("spec.ports.conditional[%d].when", i),
			port.When,
			true,
			false,
		)
	}
	for i, device := range def.Spec.Container.ConditionalDevices {
		validateWhen(fmt.Sprintf("spec.container.conditional_devices[%d].when", i), device.When, true, false)
		if strings.TrimSpace(device.Device) == "" || strings.Contains(device.Device, "/dev/mem") || strings.Contains(device.Device, "/dev/kmem") {
			errors = append(errors, ValidationError{Field: fmt.Sprintf("spec.container.conditional_devices[%d].device", i), Message: "device mapping is empty or unsafe", Severity: "error"})
		}
	}
	for i, network := range def.Spec.Networking.Networks {
		validateWhen(
			fmt.Sprintf("spec.networking.networks[%d].when", i),
			network.When,
			false,
			false,
		)
	}

	seenDependencies := make(map[string]string)
	validateDependencyName := func(field, name string) {
		if !isValidServiceName(name) {
			errors = append(errors, ValidationError{
				Field:    field,
				Message:  "dependency name must be canonical lowercase alphanumeric with hyphens",
				Severity: "error",
			})
			return
		}
		if name == def.Metadata.Name {
			errors = append(errors, ValidationError{
				Field:    field,
				Message:  "service cannot depend on itself",
				Severity: "error",
			})
		}
		if previous, exists := seenDependencies[name]; exists {
			errors = append(errors, ValidationError{
				Field:    field,
				Message:  fmt.Sprintf("dependency %q is already declared at %s", name, previous),
				Severity: "error",
			})
			return
		}
		seenDependencies[name] = field
	}
	for i, dependency := range def.Spec.Dependencies.Required {
		validateDependencyName(
			fmt.Sprintf("spec.dependencies.required[%d]", i),
			dependency,
		)
	}
	for i, dependency := range def.Spec.Dependencies.Conditional {
		field := fmt.Sprintf("spec.dependencies.conditional[%d]", i)
		validateDependencyName(field+".name", dependency.Name)
		validateWhen(field+".when", dependency.When, true, true)
		if _, ok := supportedDependencyStartupConditions[dependency.Condition]; !ok {
			errors = append(errors, ValidationError{
				Field:    field + ".condition",
				Message:  fmt.Sprintf("unsupported dependency condition %q", dependency.Condition),
				Severity: "error",
			})
		}
	}

	return errors
}

// validateRouting validates routing configuration
func (v *Validator) validateRouting(def *ServiceDefinition) []ValidationError {
	var errors []ValidationError
	validApplicationAuthModes := map[ApplicationAuthMode]bool{
		ApplicationAuthNone:                true,
		ApplicationAuthIdentityProvider:    true,
		ApplicationAuthSDBXManagedForms:    true,
		ApplicationAuthSDBXManagedPassword: true,
		ApplicationAuthSDBXManagedAPIKey:   true,
		ApplicationAuthServiceManaged:      true,
		ApplicationAuthUpstreamDefault:     true,
	}
	if !validApplicationAuthModes[def.ApplicationAuth.Mode] {
		errors = append(errors, ValidationError{
			Field:    "applicationAuth.mode",
			Message:  "must explicitly identify the native application credential owner",
			Severity: "error",
		})
	}

	if !def.Routing.Enabled {
		return errors
	}

	if def.Routing.Port <= 0 || def.Routing.Port > 65535 {
		errors = append(errors, ValidationError{
			Field:    "routing.port",
			Message:  "port must be between 1 and 65535",
			Severity: "error",
		})
	}

	if def.Routing.Subdomain != "" && !isValidSubdomain(def.Routing.Subdomain) {
		errors = append(errors, ValidationError{
			Field:    "routing.subdomain",
			Message:  "subdomain must be lowercase alphanumeric with hyphens",
			Severity: "error",
		})
	}

	if def.Routing.Path != "" && !isValidRoutePath(def.Routing.Path) {
		errors = append(errors, ValidationError{
			Field:    "routing.path",
			Message:  "path must be a clean absolute URL path",
			Severity: "error",
		})
	}

	validAuthModes := map[AuthMode]bool{
		AuthModeAdminOnly: true,
		AuthModeProtected: true,
		AuthModeNative:    true,
		AuthModePublic:    true,
	}
	if !validAuthModes[def.Routing.Auth.Mode] {
		errors = append(errors, ValidationError{
			Field:    "routing.auth.mode",
			Message:  "must be one of admin-only, protected, native-auth, or public",
			Severity: "error",
		})
	}

	validRouteNetworks := map[string]bool{
		NetworkApplication: true,
		NetworkDownload:    true,
		NetworkManagement:  true,
	}
	if !validRouteNetworks[def.Routing.Traefik.Network] {
		errors = append(errors, ValidationError{
			Field:    "routing.traefik.network",
			Message:  "must be one of app, download, or management",
			Severity: "error",
		})
	}

	validStrategies := map[string]bool{
		"stripPrefix": true,
		"urlBase":     true,
		"none":        true,
		"":            true,
	}
	if !validStrategies[def.Routing.PathRouting.Strategy] {
		errors = append(errors, ValidationError{
			Field:    "routing.pathRouting.strategy",
			Message:  fmt.Sprintf("invalid strategy: %s", def.Routing.PathRouting.Strategy),
			Severity: "error",
		})
	}

	return errors
}

func (v *Validator) validateNetworking(def *ServiceDefinition) []ValidationError {
	var errors []ValidationError
	validNetworks := map[string]bool{
		NetworkEdge:        true,
		NetworkApplication: true,
		NetworkDownload:    true,
		NetworkManagement:  true,
	}
	declared := make(map[string]bool, len(def.Spec.Networking.Networks))
	for index, network := range def.Spec.Networking.Networks {
		if !validNetworks[network.Name] {
			errors = append(errors, ValidationError{
				Field:    fmt.Sprintf("spec.networking.networks[%d].name", index),
				Message:  "must be one of edge, app, download, or management",
				Severity: "error",
			})
			continue
		}
		if declared[network.Name] {
			errors = append(errors, ValidationError{
				Field:    fmt.Sprintf("spec.networking.networks[%d].name", index),
				Message:  fmt.Sprintf("network %s is declared more than once", network.Name),
				Severity: "error",
			})
		}
		declared[network.Name] = true
	}
	if len(declared) == 0 && def.Spec.Networking.Mode != "host" {
		errors = append(errors, ValidationError{
			Field:    "spec.networking.networks",
			Message:  "at least one trust-boundary network is required",
			Severity: "error",
		})
	}
	if declared[NetworkEdge] &&
		def.Metadata.Name != "traefik" &&
		def.Metadata.Name != "cloudflared" {
		errors = append(errors, ValidationError{
			Field:    "spec.networking.networks",
			Message:  "edge network membership is reserved for Traefik and Cloudflared",
			Severity: "error",
		})
	}
	if def.Routing.Enabled &&
		def.Routing.Traefik.Network != "" &&
		!declared[def.Routing.Traefik.Network] {
		errors = append(errors, ValidationError{
			Field:    "routing.traefik.network",
			Message:  "must also be declared in spec.networking.networks",
			Severity: "error",
		})
	}
	return errors
}

// validateSecurity validates security-related settings
func (v *Validator) validateSecurity(def *ServiceDefinition) []ValidationError {
	var errors []ValidationError

	// Check for privileged mode
	if def.Spec.Container.Privileged {
		errors = append(errors, ValidationError{
			Field:    "spec.container.privileged",
			Message:  "privileged mode grants nearly unrestricted host access",
			Severity: "warning",
		})
	}

	// Check for dangerous capabilities
	for _, cap := range def.Spec.Container.Capabilities.Add {
		if v.dangerousCaps[cap] {
			errors = append(errors, ValidationError{
				Field:    "spec.container.capabilities.add",
				Message:  fmt.Sprintf("dangerous capability %s requires explicit approval", cap),
				Severity: "warning",
			})
		}
	}

	// Check for host network mode
	if def.Spec.Networking.Mode == "host" {
		errors = append(errors, ValidationError{
			Field:    "spec.networking.mode",
			Message:  "host network mode bypasses network isolation",
			Severity: "warning",
		})
	}

	// Check image source
	registry := def.Spec.Image.Registry
	if registry == "" {
		registry = "docker.io"
	}
	if _, err := imageReference(def.Spec.Image.Repository, def.Spec.Image.Tag); err != nil {
		errors = append(errors, ValidationError{
			Field:    "spec.image",
			Message:  err.Error(),
			Severity: "error",
		})
	} else if actualRegistry := repositoryRegistry(def.Spec.Image.Repository); actualRegistry != registry {
		errors = append(errors, ValidationError{
			Field: "spec.image.registry",
			Message: fmt.Sprintf(
				"declared registry %s does not match repository registry %s",
				registry,
				actualRegistry,
			),
			Severity: "error",
		})
	}
	if !v.allowedRegistries[registry] {
		errors = append(errors, ValidationError{
			Field:    "spec.image.registry",
			Message:  fmt.Sprintf("registry %s is not in allowed list", registry),
			Severity: "warning",
		})
	}

	// Check for potentially dangerous devices
	for _, device := range def.Spec.Container.Devices {
		if strings.Contains(device, "/dev/mem") || strings.Contains(device, "/dev/kmem") {
			errors = append(errors, ValidationError{
				Field:    "spec.container.devices",
				Message:  fmt.Sprintf("dangerous device mapping: %s", device),
				Severity: "error",
			})
		}
	}

	for i, vol := range def.Spec.Volumes {
		if isDockerSocketPath(vol.HostPath) || isDockerSocketPath(vol.ContainerPath) {
			errors = append(errors, ValidationError{
				Field:    fmt.Sprintf("spec.volumes[%d]", i),
				Message:  "Docker socket mounts are not supported",
				Severity: "error",
			})
		}
	}

	return errors
}

func isDockerSocketPath(path string) bool {
	normalized := strings.Trim(path, `"'`)
	return normalized == "/var/run/docker.sock"
}

// RequiredCatalogPermissions derives the host-sensitive capabilities used by a
// definition. Catalog authors must declare this exact set in permissions.
func RequiredCatalogPermissions(def *ServiceDefinition) []string {
	required := make(map[string]struct{})
	add := func(permission string) {
		if permission != "" {
			required[permission] = struct{}{}
		}
	}

	if def.Spec.Container.Privileged {
		add(PermissionPrivileged)
	}
	if def.Spec.Networking.Mode == "host" ||
		strings.Contains(def.Spec.Networking.ModeTemplate, "host") {
		add(PermissionHostNetwork)
	}
	for _, capability := range def.Spec.Container.Capabilities.Add {
		add("capability:" + strings.ToUpper(capability))
	}
	if len(def.Spec.Container.Devices) > 0 || len(def.Spec.Container.ConditionalDevices) > 0 {
		add(PermissionDevice)
	}

	for _, volume := range def.Spec.Volumes {
		if volume.Chown {
			add(PermissionHostChown)
		}
		add(requiredCatalogPathPermission(volume.HostPath))
	}
	for _, envFile := range def.Spec.Environment.EnvFile {
		add(requiredCatalogPathPermission(envFile))
	}
	if len(def.Spec.Ports.Static) > 0 || len(def.Spec.Ports.Conditional) > 0 {
		add(PermissionHostPort)
	}
	if def.Routing.Enabled {
		switch def.Routing.Auth.Mode {
		case AuthModeAdminOnly, AuthModeProtected, AuthModeNative, AuthModePublic:
			add(PermissionRoute + ":" + string(def.Routing.Auth.Mode))
		}
	}

	if def.Spec.Networking.Mode != "host" &&
		!strings.HasPrefix(def.Spec.Networking.Mode, "service:") {
		for _, network := range def.Spec.Networking.Networks {
			add("network:" + network.Name)
		}
	}
	for _, value := range []string{
		def.Spec.Networking.Mode,
		def.Spec.Networking.ModeTemplate,
	} {
		for _, match := range serviceNetworkReferencePattern.FindAllStringSubmatch(value, -1) {
			add("service-network:" + match[1])
		}
	}

	for _, env := range def.Spec.Environment.Static {
		if env.ValueFrom != nil && env.ValueFrom.SecretRef != "" {
			add("secret:" + env.ValueFrom.SecretRef)
		}
	}
	for _, env := range def.Spec.Environment.Conditional {
		if env.ValueFrom != nil && env.ValueFrom.SecretRef != "" {
			add("secret:" + env.ValueFrom.SecretRef)
		}
	}
	for _, secret := range def.Secrets {
		add("secret:" + secret.Name)
	}

	permissions := make([]string, 0, len(required))
	for permission := range required {
		permissions = append(permissions, permission)
	}
	sort.Strings(permissions)
	return permissions
}

func requiredCatalogPathPermission(value string) string {
	switch {
	case strings.Contains(value, ".Config.SecretsPath"):
		return PermissionSecretsPath
	case strings.Contains(value, ".Config.ProjectDir"):
		return PermissionProjectPath
	case strings.Contains(value, ".Config.DownloadsPath"):
		return PermissionDownloads
	case strings.Contains(value, ".Config.MediaPath"):
		return PermissionMediaPath
	case strings.Contains(value, ".Config.ConfigPath"):
		return PermissionConfigPath
	case strings.Contains(value, ".Config.DataPath"):
		return PermissionDataPath
	case strings.HasPrefix(strings.Trim(value, `"'`), "/") &&
		!isDockerSocketPath(value):
		return PermissionHostMount
	case strings.TrimSpace(value) != "":
		return PermissionProjectPath
	default:
		return ""
	}
}

func (v *Validator) validatePermissions(def *ServiceDefinition) []ValidationError {
	var errors []ValidationError
	required := RequiredCatalogPermissions(def)
	requiredSet := make(map[string]bool, len(required))
	for _, permission := range required {
		requiredSet[permission] = true
	}

	declared := make(map[string]bool, len(def.Permissions))
	for i, permission := range def.Permissions {
		field := fmt.Sprintf("permissions[%d]", i)
		if !isValidCatalogPermission(permission) {
			errors = append(errors, ValidationError{
				Field:    field,
				Message:  fmt.Sprintf("unknown catalog permission %q", permission),
				Severity: "error",
			})
			continue
		}
		if declared[permission] {
			errors = append(errors, ValidationError{
				Field:    field,
				Message:  fmt.Sprintf("duplicate catalog permission %q", permission),
				Severity: "error",
			})
			continue
		}
		declared[permission] = true
		if permission == "service-override:"+def.Metadata.Name {
			// Whether this contextual permission is required depends on source
			// selection. Registry validates that boundary against the embedded
			// catalog; the definition validator still rejects other targets.
			continue
		}
		if !requiredSet[permission] {
			errors = append(errors, ValidationError{
				Field:    field,
				Message:  fmt.Sprintf("unused catalog permission %q", permission),
				Severity: "error",
			})
		}
	}

	for _, permission := range required {
		if !declared[permission] {
			errors = append(errors, ValidationError{
				Field:    "permissions",
				Message:  fmt.Sprintf("required catalog permission %q is not declared", permission),
				Severity: "error",
			})
		}
	}

	return errors
}

func isValidCatalogPermission(permission string) bool {
	switch permission {
	case PermissionPrivileged,
		PermissionHostNetwork,
		PermissionDevice,
		PermissionHostChown,
		PermissionHostMount,
		PermissionConfigPath,
		PermissionDataPath,
		PermissionDownloads,
		PermissionHostPort,
		PermissionMediaPath,
		PermissionProjectPath,
		PermissionSecretsPath:
		return true
	}

	if strings.HasPrefix(permission, "capability:") {
		return capabilityPermissionPattern.MatchString(permission)
	}
	if strings.HasPrefix(permission, "secret:") {
		return secretPermissionPattern.MatchString(permission)
	}
	if strings.HasPrefix(permission, "network:") {
		return networkPermissionPattern.MatchString(permission)
	}
	if strings.HasPrefix(permission, "service-network:") {
		return serviceNetworkPermissionPattern.MatchString(permission)
	}
	if strings.HasPrefix(permission, "service-override:") {
		return serviceOverridePermissionPattern.MatchString(permission)
	}
	if strings.HasPrefix(permission, PermissionRoute+":") {
		return routePermissionPattern.MatchString(permission)
	}
	return false
}

func (v *Validator) validateCatalogTemplates(def *ServiceDefinition) []ValidationError {
	allowedConfigFields := map[string]bool{
		"Domain":        true,
		"Timezone":      true,
		"ConfigPath":    true,
		"DataPath":      true,
		"DownloadsPath": true,
		"MediaPath":     true,
		"SecretsPath":   true,
		"ProjectDir":    true,
		"PUID":          true,
		"PGID":          true,
		"Umask":         true,
		"VPNEnabled":    true,
		"VPNProvider":   true,
		"VPNCountry":    true,
		"TorrentPort":   true,
		"Expose":        true,
		"Routing":       true,
		"Plex":          true,
	}
	templatableFields := map[string]bool{
		"spec.container.name_template":              true,
		"spec.container.command":                    true,
		"spec.container.user":                       true,
		"spec.container.working_dir":                true,
		"spec.container.conditional_devices.device": true,
		"spec.container.conditional_devices.when":   true,
		"spec.environment.static.value":             true,
		"spec.environment.conditional.value":        true,
		"spec.environment.conditional.when":         true,
		"spec.environment.envFile":                  true,
		"spec.volumes.hostPath":                     true,
		"spec.volumes.containerPath":                true,
		"spec.volumes.when":                         true,
		"spec.ports.static":                         true,
		"spec.ports.conditional.port":               true,
		"spec.ports.conditional.when":               true,
		"spec.networking.modeTemplate":              true,
		"spec.networking.networks.when":             true,
		"spec.dependencies.conditional.when":        true,
	}

	var errors []ValidationError
	seen := make(map[string]bool)
	for _, candidate := range collectCatalogStringFields(reflect.ValueOf(def), "") {
		value := candidate.Value
		if !strings.Contains(value, "{{") {
			continue
		}
		if !templatableFields[candidate.Field] {
			key := "unsupported:" + candidate.Field
			if !seen[key] {
				seen[key] = true
				errors = append(errors, ValidationError{
					Field: "templates",
					Message: fmt.Sprintf(
						"catalog templates are not supported in %s",
						candidate.Field,
					),
					Severity: "error",
				})
			}
			continue
		}
		if !seen["syntax:"+value] {
			seen["syntax:"+value] = true
			if _, err := template.New("catalog").
				Funcs(template.FuncMap{
					"default": func(defaultValue, value interface{}) interface{} {
						if value == nil || value == "" {
							return defaultValue
						}
						return value
					},
					"lower":   strings.ToLower,
					"upper":   strings.ToUpper,
					"replace": strings.ReplaceAll,
				}).
				Parse(value); err != nil {
				errors = append(errors, ValidationError{
					Field:    "templates",
					Message:  fmt.Sprintf("catalog template syntax is invalid: %v", err),
					Severity: "error",
				})
			}
		}
		if catalogSecretsReference.MatchString(value) && !seen["Secrets"] {
			seen["Secrets"] = true
			errors = append(errors, ValidationError{
				Field:    "templates",
				Message:  "catalog templates cannot access secret values directly; declare and mount a file-backed secret",
				Severity: "error",
			})
		}
		for _, match := range catalogRootReference.FindAllStringSubmatch(value, -1) {
			field := match[1]
			if field == "Config" || field == "Name" || seen["root."+field] {
				continue
			}
			seen["root."+field] = true
			errors = append(errors, ValidationError{
				Field:    "templates",
				Message:  fmt.Sprintf("catalog template access to .%s is not allowed", field),
				Severity: "error",
			})
		}
		for _, match := range catalogConfigReference.FindAllStringSubmatch(value, -1) {
			field := match[1]
			if allowedConfigFields[field] || seen["Config."+field] {
				continue
			}
			seen["Config."+field] = true
			errors = append(errors, ValidationError{
				Field:    "templates",
				Message:  fmt.Sprintf("catalog template access to .Config.%s is not allowed", field),
				Severity: "error",
			})
		}
	}
	return errors
}

type catalogStringField struct {
	Field string
	Value string
}

func collectCatalogStringFields(
	value reflect.Value,
	fieldPath string,
) []catalogStringField {
	if !value.IsValid() {
		return nil
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		return collectCatalogStringFields(value.Elem(), fieldPath)
	}

	switch value.Kind() {
	case reflect.String:
		return []catalogStringField{{
			Field: fieldPath,
			Value: value.String(),
		}}
	case reflect.Struct:
		var values []catalogStringField
		valueType := value.Type()
		for i := 0; i < value.NumField(); i++ {
			structField := valueType.Field(i)
			tagParts := strings.Split(structField.Tag.Get("yaml"), ",")
			yamlName := tagParts[0]
			inline := false
			for _, option := range tagParts[1:] {
				if option == "inline" {
					inline = true
					break
				}
			}
			childPath := fieldPath
			if !inline {
				if yamlName == "" {
					yamlName = structField.Name
				}
				if yamlName == "-" {
					continue
				}
				childPath = joinCatalogFieldPath(fieldPath, yamlName)
			}
			values = append(
				values,
				collectCatalogStringFields(value.Field(i), childPath)...,
			)
		}
		return values
	case reflect.Slice, reflect.Array:
		var values []catalogStringField
		for i := 0; i < value.Len(); i++ {
			values = append(
				values,
				collectCatalogStringFields(value.Index(i), fieldPath)...,
			)
		}
		return values
	case reflect.Map:
		var values []catalogStringField
		iter := value.MapRange()
		for iter.Next() {
			values = append(
				values,
				collectCatalogStringFields(iter.Key(), fieldPath)...,
			)
			values = append(
				values,
				collectCatalogStringFields(iter.Value(), fieldPath)...,
			)
		}
		return values
	default:
		return nil
	}
}

func joinCatalogFieldPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}

// ValidateWithTrustLevel validates against a specific trust level
func (v *Validator) ValidateWithTrustLevel(def *ServiceDefinition, trust TrustLevel) []ValidationError {
	errors := v.Validate(def)

	for _, permission := range def.Permissions {
		if !catalogPermissionGranted(permission, trust.AllowCatalogPermissions) {
			errors = append(errors, ValidationError{
				Field:    "permissions",
				Message:  fmt.Sprintf("catalog permission %q is not granted to this source", permission),
				Severity: "error",
			})
		}
	}

	// Check registries
	allowedRegs := make(map[string]bool)
	for _, reg := range trust.AllowedRegistries {
		if reg == "*" {
			allowedRegs["*"] = true
			break
		}
		allowedRegs[reg] = true
	}

	if !allowedRegs["*"] {
		registry := def.Spec.Image.Registry
		if registry == "" {
			registry = "docker.io"
		}
		if !allowedRegs[registry] {
			errors = append(errors, ValidationError{
				Field:    "spec.image.registry",
				Message:  fmt.Sprintf("registry %s not allowed by trust level", registry),
				Severity: "error",
			})
		}
	}

	return errors
}

func catalogPermissionGranted(permission string, grants []string) bool {
	for _, grant := range grants {
		if grant == "*" || grant == permission {
			return true
		}
		if strings.HasSuffix(grant, ":*") &&
			strings.HasPrefix(permission, strings.TrimSuffix(grant, "*")) {
			return true
		}
	}
	return false
}

// HasErrors returns true if there are any error-severity validation errors
func HasErrors(errors []ValidationError) bool {
	for _, e := range errors {
		if e.Severity == "error" {
			return true
		}
	}
	return false
}

// FilterByServerity filters validation errors by severity
func FilterBySeverity(errors []ValidationError, severity string) []ValidationError {
	var filtered []ValidationError
	for _, e := range errors {
		if e.Severity == severity {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// isValidServiceName checks if a name is a valid service name
func isValidServiceName(name string) bool {
	// Must be lowercase, alphanumeric, with hyphens
	matched, _ := regexp.MatchString(`^[a-z][a-z0-9-]*[a-z0-9]$|^[a-z]$`, name)
	return matched
}

func validateServiceLookupName(name string) error {
	if !isValidServiceName(name) {
		return fmt.Errorf(
			"invalid service name %q: use lowercase letters, numbers, and hyphens",
			name,
		)
	}
	return nil
}

// isValidSubdomain checks if a subdomain is valid
func isValidSubdomain(subdomain string) bool {
	matched, _ := regexp.MatchString(`^[a-z][a-z0-9-]*[a-z0-9]$|^[a-z]$`, subdomain)
	return matched
}

func isValidRoutePath(value string) bool {
	if !routePathRegex.MatchString(value) {
		return false
	}
	for _, segment := range strings.Split(strings.TrimPrefix(value, "/"), "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// isValidCategory checks if a category is valid
func isValidCategory(category ServiceCategory) bool {
	valid := map[ServiceCategory]bool{
		CategoryMedia:      true,
		CategoryDownloads:  true,
		CategoryManagement: true,
		CategoryUtility:    true,
		CategoryNetworking: true,
		CategoryAuth:       true,
	}
	return valid[category]
}
