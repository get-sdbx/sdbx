package registry

import (
	"strings"
	"testing"
)

func TestValidatorRequiresExplicitRouteAuthMode(t *testing.T) {
	def := minimalServiceDefinition()
	def.Routing = RoutingConfig{
		Enabled:   true,
		Port:      8080,
		Subdomain: "test",
		Path:      "/test",
		Traefik:   TraefikConfig{Network: NetworkApplication},
	}

	errors := NewValidator().Validate(def)
	if !hasValidation(errors, "error", "must be one of admin-only") {
		t.Fatalf("expected missing route classification error, got %#v", errors)
	}
}

func TestValidatorRequiresExplicitApplicationAuthMode(t *testing.T) {
	def := minimalServiceDefinition()
	def.ApplicationAuth = ApplicationAuthConfig{}

	errors := NewValidator().Validate(def)
	if !hasValidationField(errors, "error", "applicationAuth.mode") {
		t.Fatalf("missing application auth ownership was accepted: %#v", errors)
	}
}

func TestValidatorAcceptsEveryApplicationAuthMode(t *testing.T) {
	for _, mode := range []ApplicationAuthMode{
		ApplicationAuthNone,
		ApplicationAuthIdentityProvider,
		ApplicationAuthSDBXManagedForms,
		ApplicationAuthSDBXManagedPassword,
		ApplicationAuthSDBXManagedAPIKey,
		ApplicationAuthServiceManaged,
		ApplicationAuthUpstreamDefault,
	} {
		t.Run(string(mode), func(t *testing.T) {
			def := minimalServiceDefinition()
			def.ApplicationAuth.Mode = mode
			if errors := NewValidator().Validate(def); hasSeverity(errors, "error") {
				t.Fatalf("valid application auth mode rejected: %#v", errors)
			}
		})
	}
}

func TestValidatorAcceptsEveryRouteAuthMode(t *testing.T) {
	for _, mode := range []AuthMode{
		AuthModeAdminOnly,
		AuthModeProtected,
		AuthModeNative,
		AuthModePublic,
	} {
		t.Run(string(mode), func(t *testing.T) {
			def := minimalServiceDefinition()
			def.Routing = RoutingConfig{
				Enabled:   true,
				Port:      8080,
				Subdomain: "test",
				Path:      "/test",
				Auth:      AuthConfig{Mode: mode},
				Traefik:   TraefikConfig{Network: NetworkApplication},
			}
			def.Permissions = append(def.Permissions, PermissionRoute+":"+string(mode))
			if errors := NewValidator().Validate(def); hasSeverity(errors, "error") {
				t.Fatalf("valid auth mode rejected: %#v", errors)
			}
		})
	}
}

func TestValidatorRejectsUnsafeCatalogRoutePath(t *testing.T) {
	for _, routePath := range []string{
		"relative",
		"/shows`) || Host(`attacker.example",
		"/shows//admin",
		"/shows/../admin",
		"/shows?admin=true",
	} {
		t.Run(routePath, func(t *testing.T) {
			def := minimalServiceDefinition()
			def.Routing = RoutingConfig{
				Enabled:   true,
				Port:      8080,
				Subdomain: "test",
				Path:      routePath,
				Auth:      AuthConfig{Mode: AuthModeAdminOnly},
				Traefik:   TraefikConfig{Network: NetworkApplication},
			}
			errors := NewValidator().Validate(def)
			if !hasValidation(errors, "error", "clean absolute URL path") {
				t.Fatalf("unsafe route path %q was accepted: %#v", routePath, errors)
			}
		})
	}
}

func TestRoutedCatalogRequiresExactAuthPermissionAndGrant(t *testing.T) {
	def := minimalServiceDefinition()
	def.Routing = RoutingConfig{
		Enabled:   true,
		Port:      8080,
		Subdomain: "test",
		Path:      "/test",
		Auth:      AuthConfig{Mode: AuthModePublic},
		Traefik:   TraefikConfig{Network: NetworkApplication},
	}

	errors := NewValidator().Validate(def)
	if !hasValidation(errors, "error", `required catalog permission "route:public"`) {
		t.Fatalf("missing route permission was accepted: %#v", errors)
	}

	def.Permissions = append(def.Permissions, "route:public")
	errors = NewValidator().ValidateWithTrustLevel(def, TrustLevel{
		AllowedRegistries:       []string{"docker.io"},
		AllowCatalogPermissions: []string{"network:app"},
	})
	if !hasValidation(errors, "error", `catalog permission "route:public" is not granted`) {
		t.Fatalf("ungranted public route was accepted: %#v", errors)
	}

	errors = NewValidator().ValidateWithTrustLevel(def, TrustLevel{
		AllowedRegistries:       []string{"docker.io"},
		AllowCatalogPermissions: []string{"network:app", "route:public"},
	})
	if hasSeverity(errors, "error") {
		t.Fatalf("explicitly granted public route rejected: %#v", errors)
	}
}

func TestLoaderRejectsCatalogControlledTraefikPolicy(t *testing.T) {
	for _, field := range []string{
		"priority: 999999",
		"middlewares: [attacker-auth]",
		"customLabels:\n      traefik.http.routers.victim.priority: \"999999\"",
	} {
		t.Run(strings.SplitN(field, ":", 2)[0], func(t *testing.T) {
			document := `apiVersion: sdbx.one/v1
kind: Service
applicationAuth:
  mode: none
metadata:
  name: route-policy
  version: 1.0.0
  category: utility
  description: route policy test
spec:
  image:
    repository: example/service
    tag: latest
  container:
    name_template: "sdbx-{{ .Name }}"
  networking:
    networks:
      - name: app
permissions:
  - network:app
routing:
  enabled: true
  port: 8080
  subdomain: route-policy
  path: /route-policy
  auth:
    mode: protected
  traefik:
    network: app
    ` + field + `
`
			_, err := NewLoader().ParseServiceDefinition([]byte(document))
			if err == nil || !strings.Contains(err.Error(), "field") {
				t.Fatalf("catalog Traefik policy %q was accepted: %v", field, err)
			}
		})
	}
}

func TestValidatorRequiresExplicitTrustBoundaryNetwork(t *testing.T) {
	def := minimalServiceDefinition()
	def.Spec.Networking.Networks = nil

	errors := NewValidator().Validate(def)
	if !hasValidation(errors, "error", "at least one trust-boundary network") {
		t.Fatalf("expected missing network error, got %#v", errors)
	}
}

func TestValidatorRejectsInvalidRuntimeLimits(t *testing.T) {
	def := minimalServiceDefinition()
	def.Spec.Container.PidsLimit = -1
	def.Spec.Container.StopGrace = "eventually"
	def.Spec.Container.Tmpfs = []string{"tmp", "/tmp/../escape", "/run", "/run:size=1m"}

	errors := NewValidator().Validate(def)
	for _, message := range []string{
		"process limit must be positive",
		"positive Go duration",
		"clean absolute container path",
		"declared more than once",
	} {
		if !hasValidation(errors, "error", message) {
			t.Fatalf("validation errors = %#v, want %q", errors, message)
		}
	}
}

func TestValidatorRequiresOneSupportedActivationSelector(t *testing.T) {
	testCases := []struct {
		name       string
		conditions Conditions
		want       string
	}{
		{
			name: "missing",
			want: "exactly one activation selector",
		},
		{
			name: "ambiguous",
			conditions: Conditions{
				Always:       true,
				RequireAddon: true,
			},
			want: "exactly one activation selector",
		},
		{
			name: "unknown-config",
			conditions: Conditions{
				RequireConfig: "enable_everything",
			},
			want: `unsupported config selector "enable_everything"`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			def := minimalServiceDefinition()
			def.Conditions = testCase.conditions
			errors := NewValidator().Validate(def)
			if !hasValidation(errors, "error", testCase.want) {
				t.Fatalf("validation errors = %#v, want %q", errors, testCase.want)
			}
		})
	}
}

func TestValidatorRejectsUnsupportedCatalogConditions(t *testing.T) {
	const unsupported = "{{ .Config.EnableEverything }}"
	testCases := []struct {
		name  string
		apply func(*ServiceDefinition)
		field string
	}{
		{
			name: "environment",
			apply: func(def *ServiceDefinition) {
				def.Spec.Environment.Conditional = []ConditionalEnvVar{{
					EnvVar: EnvVar{Name: "MODE", Value: "unsafe"},
					When:   unsupported,
				}}
			},
			field: "spec.environment.conditional[0].when",
		},
		{
			name: "volume",
			apply: func(def *ServiceDefinition) {
				def.Spec.Volumes = []VolumeMount{{
					HostPath:      "./state",
					ContainerPath: "/state",
					When:          unsupported,
				}}
			},
			field: "spec.volumes[0].when",
		},
		{
			name: "port",
			apply: func(def *ServiceDefinition) {
				def.Spec.Ports.Conditional = []ConditionalPort{{
					Port: "127.0.0.1:8080:8080",
					When: unsupported,
				}}
				def.Permissions = append(def.Permissions, PermissionHostPort)
			},
			field: "spec.ports.conditional[0].when",
		},
		{
			name: "network",
			apply: func(def *ServiceDefinition) {
				def.Spec.Networking.Networks[0].When = unsupported
			},
			field: "spec.networking.networks[0].when",
		},
		{
			name: "dependency",
			apply: func(def *ServiceDefinition) {
				def.Spec.Dependencies.Conditional = []ConditionalDependency{{
					Name: "dependency",
					When: unsupported,
				}}
			},
			field: "spec.dependencies.conditional[0].when",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			def := minimalServiceDefinition()
			testCase.apply(def)
			errors := NewValidator().Validate(def)
			if !hasValidation(errors, "error", "unsupported catalog condition") ||
				!hasValidationField(errors, "error", testCase.field) {
				t.Fatalf(
					"validation errors = %#v, want unsupported condition at %s",
					errors,
					testCase.field,
				)
			}
		})
	}
}

func TestValidatorAcceptsDocumentedCatalogConditions(t *testing.T) {
	for condition := range supportedCatalogConditions {
		t.Run(condition, func(t *testing.T) {
			def := minimalServiceDefinition()
			def.Spec.Environment.Conditional = []ConditionalEnvVar{{
				EnvVar: EnvVar{Name: "MODE", Value: "safe"},
				When:   condition,
			}}
			errors := NewValidator().Validate(def)
			if hasValidation(errors, "error", "unsupported catalog condition") {
				t.Fatalf("documented condition %q was rejected: %#v", condition, errors)
			}
		})
	}
}

func TestValidatorRejectsInvalidDependencyPolicy(t *testing.T) {
	testCases := []struct {
		name       string
		dependency DependencySpec
		want       string
	}{
		{
			name: "invalid-name",
			dependency: DependencySpec{
				Required: []string{"../escape"},
			},
			want: "dependency name must be canonical",
		},
		{
			name: "self-dependency",
			dependency: DependencySpec{
				Required: []string{"test"},
			},
			want: "service cannot depend on itself",
		},
		{
			name: "duplicate",
			dependency: DependencySpec{
				Required: []string{"dependency"},
				Conditional: []ConditionalDependency{{
					Name: "dependency",
					When: conditionVPNEnabled,
				}},
			},
			want: "already declared",
		},
		{
			name: "missing-when",
			dependency: DependencySpec{
				Conditional: []ConditionalDependency{{
					Name: "dependency",
				}},
			},
			want: "must declare a when expression",
		},
		{
			name: "routing-dependent-resolution",
			dependency: DependencySpec{
				Conditional: []ConditionalDependency{{
					Name: "dependency",
					When: conditionRoutingPath,
				}},
			},
			want: "unsupported catalog condition",
		},
		{
			name: "unsupported-startup-condition",
			dependency: DependencySpec{
				Conditional: []ConditionalDependency{{
					Name:      "dependency",
					When:      conditionVPNEnabled,
					Condition: "service_magic",
				}},
			},
			want: `unsupported dependency condition "service_magic"`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			def := minimalServiceDefinition()
			def.Spec.Dependencies = testCase.dependency
			errors := NewValidator().Validate(def)
			if !hasValidation(errors, "error", testCase.want) {
				t.Fatalf("validation errors = %#v, want %q", errors, testCase.want)
			}
		})
	}
}

func TestValidatorWarnsForNetworkAdministrationCapability(t *testing.T) {
	def := minimalServiceDefinition()
	def.Spec.Container.Capabilities.Add = []string{"NET_ADMIN"}
	def.Permissions = append(def.Permissions, "capability:NET_ADMIN")

	errors := NewValidator().Validate(def)
	if !hasValidation(errors, "warning", "dangerous capability NET_ADMIN") {
		t.Fatalf("expected NET_ADMIN security warning, got %#v", errors)
	}
}

func TestValidatorReservesEdgeAndRequiresSharedTraefikNetwork(t *testing.T) {
	edge := minimalServiceDefinition()
	edge.Spec.Networking.Networks = []NetworkRef{{Name: NetworkEdge}}
	errors := NewValidator().Validate(edge)
	if !hasValidation(errors, "error", "reserved for Traefik and Cloudflared") {
		t.Fatalf("expected reserved edge error, got %#v", errors)
	}

	mismatch := minimalServiceDefinition()
	mismatch.Routing = RoutingConfig{
		Enabled:   true,
		Port:      8080,
		Subdomain: "test",
		Path:      "/test",
		Auth:      AuthConfig{Mode: AuthModeAdminOnly},
		Traefik:   TraefikConfig{Network: NetworkManagement},
	}
	errors = NewValidator().Validate(mismatch)
	if !hasValidation(errors, "error", "must also be declared") {
		t.Fatalf("expected Traefik network mismatch error, got %#v", errors)
	}
}

func TestValidatorRejectsRemovedDockerAPINetwork(t *testing.T) {
	def := minimalServiceDefinition()
	def.Spec.Networking.Networks = []NetworkRef{{Name: "docker-api"}}

	errors := NewValidator().Validate(def)
	if !hasValidation(errors, "error", "must be one of edge, app, download, or management") {
		t.Fatalf("expected removed docker-api network error, got %#v", errors)
	}
}

func TestValidatorRejectsDockerSocketMount(t *testing.T) {
	def := dockerSocketServiceDefinition(true)

	errors := NewValidator().Validate(def)
	if !hasValidation(errors, "error", "Docker socket mounts are not supported") {
		t.Fatalf("expected Docker socket rejection, got %#v", errors)
	}
}

func TestValidatorRejectsUnusedAndUnknownPermissions(t *testing.T) {
	def := minimalServiceDefinition()
	def.Permissions = []string{PermissionHostNetwork, "host-root"}

	errors := NewValidator().Validate(def)

	if !hasValidation(errors, "error", "unused catalog permission") {
		t.Fatalf("expected unused permission error, got %#v", errors)
	}
	if !hasValidation(errors, "error", "unknown catalog permission") {
		t.Fatalf("expected unknown permission error, got %#v", errors)
	}
}

func TestValidatorRejectsSecretAndPrivateConfigTemplateAccess(t *testing.T) {
	def := minimalServiceDefinition()
	def.Spec.Environment.Static = []EnvVar{
		{Name: "LEAK_ALL", Value: `{{ printf "%v" .Secrets }}`},
		{Name: "LEAK_HASH", Value: "{{ .Config.AdminPasswordHash }}"},
	}

	errors := NewValidator().Validate(def)

	if !hasValidation(errors, "error", "cannot access secret values directly") {
		t.Fatalf("expected direct secret-access rejection, got %#v", errors)
	}
	if !hasValidation(errors, "error", ".Config.AdminPasswordHash is not allowed") {
		t.Fatalf("expected private config-access rejection, got %#v", errors)
	}
}

func TestValidatorAcceptsCatalogTemplateAllowlist(t *testing.T) {
	def := minimalServiceDefinition()
	def.Spec.Environment.Static = []EnvVar{
		{Name: "DOMAIN", Value: "{{ .Config.Domain }}"},
		{Name: "MODE", Value: "{{ .Config.Expose.Mode }}"},
		{Name: "SERVICE", Value: "{{ .Name }}"},
	}

	errors := NewValidator().Validate(def)
	if hasSeverity(errors, "error") {
		t.Fatalf("allowlisted catalog template rejected: %#v", errors)
	}
}

func TestValidatorRejectsMalformedAndUnknownRootCatalogTemplates(t *testing.T) {
	def := minimalServiceDefinition()
	def.Spec.Environment.Static = []EnvVar{
		{Name: "MALFORMED", Value: "{{ .Config.Domain "},
		{Name: "UNKNOWN_ROOT", Value: "{{ .OperatorToken }}"},
	}

	errors := NewValidator().Validate(def)
	if !hasValidation(errors, "error", "catalog template syntax is invalid") {
		t.Fatalf("expected malformed template rejection, got %#v", errors)
	}
	if !hasValidation(errors, "error", ".OperatorToken is not allowed") {
		t.Fatalf("expected unknown root rejection, got %#v", errors)
	}
}

func TestValidatorRejectsTemplatesOutsideRenderedCatalogFields(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*ServiceDefinition)
		wantField string
	}{
		{
			name: "metadata",
			mutate: func(def *ServiceDefinition) {
				def.Metadata.Description = "{{ .Config.Domain }}"
			},
			wantField: "metadata.description",
		},
		{
			name: "image",
			mutate: func(def *ServiceDefinition) {
				def.Spec.Image.Tag = "{{ .Config.Domain }}"
			},
			wantField: "spec.image.tag",
		},
		{
			name: "environment name",
			mutate: func(def *ServiceDefinition) {
				def.Spec.Environment.Static = []EnvVar{{
					Name:  "{{ .Config.Domain }}",
					Value: "value",
				}}
			},
			wantField: "spec.environment.static.name",
		},
		{
			name: "sysctl",
			mutate: func(def *ServiceDefinition) {
				def.Spec.Container.Sysctls = map[string]string{
					"net.ipv4.ip_unprivileged_port_start": "{{ .Config.PUID }}",
				}
			},
			wantField: "spec.container.sysctls",
		},
		{
			name: "tmpfs",
			mutate: func(def *ServiceDefinition) {
				def.Spec.Container.Tmpfs = []string{"/tmp:size={{ .Config.PUID }}"}
			},
			wantField: "spec.container.tmpfs",
		},
		{
			name: "device",
			mutate: func(def *ServiceDefinition) {
				def.Spec.Container.Devices = []string{"{{ .Config.ProjectDir }}:/dev/null"}
			},
			wantField: "spec.container.devices",
		},
		{
			name: "healthcheck",
			mutate: func(def *ServiceDefinition) {
				def.Spec.HealthCheck = &HealthCheck{
					Test: []string{"CMD", "{{ .Config.Domain }}"},
				}
			},
			wantField: "spec.healthcheck.test",
		},
		{
			name: "routing",
			mutate: func(def *ServiceDefinition) {
				def.Routing.Path = "/{{ .Config.Domain }}"
			},
			wantField: "routing.path",
		},
		{
			name: "secret metadata",
			mutate: func(def *ServiceDefinition) {
				def.Secrets = []SecretDef{{
					Name:        "example",
					Type:        "manual",
					Description: "{{ .Config.Domain }}",
				}}
			},
			wantField: "secrets.description",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			def := minimalServiceDefinition()
			test.mutate(def)

			errors := NewValidator().Validate(def)
			if !hasValidation(
				errors,
				"error",
				"catalog templates are not supported in "+test.wantField,
			) {
				t.Fatalf(
					"expected unsupported template rejection for %s, got %#v",
					test.wantField,
					errors,
				)
			}
		})
	}
}

func TestValidatorRejectsUnsafeLauncherPresentation(t *testing.T) {
	tests := []struct {
		name      string
		launcher  *LauncherPresentation
		routed    bool
		wantField string
	}{
		{
			name: "disabled declaration",
			launcher: &LauncherPresentation{
				Group: "media",
			},
			routed:    true,
			wantField: "presentation.launcher.enabled",
		},
		{
			name: "unrouted service",
			launcher: &LauncherPresentation{
				Enabled: true,
				Group:   "media",
			},
			wantField: "presentation.launcher",
		},
		{
			name: "unknown group",
			launcher: &LauncherPresentation{
				Enabled: true,
				Group:   "internet",
			},
			routed:    true,
			wantField: "presentation.launcher.group",
		},
		{
			name: "remote icon",
			launcher: &LauncherPresentation{
				Enabled: true,
				Group:   "media",
				Icon:    "https://icons.example/sonarr.svg",
			},
			routed:    true,
			wantField: "presentation.launcher.icon",
		},
		{
			name: "template subtitle",
			launcher: &LauncherPresentation{
				Enabled:  true,
				Group:    "media",
				Subtitle: "{{ .Config.Domain }}",
			},
			routed:    true,
			wantField: "presentation.launcher.subtitle",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			def := minimalServiceDefinition()
			def.Presentation.Launcher = test.launcher
			def.Routing.Enabled = test.routed
			if test.routed {
				def.Routing.Port = 8080
				def.Routing.Subdomain = "example"
				def.Routing.Path = "/example"
				def.Routing.Auth.Mode = AuthModeAdminOnly
				def.Routing.Traefik.Network = NetworkApplication
				def.Spec.Networking.Networks = []NetworkRef{{Name: NetworkApplication}}
				def.Permissions = []string{
					PermissionConfigPath,
					"network:" + NetworkApplication,
					PermissionRoute + ":" + string(AuthModeAdminOnly),
				}
			}
			if !hasValidationField(NewValidator().Validate(def), "error", test.wantField) {
				t.Fatalf("expected launcher validation error for %s", test.wantField)
			}
		})
	}
}

func TestValidatorEnforcesCanonicalUnpackerrContract(t *testing.T) {
	valid := minimalServiceDefinition()
	valid.Metadata.Name = "sonarr"
	valid.Integrations.Unpackerr = &UnpackerrIntegration{
		Enabled:      true,
		URLEnvVar:    "UN_SONARR_0_URL",
		APIKeyEnvVar: "UN_SONARR_0_API_KEY",
		InternalURL:  "http://sdbx-sonarr:8989",
	}
	if errors := NewValidator().Validate(valid); hasSeverity(errors, "error") {
		t.Fatalf("canonical Unpackerr contract rejected: %#v", errors)
	}

	for _, test := range []struct {
		name  string
		field string
		value string
	}{
		{
			name:  "url env injection",
			field: "urlEnvVar",
			value: "UN_SONARR_0_URL\nATTACKER",
		},
		{
			name:  "api key env injection",
			field: "apiKeyEnvVar",
			value: "UN_ATTACKER_API_KEY",
		},
		{
			name:  "internal endpoint injection",
			field: "internalUrl",
			value: "http://attacker.invalid",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			def := *valid
			integration := *valid.Integrations.Unpackerr
			def.Integrations.Unpackerr = &integration
			switch test.field {
			case "urlEnvVar":
				integration.URLEnvVar = test.value
			case "apiKeyEnvVar":
				integration.APIKeyEnvVar = test.value
			case "internalUrl":
				integration.InternalURL = test.value
			}
			errors := NewValidator().Validate(&def)
			if !hasValidationField(
				errors,
				"error",
				"integrations.unpackerr."+test.field,
			) {
				t.Fatalf("unsafe integration accepted: %#v", errors)
			}
		})
	}

	unsupported := *valid
	unsupported.Metadata.Name = "attacker"
	if !hasValidationField(
		NewValidator().Validate(&unsupported),
		"error",
		"integrations.unpackerr",
	) {
		t.Fatal("unsupported Unpackerr integration owner was accepted")
	}
}

func TestValidatorTreatsTemplateLikeDocumentationAsPlainText(t *testing.T) {
	def := minimalServiceDefinition()
	def.Metadata.Description = "The field .Config.Internal is not a template."

	errors := NewValidator().Validate(def)
	if hasValidation(errors, "error", ".Config.Internal is not allowed") {
		t.Fatalf("plain descriptive text was treated as a template: %#v", errors)
	}
}

func TestValidatorRejectsInlineSecretEnvironment(t *testing.T) {
	def := minimalServiceDefinition()
	def.Spec.Environment.Static = []EnvVar{{
		Name:      "TOKEN",
		ValueFrom: &ValueSource{SecretRef: "service_token"},
	}}
	def.Permissions = []string{"secret:service_token"}

	errors := NewValidator().Validate(def)
	if !hasValidation(errors, "error", "inline secret environment values are forbidden") {
		t.Fatalf("expected inline secret rejection, got %#v", errors)
	}
}

func TestValidatorRejectsRepositoryRegistryMismatch(t *testing.T) {
	def := minimalServiceDefinition()
	def.Spec.Image.Repository = "ghcr.io/example/service"
	def.Spec.Image.Registry = "docker.io"

	errors := NewValidator().Validate(def)
	if !hasValidation(errors, "error", "does not match repository registry ghcr.io") {
		t.Fatalf("expected repository registry mismatch, got %#v", errors)
	}
}

func TestMaliciousCatalogFixturesAreRejected(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{
			path: "testdata/malicious/undeclared-docker-socket.yaml",
			want: "Docker socket mounts are not supported",
		},
		{
			path: "testdata/malicious/direct-secret-template.yaml",
			want: "cannot access secret values directly",
		},
		{
			path: "testdata/malicious/unrendered-healthcheck-template.yaml",
			want: "catalog templates are not supported in spec.healthcheck.test",
		},
		{
			path: "testdata/malicious/ungranted-privileged.yaml",
			want: `catalog permission "privileged" is not granted`,
		},
	}

	validator := NewValidator()
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			def, err := NewLoader().LoadServiceDefinition(test.path)
			if err != nil {
				t.Fatalf("LoadServiceDefinition failed: %v", err)
			}
			errors := validator.ValidateWithTrustLevel(def, TrustLevel{
				AllowedRegistries: []string{"docker.io"},
			})
			if !hasValidation(errors, "error", test.want) {
				t.Fatalf("fixture errors = %#v, want %q", errors, test.want)
			}
		})
	}
}

func TestRequiredCatalogPermissionsCoversHostSensitiveSurfaces(t *testing.T) {
	def := minimalServiceDefinition()
	def.Spec.Container.Privileged = true
	def.Spec.Container.Capabilities.Add = []string{"NET_ADMIN"}
	def.Spec.Container.Devices = []string{"/dev/net/tun:/dev/net/tun"}
	def.Spec.Networking.ModeTemplate =
		"{{ if .Config.VPNEnabled }}service:gluetun{{ else }}host{{ end }}"
	def.Spec.Volumes = []VolumeMount{
		{HostPath: "{{ .Config.ProjectDir }}", ContainerPath: "/project"},
		{HostPath: "{{ .Config.SecretsPath }}", ContainerPath: "/secrets"},
		{HostPath: "/srv/media", ContainerPath: "/media", Chown: true},
	}
	def.Spec.Environment.EnvFile = []string{
		"{{ .Config.ConfigPath }}/service/runtime.env",
	}
	def.Spec.Ports.Static = []string{"127.0.0.1:8080:8080"}
	def.Spec.Environment.Static = []EnvVar{{
		Name:      "TOKEN",
		ValueFrom: &ValueSource{SecretRef: "service_token"},
	}}

	got := RequiredCatalogPermissions(def)
	want := []string{
		"capability:NET_ADMIN",
		"config-path",
		"device",
		"host-chown",
		"host-mount",
		"host-network",
		"host-port",
		"network:app",
		"privileged",
		"project-path",
		"secret:service_token",
		"secrets-path",
		"service-network:gluetun",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("RequiredCatalogPermissions() = %v, want %v", got, want)
	}
}

func dockerSocketServiceDefinition(readOnly bool) *ServiceDefinition {
	def := minimalServiceDefinition()
	def.Spec.Volumes = []VolumeMount{
		{
			Name:          "docker-socket",
			HostPath:      "/var/run/docker.sock",
			ContainerPath: "/var/run/docker.sock",
			ReadOnly:      readOnly,
		},
	}
	return def
}

func minimalServiceDefinition() *ServiceDefinition {
	return &ServiceDefinition{
		APIVersion: APIVersion,
		Kind:       KindService,
		ApplicationAuth: ApplicationAuthConfig{
			Mode: ApplicationAuthNone,
		},
		Metadata: ServiceMetadata{
			Name:        "test",
			Version:     "1.0.0",
			Category:    "utility",
			Description: "Test service",
		},
		Spec: ServiceSpec{
			Image: ImageSpec{
				Repository: "alpine",
				Tag:        "latest",
			},
			Container: ContainerSpec{
				NameTemplate: "sdbx-{{ .Name }}",
			},
			Networking: NetworkSpec{
				Networks: []NetworkRef{{Name: NetworkApplication}},
			},
		},
		Permissions: []string{"network:" + NetworkApplication},
		Conditions:  Conditions{Always: true},
	}
}

func hasValidation(errors []ValidationError, severity, message string) bool {
	for _, err := range errors {
		if err.Severity == severity && strings.Contains(err.Message, message) {
			return true
		}
	}
	return false
}

func hasSeverity(errors []ValidationError, severity string) bool {
	for _, err := range errors {
		if err.Severity == severity {
			return true
		}
	}
	return false
}

func hasValidationField(errors []ValidationError, severity, field string) bool {
	for _, err := range errors {
		if err.Severity == severity && err.Field == field {
			return true
		}
	}
	return false
}
