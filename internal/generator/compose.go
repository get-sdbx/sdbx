package generator

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
	sdbxrouting "github.com/get-sdbx/sdbx/internal/routing"
)

// ComposeGenerator generates Docker Compose files from registry definitions
type ComposeGenerator struct {
	Config   *config.Config
	Registry *registry.Registry
	Lock     *registry.LockFile
}

// NewComposeGenerator creates a new compose generator
func NewComposeGenerator(cfg *config.Config, reg *registry.Registry) *ComposeGenerator {
	return NewComposeGeneratorWithLock(cfg, reg, nil)
}

// NewComposeGeneratorWithLock creates a generator that emits digest-pinned
// image references from a validated schema-v2 lock.
func NewComposeGeneratorWithLock(
	cfg *config.Config,
	reg *registry.Registry,
	lock *registry.LockFile,
) *ComposeGenerator {
	g := &ComposeGenerator{
		Config:   cfg,
		Registry: reg,
		Lock:     lock,
	}
	return g
}

// ComposeFile represents a Docker Compose file
type ComposeFile struct {
	Name     string                      `yaml:"name"`
	Services map[string]ComposeService   `yaml:"services"`
	Networks map[string]ComposeNetwork   `yaml:"networks,omitempty"`
	Secrets  map[string]ComposeSecretDef `yaml:"secrets,omitempty"`
}

// ComposeService represents a Docker Compose service
type ComposeService struct {
	Image         string                        `yaml:"image"`
	ContainerName string                        `yaml:"container_name"`
	Hostname      string                        `yaml:"hostname,omitempty"`
	Restart       string                        `yaml:"restart,omitempty"`
	User          string                        `yaml:"user,omitempty"`
	Environment   []string                      `yaml:"environment,omitempty"`
	EnvFile       []string                      `yaml:"env_file,omitempty"`
	Volumes       []string                      `yaml:"volumes,omitempty"`
	Ports         []string                      `yaml:"ports,omitempty"`
	Networks      []string                      `yaml:"networks,omitempty"`
	NetworkMode   string                        `yaml:"network_mode,omitempty"`
	DependsOn     map[string]DependsOnCondition `yaml:"depends_on,omitempty"`
	Labels        []string                      `yaml:"labels,omitempty"`
	HealthCheck   *ComposeHealthCheck           `yaml:"healthcheck,omitempty"`
	CapAdd        []string                      `yaml:"cap_add,omitempty"`
	CapDrop       []string                      `yaml:"cap_drop,omitempty"`
	Devices       []string                      `yaml:"devices,omitempty"`
	SecurityOpt   []string                      `yaml:"security_opt,omitempty"`
	ReadOnly      bool                          `yaml:"read_only,omitempty"`
	Tmpfs         []string                      `yaml:"tmpfs,omitempty"`
	PidsLimit     int                           `yaml:"pids_limit,omitempty"`
	StopGrace     string                        `yaml:"stop_grace_period,omitempty"`
	Logging       *ComposeLogging               `yaml:"logging,omitempty"`
	Secrets       []string                      `yaml:"secrets,omitempty"`
	Command       string                        `yaml:"command,omitempty"`
	ShmSize       string                        `yaml:"shm_size,omitempty"`
	Sysctls       map[string]string             `yaml:"sysctls,omitempty"`
	Init          bool                          `yaml:"init,omitempty"`
	WorkingDir    string                        `yaml:"working_dir,omitempty"`
	ExtraHosts    []string                      `yaml:"extra_hosts,omitempty"`
}

// DependsOnCondition represents a depends_on condition
type DependsOnCondition struct {
	Condition string `yaml:"condition,omitempty"`
}

// ComposeHealthCheck represents a Docker Compose health check
type ComposeHealthCheck struct {
	Test        []string `yaml:"test"`
	Interval    string   `yaml:"interval,omitempty"`
	Timeout     string   `yaml:"timeout,omitempty"`
	Retries     int      `yaml:"retries,omitempty"`
	StartPeriod string   `yaml:"start_period,omitempty"`
}

// ComposeLogging bounds local disk consumption while preserving docker logs.
type ComposeLogging struct {
	Driver  string            `yaml:"driver"`
	Options map[string]string `yaml:"options,omitempty"`
}

// ComposeNetwork represents a Docker Compose network
type ComposeNetwork struct {
	Name     string `yaml:"name,omitempty"`
	Internal bool   `yaml:"internal,omitempty"`
}

// ComposeSecretDef represents a Docker Compose secret definition
type ComposeSecretDef struct {
	File string `yaml:"file"`
}

func catalogTemplateFuncMap() template.FuncMap {
	return template.FuncMap{
		"eq":        func(a, b interface{}) bool { return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b) },
		"ne":        func(a, b interface{}) bool { return fmt.Sprintf("%v", a) != fmt.Sprintf("%v", b) },
		"not":       func(b bool) bool { return !b },
		"or":        func(a, b bool) bool { return a || b },
		"and":       func(a, b bool) bool { return a && b },
		"lower":     strings.ToLower,
		"upper":     strings.ToUpper,
		"trim":      strings.TrimSpace,
		"contains":  strings.Contains,
		"hasPrefix": strings.HasPrefix,
		"hasSuffix": strings.HasSuffix,
		"default": func(def, val interface{}) interface{} {
			if val == nil || val == "" {
				return def
			}
			return val
		},
	}
}

// TemplateContext provides data for template evaluation
type TemplateContext struct {
	Config CatalogTemplateConfig
	Name   string
}

// CatalogTemplateConfig is the only project data exposed to service-catalog
// templates. Authentication hashes, secret values, usernames, and arbitrary
// per-service configuration intentionally stay outside this boundary.
type CatalogTemplateConfig struct {
	Domain        string
	Timezone      string
	ConfigPath    string
	DataPath      string
	DownloadsPath string
	MediaPath     string
	SecretsPath   string
	ProjectDir    string
	PUID          int
	PGID          int
	Umask         string
	VPNEnabled    bool
	VPNProvider   string
	VPNCountry    string
	TorrentPort   int
	Expose        CatalogExposeConfig
	Routing       CatalogRoutingConfig
}

type CatalogExposeConfig struct {
	Mode string
}

type CatalogRoutingConfig struct {
	Strategy   string
	BaseDomain string
	Hostname   string
	Subdomain  string
	Path       string
}

func catalogTemplateConfig(
	cfg *config.Config,
	definition *registry.ServiceDefinition,
) CatalogTemplateConfig {
	return CatalogTemplateConfig{
		Domain:        cfg.Domain,
		Timezone:      cfg.Timezone,
		ConfigPath:    cfg.ConfigPath,
		DataPath:      cfg.DataPath,
		DownloadsPath: cfg.DownloadsPath,
		MediaPath:     cfg.MediaPath,
		SecretsPath:   cfg.SecretsPath,
		ProjectDir:    cfg.ProjectDir,
		PUID:          cfg.PUID,
		PGID:          cfg.PGID,
		Umask:         cfg.Umask,
		VPNEnabled:    cfg.VPNEnabled,
		VPNProvider:   cfg.VPNProvider,
		VPNCountry:    cfg.VPNCountry,
		TorrentPort:   cfg.TorrentPort,
		Expose: CatalogExposeConfig{
			Mode: cfg.Expose.Mode,
		},
		Routing: CatalogRoutingConfig{
			Strategy:   sdbxrouting.Strategy(cfg, definition),
			BaseDomain: cfg.Routing.BaseDomain,
			Hostname:   sdbxrouting.Hostname(cfg, definition),
			Subdomain:  sdbxrouting.Subdomain(cfg, definition),
			Path:       sdbxrouting.Path(cfg, definition),
		},
	}
}

// Generate generates a Docker Compose file from resolved services
func (g *ComposeGenerator) Generate(graph *registry.ResolutionGraph) (*ComposeFile, error) {
	if len(graph.Errors) > 0 {
		return nil, fmt.Errorf("resolution graph has errors: %w", graph.Errors[0])
	}
	if g.Lock != nil {
		if err := registry.ValidateLockFile(g.Lock, true); err != nil {
			return nil, fmt.Errorf("invalid lock file: %w", err)
		}
	}

	compose := &ComposeFile{
		Name:     "sdbx",
		Services: make(map[string]ComposeService),
		Networks: map[string]ComposeNetwork{
			registry.NetworkEdge:        {Name: "sdbx_edge"},
			registry.NetworkApplication: {Name: "sdbx_app"},
			registry.NetworkDownload:    {Name: "sdbx_download"},
			registry.NetworkManagement:  {Name: "sdbx_management"},
		},
		Secrets: make(map[string]ComposeSecretDef),
	}
	// Generate services in dependency order
	for _, serviceName := range graph.Order {
		resolved := graph.Services[serviceName]
		if !resolved.Enabled {
			continue
		}

		def := resolved.FinalDefinition

		// Check conditions
		if !registry.MatchesActivationConditions(def.Conditions, g.Config) {
			continue
		}

		// Generate compose service
		svc, err := g.generateService(def)
		if err != nil {
			return nil, fmt.Errorf("failed to generate service %s: %w", serviceName, err)
		}

		if serviceName == "traefik" {
			// The host console is not a container and never receives Docker API
			// access. This Docker-provided gateway alias is the sole route from
			// Traefik to its mutually authenticated TLS listener.
			svc.ExtraHosts = []string{"host.docker.internal:host-gateway"}
		}
		compose.Services[serviceName] = svc

		// Collect secrets
		for _, secret := range def.Secrets {
			compose.Secrets[secret.Name] = ComposeSecretDef{
				File: g.secretFilePath(secret.Name),
			}
		}
	}

	if err := g.validateVPNBoundary(compose); err != nil {
		return nil, err
	}
	return compose, nil
}

func (g *ComposeGenerator) validateVPNBoundary(compose *ComposeFile) error {
	if g.Config == nil || !g.Config.VPNEnabled {
		return nil
	}
	gluetun, gluetunExists := compose.Services["gluetun"]
	if !gluetunExists {
		return fmt.Errorf("VPN policy requires the gluetun service")
	}
	if !containsString(gluetun.Networks, registry.NetworkDownload) {
		return fmt.Errorf(
			"VPN policy requires gluetun on the %q network",
			registry.NetworkDownload,
		)
	}

	qbittorrent, qbittorrentExists := compose.Services["qbittorrent"]
	if !qbittorrentExists {
		return fmt.Errorf("VPN policy requires the qbittorrent service")
	}
	if qbittorrent.NetworkMode != "service:gluetun" {
		return fmt.Errorf(
			"VPN policy requires qbittorrent network_mode service:gluetun",
		)
	}
	if len(qbittorrent.Networks) != 0 || len(qbittorrent.Ports) != 0 {
		return fmt.Errorf(
			"VPN policy forbids qbittorrent networks or host ports outside gluetun",
		)
	}
	if dependency, ok := qbittorrent.DependsOn["gluetun"]; !ok ||
		dependency.Condition != "service_healthy" {
		return fmt.Errorf(
			"VPN policy requires qbittorrent to wait for healthy gluetun",
		)
	}
	return nil
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

// generateService generates a single compose service
func (g *ComposeGenerator) generateService(def *registry.ServiceDefinition) (ComposeService, error) {
	ctx := TemplateContext{
		Config: catalogTemplateConfig(g.Config, def),
		Name:   def.Metadata.Name,
	}

	image, err := g.resolveImage(def)
	if err != nil {
		return ComposeService{}, err
	}
	containerName, err := renderCatalogTemplate(def.Spec.Container.NameTemplate, ctx)
	if err != nil {
		return ComposeService{}, fmt.Errorf("render container name: %w", err)
	}
	if strings.TrimSpace(containerName) == "" {
		return ComposeService{}, fmt.Errorf("render container name: result is empty")
	}
	hostname, err := renderCatalogTemplate(def.Spec.Container.Hostname, ctx)
	if err != nil {
		return ComposeService{}, fmt.Errorf("render container hostname: %w", err)
	}
	if err := validateEffectiveContainerHostname(hostname); err != nil {
		return ComposeService{}, fmt.Errorf("container hostname: %w", err)
	}
	command, err := renderCatalogTemplate(def.Spec.Container.Command, ctx)
	if err != nil {
		return ComposeService{}, fmt.Errorf("render container command: %w", err)
	}
	user, err := renderCatalogTemplate(def.Spec.Container.User, ctx)
	if err != nil {
		return ComposeService{}, fmt.Errorf("render container user: %w", err)
	}
	if err := validateEffectiveContainerUser(user); err != nil {
		return ComposeService{}, fmt.Errorf("container user: %w", err)
	}
	workingDir, err := renderCatalogTemplate(def.Spec.Container.WorkingDir, ctx)
	if err != nil {
		return ComposeService{}, fmt.Errorf("render container working directory: %w", err)
	}
	svc := ComposeService{
		Image:         image,
		ContainerName: containerName,
		Hostname:      hostname,
		Restart:       def.Spec.Container.Restart,
		User:          user,
		Command:       command,
		ShmSize:       def.Spec.Container.ShmSize,
		Sysctls:       def.Spec.Container.Sysctls,
		Init:          def.Spec.Container.Init,
		WorkingDir:    workingDir,
		SecurityOpt:   []string{"no-new-privileges:true"},
		ReadOnly:      def.Spec.Container.ReadOnlyRoot,
		Tmpfs:         append([]string(nil), def.Spec.Container.Tmpfs...),
		PidsLimit:     def.Spec.Container.PidsLimit,
		StopGrace:     def.Spec.Container.StopGrace,
		Logging: &ComposeLogging{
			Driver: "local",
			Options: map[string]string{
				"max-size": "10m",
				"max-file": "3",
			},
		},
	}
	if svc.PidsLimit == 0 {
		svc.PidsLimit = 512
	}
	if svc.StopGrace == "" {
		svc.StopGrace = "30s"
	}

	// Environment variables
	svc.Environment, err = g.buildEnvironment(def, ctx)
	if err != nil {
		return ComposeService{}, err
	}

	// Env files (template-evaluated so paths can reference Config.ConfigPath etc.)
	if files := def.Spec.Environment.EnvFile; len(files) > 0 {
		svc.EnvFile = make([]string, 0, len(files))
		for index, envFile := range files {
			rendered, renderErr := renderCatalogTemplate(envFile, ctx)
			if renderErr != nil {
				return ComposeService{}, fmt.Errorf(
					"render environment file %d path: %w",
					index,
					renderErr,
				)
			}
			rendered, renderErr = validateEffectiveEnvFile(def, ctx, rendered)
			if renderErr != nil {
				return ComposeService{}, fmt.Errorf(
					"environment file %d: %w",
					index,
					renderErr,
				)
			}
			svc.EnvFile = append(svc.EnvFile, rendered)
		}
	}

	// Volumes
	svc.Volumes, err = g.buildVolumes(def, ctx)
	if err != nil {
		return ComposeService{}, err
	}

	// Ports
	svc.Ports, err = g.buildPorts(def, ctx)
	if err != nil {
		return ComposeService{}, err
	}

	// Networks
	svc.Networks, svc.NetworkMode, err = g.buildNetworking(def, ctx)
	if err != nil {
		return ComposeService{}, err
	}

	// Dependencies
	svc.DependsOn, err = g.buildDependsOn(def, ctx)
	if err != nil {
		return ComposeService{}, err
	}

	// Labels (including Traefik)
	svc.Labels = g.buildLabels(def, ctx)

	// Health check
	if def.Spec.HealthCheck != nil {
		svc.HealthCheck = &ComposeHealthCheck{
			Test:        def.Spec.HealthCheck.Test,
			Interval:    def.Spec.HealthCheck.Interval,
			Timeout:     def.Spec.HealthCheck.Timeout,
			Retries:     def.Spec.HealthCheck.Retries,
			StartPeriod: def.Spec.HealthCheck.StartPeriod,
		}
	}

	// Capabilities
	svc.CapAdd = def.Spec.Container.Capabilities.Add
	svc.CapDrop = def.Spec.Container.Capabilities.Drop

	// Devices
	svc.Devices = def.Spec.Container.Devices

	// Secrets
	for _, secret := range def.Secrets {
		svc.Secrets = append(svc.Secrets, secret.Name)
	}

	return svc, nil
}

// secretFilePath returns the host file path for a docker compose secret. If
// SecretsPath is absolute, the secret file is anchored to it; otherwise we
// emit a relative path that docker compose resolves against the compose file's
// directory (which is the project OutputDir).
func (g *ComposeGenerator) secretFilePath(name string) string {
	base := g.Config.SecretsPath
	if base == "" {
		base = "./secrets"
	}
	if !strings.HasSuffix(base, "/") && !strings.HasSuffix(base, string(filepath.Separator)) {
		base += "/"
	}
	return base + name + ".txt"
}

// resolveImage builds the full image reference
func (g *ComposeGenerator) resolveImage(def *registry.ServiceDefinition) (string, error) {
	img := def.Spec.Image.Repository
	if g.Lock != nil {
		locked, ok := g.Lock.Services[def.Metadata.Name]
		if !ok {
			return "", fmt.Errorf("service %s is missing from lock file", def.Metadata.Name)
		}
		if locked.Image.Repository != def.Spec.Image.Repository ||
			locked.Image.Tag != def.Spec.Image.Tag {
			return "", fmt.Errorf("service %s image does not match lock file", def.Metadata.Name)
		}
		if locked.Image.PlatformDigest == "" {
			return "", fmt.Errorf("service %s has no locked platform digest", def.Metadata.Name)
		}
		return img + "@" + locked.Image.PlatformDigest, nil
	}
	if def.Spec.Image.Tag != "" {
		img += ":" + def.Spec.Image.Tag
	}
	return img, nil
}

// buildEnvironment builds environment variables
func (g *ComposeGenerator) buildEnvironment(
	def *registry.ServiceDefinition,
	ctx TemplateContext,
) ([]string, error) {
	var env []string

	// Static environment variables
	for index, e := range def.Spec.Environment.Static {
		if e.ValueFrom != nil {
			return nil, fmt.Errorf(
				"environment variable %s uses unsupported valueFrom; use a file-backed secret",
				e.Name,
			)
		}
		value, err := renderCatalogTemplate(e.Value, ctx)
		if err != nil {
			return nil, fmt.Errorf(
				"render static environment variable %d (%s): %w",
				index,
				e.Name,
				err,
			)
		}
		env = append(env, fmt.Sprintf("%s=%s", e.Name, value))
	}

	// Conditional environment variables
	for index, e := range def.Spec.Environment.Conditional {
		matches, err := evalCatalogCondition(e.When, ctx)
		if err != nil {
			return nil, fmt.Errorf(
				"evaluate conditional environment variable %d (%s): %w",
				index,
				e.Name,
				err,
			)
		}
		if matches {
			if e.ValueFrom != nil {
				return nil, fmt.Errorf(
					"environment variable %s uses unsupported valueFrom; use a file-backed secret",
					e.Name,
				)
			}
			value, renderErr := renderCatalogTemplate(e.Value, ctx)
			if renderErr != nil {
				return nil, fmt.Errorf(
					"render conditional environment variable %d (%s): %w",
					index,
					e.Name,
					renderErr,
				)
			}
			env = append(env, fmt.Sprintf("%s=%s", e.Name, value))
		}
	}

	return env, nil
}

// buildVolumes builds volume mounts
func (g *ComposeGenerator) buildVolumes(
	def *registry.ServiceDefinition,
	ctx TemplateContext,
) ([]string, error) {
	var volumes []string
	for index, v := range def.Spec.Volumes {
		matches, err := evalCatalogCondition(v.When, ctx)
		if err != nil {
			return nil, fmt.Errorf("evaluate volume %d condition: %w", index, err)
		}
		if !matches {
			continue
		}
		hostPath, err := renderCatalogTemplate(v.HostPath, ctx)
		if err != nil {
			return nil, fmt.Errorf("render volume %d host path: %w", index, err)
		}
		// Templates also work in containerPath for definitions that require
		// matching host and container paths.
		containerPath, err := renderCatalogTemplate(v.ContainerPath, ctx)
		if err != nil {
			return nil, fmt.Errorf("render volume %d container path: %w", index, err)
		}
		hostPath, containerPath, err = validateEffectiveVolume(
			def,
			ctx,
			v,
			hostPath,
			containerPath,
		)
		if err != nil {
			return nil, fmt.Errorf("volume %d: %w", index, err)
		}
		mount := fmt.Sprintf("%s:%s", hostPath, containerPath)
		if v.ReadOnly {
			mount += ":ro"
		}
		volumes = append(volumes, mount)
	}
	return volumes, nil
}

// buildPorts builds port mappings
func (g *ComposeGenerator) buildPorts(
	def *registry.ServiceDefinition,
	ctx TemplateContext,
) ([]string, error) {
	var ports []string

	// Static ports
	for index, port := range def.Spec.Ports.Static {
		rendered, err := renderCatalogTemplate(port, ctx)
		if err != nil {
			return nil, fmt.Errorf("render static port %d: %w", index, err)
		}
		rendered, err = g.normalizePortBinding(def, rendered)
		if err != nil {
			return nil, fmt.Errorf("static port %d: %w", index, err)
		}
		ports = append(ports, rendered)
	}

	// Conditional ports
	for index, p := range def.Spec.Ports.Conditional {
		matches, err := evalCatalogCondition(p.When, ctx)
		if err != nil {
			return nil, fmt.Errorf("evaluate conditional port %d: %w", index, err)
		}
		if matches {
			rendered, err := renderCatalogTemplate(p.Port, ctx)
			if err != nil {
				return nil, fmt.Errorf("render conditional port %d: %w", index, err)
			}
			rendered, err = g.normalizePortBinding(def, rendered)
			if err != nil {
				return nil, fmt.Errorf("conditional port %d: %w", index, err)
			}
			ports = append(ports, rendered)
		}
	}

	return ports, nil
}

func (g *ComposeGenerator) normalizePortBinding(
	def *registry.ServiceDefinition,
	port string,
) (string, error) {
	if strings.TrimSpace(port) == "" || strings.ContainsAny(port, "\x00\r\n") {
		return "", fmt.Errorf("host port binding is empty or contains a control character")
	}
	if !declaresCatalogPermission(def, registry.PermissionHostPort) {
		return "", fmt.Errorf(
			"host port binding requires catalog permission %q",
			registry.PermissionHostPort,
		)
	}
	if g.Config == nil || g.Config.Expose.Mode != config.ExposeModeCloudflared {
		return port, nil
	}
	if strings.HasPrefix(port, "127.0.0.1:") || strings.HasPrefix(port, "localhost:") || strings.HasPrefix(port, "[::1]:") {
		return port, nil
	}
	if strings.Count(port, ":") == 1 {
		return "127.0.0.1:" + port, nil
	}
	return "", fmt.Errorf(
		"cloudflared mode rejects non-loopback explicit host binding %q",
		port,
	)
}

// buildNetworking builds network configuration
func (g *ComposeGenerator) buildNetworking(
	def *registry.ServiceDefinition,
	ctx TemplateContext,
) ([]string, string, error) {
	var networks []string
	var networkMode string

	// Check for network mode template
	if def.Spec.Networking.ModeTemplate != "" {
		var err error
		networkMode, err = renderCatalogTemplate(
			def.Spec.Networking.ModeTemplate,
			ctx,
		)
		if err != nil {
			return nil, "", fmt.Errorf("render network mode: %w", err)
		}
	}

	if networkMode == "" && def.Spec.Networking.Mode != "" && def.Spec.Networking.Mode != "bridge" {
		networkMode = def.Spec.Networking.Mode
	}

	if networkMode == "bridge" || networkMode == "" {
		// Default bridge mode - use networks
		for index, n := range def.Spec.Networking.Networks {
			matches, err := evalCatalogCondition(n.When, ctx)
			if err != nil {
				return nil, "", fmt.Errorf(
					"evaluate network %d (%s) condition: %w",
					index,
					n.Name,
					err,
				)
			}
			if matches {
				if err := validateEffectiveNetworkMembership(def, n.Name); err != nil {
					return nil, "", err
				}
				networks = append(networks, n.Name)
			}
		}
		networkMode = ""
	}

	if err := validateEffectiveNetworkMode(def, networkMode); err != nil {
		return nil, "", err
	}
	return networks, networkMode, nil
}

// buildDependsOn builds service dependencies.
func (g *ComposeGenerator) buildDependsOn(
	def *registry.ServiceDefinition,
	ctx TemplateContext,
) (map[string]DependsOnCondition, error) {
	deps := make(map[string]DependsOnCondition)

	// Required dependencies
	for _, dep := range def.Spec.Dependencies.Required {
		deps[dep] = DependsOnCondition{Condition: "service_started"}
	}

	// Conditional dependencies
	for index, dep := range def.Spec.Dependencies.Conditional {
		matches, err := evalCatalogCondition(dep.When, ctx)
		if err != nil {
			return nil, fmt.Errorf(
				"evaluate conditional dependency %d (%s): %w",
				index,
				dep.Name,
				err,
			)
		}
		if matches {
			deps[dep.Name] = DependsOnCondition{
				Condition: defaultDependencyCondition(dep.Condition),
			}
		}
	}

	if len(deps) == 0 {
		return nil, nil
	}
	return deps, nil
}

// buildLabels builds Docker labels including Traefik configuration
func (g *ComposeGenerator) buildLabels(def *registry.ServiceDefinition, ctx TemplateContext) []string {
	var labels []string

	for key, value := range def.Spec.Container.CustomLabels {
		labels = append(labels, fmt.Sprintf("%s=%s", key, value))
	}

	return labels
}

func defaultDependencyCondition(condition string) string {
	if condition == "" {
		return "service_started"
	}
	return condition
}

func renderCatalogTemplate(tmpl string, ctx TemplateContext) (string, error) {
	if !strings.Contains(tmpl, "{{") {
		return tmpl, nil
	}
	t, err := template.New("").
		Funcs(catalogTemplateFuncMap()).
		Option("missingkey=error").
		Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, ctx); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}
	return buf.String(), nil
}

// evalCatalogCondition evaluates a rendered condition using the exact boolean
// contract accepted by the catalog validator.
func evalCatalogCondition(condition string, ctx TemplateContext) (bool, error) {
	condition = strings.TrimSpace(condition)
	if condition == "" {
		return true, nil
	}

	rendered, err := renderCatalogTemplate(condition, ctx)
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(rendered) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf(
			"condition rendered %q; expected true or false",
			strings.TrimSpace(rendered),
		)
	}
}

// ToYAML converts the compose file to YAML
func (c *ComposeFile) ToYAML() ([]byte, error) {
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(c); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
