// Package generator handles project file generation from templates and registry.
package generator

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/integrate"
	"github.com/get-sdbx/sdbx/internal/registry"
	sdbxrouting "github.com/get-sdbx/sdbx/internal/routing"
	"github.com/get-sdbx/sdbx/internal/secrets"
	"github.com/get-sdbx/sdbx/internal/securefs"
)

//go:embed templates/*
var templatesFS embed.FS

// Generator handles project generation
type Generator struct {
	Config               *config.Config
	OutputDir            string
	Registry             *registry.Registry
	Lock                 *registry.LockFile
	CLIVersion           string
	configRootOverride   string
	secretsRootOverride  string
	deferVolumeOwnership bool
}

// WithManagedRoots redirects generated configuration and secret files without
// changing the paths rendered into Compose. It is used by the transactional
// initializer to validate a complete staged tree before promotion.
func (g *Generator) WithManagedRoots(configRoot, secretsRoot string) *Generator {
	g.configRootOverride = configRoot
	g.secretsRootOverride = secretsRoot
	return g
}

// WithDeferredVolumeOwnership prevents a staging generator from changing live
// host ownership before its journal is committed. The transaction applies the
// same ownership plan to the promoted targets after file promotion.
func (g *Generator) WithDeferredVolumeOwnership() *Generator {
	g.deferVolumeOwnership = true
	return g
}

// NewGenerator creates a new Generator with default registry
func NewGenerator(cfg *config.Config, outputDir string) *Generator {
	// Always create a default registry for service resolution
	reg, err := registry.NewWithDefaults()
	if err != nil {
		// Log error but continue - embedded source will be available
		reg = nil
	}
	return &Generator{
		Config:    cfg,
		OutputDir: outputDir,
		Registry:  reg,
	}
}

// NewGeneratorWithRegistry creates a Generator with registry support
func NewGeneratorWithRegistry(cfg *config.Config, outputDir string, reg *registry.Registry) *Generator {
	return &Generator{
		Config:    cfg,
		OutputDir: outputDir,
		Registry:  reg,
	}
}

// NewGeneratorWithLock creates a production generator that refuses stale or
// incomplete provenance and emits only digest-pinned images.
func NewGeneratorWithLock(
	cfg *config.Config,
	outputDir string,
	reg *registry.Registry,
	lock *registry.LockFile,
	cliVersion string,
) *Generator {
	return &Generator{
		Config:     cfg,
		OutputDir:  outputDir,
		Registry:   reg,
		Lock:       lock,
		CLIVersion: cliVersion,
	}
}

// TemplateData is passed to all templates
type TemplateData struct {
	Config          *config.Config
	AutheliaAddress string
	AutheliaURL     string
	AutheliaRules   []AutheliaAccessRule
	ProjectIgnores  []string
}

// Plan validates configuration, managed paths, lock provenance, and the
// service graph without creating directories, secrets, or generated files.
func (g *Generator) Plan() (*registry.ResolutionGraph, error) {
	if err := g.validateConfig(); err != nil {
		return nil, err
	}
	if err := g.validateManagedPaths(); err != nil {
		return nil, err
	}
	if err := g.validateLock(); err != nil {
		return nil, err
	}
	graph, err := g.resolve()
	if err != nil {
		return nil, err
	}
	if len(graph.Errors) > 0 {
		return nil, fmt.Errorf("service resolution failed: %w", graph.Errors[0])
	}
	activateConfigServices(g.Config, graph)
	return graph, nil
}

func activateConfigServices(
	cfg *config.Config,
	graph *registry.ResolutionGraph,
) {
	cfg.ActiveServices = make(map[string]bool, len(graph.Order))
	for _, name := range graph.Order {
		resolved := graph.Services[name]
		if resolved != nil && resolved.Enabled && resolved.FinalDefinition != nil {
			cfg.ActiveServices[name] = true
		}
	}
}

// Generate creates all project files
func (g *Generator) Generate() error {
	graph, err := g.Plan()
	if err != nil {
		return err
	}

	if err := g.ensureDirs(g.fullProjectDirs(graph)); err != nil {
		return err
	}
	if err := g.ensureTraefikState(); err != nil {
		return err
	}

	if err := g.applyVolumeOwnership(graph); err != nil {
		return err
	}

	data, err := g.templateData(graph)
	if err != nil {
		return err
	}

	if err := g.writeResolvedFiles(graph, data, writeOptions{Env: true}); err != nil {
		return err
	}
	if err := g.writeStaticFiles(graph, data); err != nil {
		return err
	}
	if err := g.renderDependentConfigs(graph); err != nil {
		return err
	}
	return g.recordGeneratedFileDigests(graph)
}

// GenerateRuntimeFiles refreshes files that are derived from the service graph
// without rewriting static service configuration templates.
func (g *Generator) GenerateRuntimeFiles() error {
	graph, err := g.Plan()
	if err != nil {
		return err
	}

	if err := g.ensureDirs(g.runtimeDirs(graph)); err != nil {
		return err
	}
	if err := g.ensureTraefikState(); err != nil {
		return err
	}

	if err := g.applyVolumeOwnership(graph); err != nil {
		return err
	}

	data, err := g.templateData(graph)
	if err != nil {
		return err
	}

	if err := g.writeResolvedFiles(
		graph,
		data,
		writeOptions{Env: true, ProjectConfig: true},
	); err != nil {
		return err
	}
	if err := g.renderDependentConfigs(graph); err != nil {
		return err
	}
	return g.recordGeneratedFileDigests(graph)
}

func (g *Generator) renderDependentConfigs(graph *registry.ResolutionGraph) error {
	cfg := *g.Config
	cfg.ConfigPath = g.configRoot()
	cfg.SecretsPath = g.secretsRoot()
	results, err := integrate.EnsureArrAPIKeys(&cfg)
	if err != nil {
		return fmt.Errorf("render *arr authentication config: %w", err)
	}
	for _, result := range results {
		if result.Err != nil {
			return fmt.Errorf(
				"render %s authentication config: %w",
				result.Service,
				result.Err,
			)
		}
	}
	if graphServiceEnabled(graph, "unpackerr") {
		if err := integrate.RenderUnpackerrEnvironment(&cfg, graph); err != nil {
			return fmt.Errorf("render Unpackerr integration: %w", err)
		}
	}
	if graphServiceEnabled(graph, "cobalt") {
		if _, err := integrate.EnsureCobaltKeys(&cfg); err != nil {
			return fmt.Errorf("render Cobalt API keys: %w", err)
		}
	}
	return nil
}

func (g *Generator) recordGeneratedFileDigests(
	graph *registry.ResolutionGraph,
) error {
	if g.Lock == nil {
		return nil
	}

	paths := []string{
		"compose.yaml",
		".env",
		registry.ConfigGeneratedFile("authelia/configuration.yml"),
		registry.ConfigGeneratedFile("traefik/traefik.yml"),
		registry.ConfigGeneratedFile("traefik/dynamic/middlewares.yml"),
	}

	digests, err := registry.RecordGeneratedFiles(
		g.OutputDir,
		g.configRoot(),
		paths,
	)
	if err != nil {
		return fmt.Errorf("failed to record generated runtime files: %w", err)
	}
	g.Lock.GeneratedFiles = digests
	return nil
}

func (g *Generator) validateConfig() error {
	if g.Config == nil {
		return fmt.Errorf("project configuration is required")
	}
	if err := g.Config.Validate(); err != nil {
		return fmt.Errorf("invalid project configuration: %w", err)
	}
	return nil
}

func (g *Generator) validateLock() error {
	if g.Lock == nil {
		return nil
	}
	return ValidateProjectLock(
		context.Background(),
		g.Config,
		g.Registry,
		g.Lock,
		g.CLIVersion,
	)
}

// ValidateProjectLock proves that config, catalog, definitions, source trust,
// install order, CLI version, and image pins still match.
func ValidateProjectLock(
	ctx context.Context,
	cfg *config.Config,
	reg *registry.Registry,
	lock *registry.LockFile,
	cliVersion string,
) error {
	resolver, err := registry.NewLockedImageResolver(lock)
	if err != nil {
		return fmt.Errorf("invalid .sdbx.lock: %w", err)
	}
	allowLocalSources := false
	for _, source := range lock.Sources {
		if source.Type == "local" {
			allowLocalSources = true
			break
		}
	}
	current, _, err := reg.GenerateLockFileWithOptions(
		ctx,
		cfg,
		registry.LockOptions{
			CLIVersion:        cliVersion,
			AllowLocalSources: allowLocalSources,
			ImageResolver:     resolver,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to verify .sdbx.lock: %w", err)
	}
	if diffs := reg.DiffLockFiles(lock, current); len(diffs) > 0 {
		return fmt.Errorf(".sdbx.lock is stale: %s", diffs[0].Description)
	}
	return nil
}

// RegenerateRuntimeWithUpdatedLock applies an authorized config/catalog
// mutation, reusing existing pins and resolving only newly introduced images.
func RegenerateRuntimeWithUpdatedLock(
	ctx context.Context,
	cfg *config.Config,
	outputDir string,
	reg *registry.Registry,
	existing *registry.LockFile,
	cliVersion string,
	imageResolver registry.ImageDigestResolver,
) (*registry.LockFile, error) {
	if existing == nil {
		return nil, fmt.Errorf(".sdbx.lock is required for project mutations")
	}
	updatingResolver, err := registry.NewUpdatingImageResolver(existing, imageResolver)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize image resolver: %w", err)
	}
	allowLocalSources := false
	for _, source := range existing.Sources {
		if source.Type == "local" {
			allowLocalSources = true
			break
		}
	}
	updated, _, err := reg.GenerateLockFileWithOptions(
		ctx,
		cfg,
		registry.LockOptions{
			CLIVersion:        cliVersion,
			AllowLocalSources: allowLocalSources,
			ImageResolver:     updatingResolver,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update .sdbx.lock: %w", err)
	}
	if err := GenerateProjectTransactional(
		cfg,
		outputDir,
		reg,
		updated,
		cliVersion,
		ProjectTransactionOptions{RuntimeOnly: true},
	); err != nil {
		return nil, fmt.Errorf("commit updated runtime transaction: %w", err)
	}
	return updated, nil
}

type writeOptions struct {
	Env           bool
	ProjectConfig bool
}

func (g *Generator) resolve() (*registry.ResolutionGraph, error) {
	ctx := context.Background()

	if g.Registry == nil {
		var err error
		g.Registry, err = registry.NewWithDefaults()
		if err != nil {
			return nil, fmt.Errorf("failed to create registry: %w", err)
		}
	}

	graph, err := g.Registry.Resolve(ctx, g.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve services: %w", err)
	}
	return graph, nil
}

func (g *Generator) templateData(
	graph *registry.ResolutionGraph,
) (TemplateData, error) {
	projectIgnores, err := g.projectIgnorePatterns()
	if err != nil {
		return TemplateData{}, err
	}
	secretsDir := g.secretsRoot()
	required, err := requiredGraphSecrets(graph)
	if err != nil {
		return TemplateData{}, err
	}
	if err := secrets.GenerateSelectedSecrets(secretsDir, required); err != nil {
		return TemplateData{}, fmt.Errorf("failed to generate secrets: %w", err)
	}
	if graphServiceEnabled(graph, "traefik") {
		if err := secrets.EnsureConsoleProxyPKI(secretsDir); err != nil {
			return TemplateData{}, fmt.Errorf("prepare console proxy trust: %w", err)
		}
	}

	return TemplateData{
		Config:         g.Config,
		ProjectIgnores: projectIgnores,
	}, nil
}

func (g *Generator) projectIgnorePatterns() ([]string, error) {
	projectRoot, err := filepath.Abs(g.OutputDir)
	if err != nil {
		return nil, fmt.Errorf("resolve project root for .gitignore: %w", err)
	}

	configured := []string{
		g.Config.ConfigPath,
		g.Config.DataPath,
		g.Config.DownloadsPath,
		g.Config.MediaPath,
		g.Config.SecretsPath,
	}
	candidates := make([]string, 0, len(configured))
	for _, target := range configured {
		if target == "" {
			continue
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(projectRoot, target)
		}
		relative, err := filepath.Rel(projectRoot, filepath.Clean(target))
		if err != nil {
			return nil, fmt.Errorf("resolve managed .gitignore path: %w", err)
		}
		if relative == "." ||
			relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		if strings.ContainsAny(relative, "\x00\r\n") {
			return nil, fmt.Errorf("managed .gitignore path contains a control character")
		}
		candidates = append(
			candidates,
			"/"+filepath.ToSlash(relative)+"/",
		)
	}

	sort.Strings(candidates)
	patterns := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		covered := false
		for _, existing := range patterns {
			if strings.HasPrefix(candidate, existing) {
				covered = true
				break
			}
		}
		if !covered {
			patterns = append(patterns, candidate)
		}
	}
	return patterns, nil
}

func requiredGraphSecrets(
	graph *registry.ResolutionGraph,
) (map[string]int, error) {
	required := make(map[string]int)
	for _, serviceName := range graph.Order {
		resolved := graph.Services[serviceName]
		if resolved == nil || !resolved.Enabled || resolved.FinalDefinition == nil {
			continue
		}
		for _, definition := range resolved.FinalDefinition.Secrets {
			length := 0
			switch definition.Type {
			case "auto":
				length = definition.Length
				if length < 16 || length > 4096 {
					return nil, fmt.Errorf(
						"service %s secret %s has unsafe generated length %d",
						serviceName,
						definition.Name,
						length,
					)
				}
			case "manual":
				if definition.Length != 0 {
					return nil, fmt.Errorf(
						"service %s manual secret %s must not declare a generated length",
						serviceName,
						definition.Name,
					)
				}
			default:
				return nil, fmt.Errorf(
					"service %s secret %s has unsupported type %q",
					serviceName,
					definition.Name,
					definition.Type,
				)
			}
			filename := definition.Name + ".txt"
			if existing, duplicate := required[filename]; duplicate && existing != length {
				return nil, fmt.Errorf(
					"secret %s has conflicting generated lengths %d and %d",
					definition.Name,
					existing,
					length,
				)
			}
			required[filename] = length
		}
	}
	// These credentials are consumed by deterministic post-start integrations
	// rather than mounted into the corresponding service containers.
	integrationCredentials := map[string]string{
		"qbittorrent": "qbittorrent_password.txt",
		"filebrowser": "filebrowser_admin_password.txt",
		"sonarr":      "sonarr_admin_password.txt",
		"prowlarr":    "prowlarr_admin_password.txt",
		"radarr":      "radarr_admin_password.txt",
		"lidarr":      "lidarr_admin_password.txt",
		"whisparr":    "whisparr_admin_password.txt",
	}
	for serviceName, filename := range integrationCredentials {
		if graphServiceEnabled(graph, serviceName) {
			required[filename] = secrets.SecretFiles[filename]
		}
	}
	if graphServiceEnabled(graph, "traefik") {
		for _, filename := range []string{
			secrets.ConsoleProxyCAFile,
			secrets.ConsoleProxyServerCertFile,
			secrets.ConsoleProxyServerKeyFile,
			secrets.ConsoleProxyClientCertFile,
			secrets.ConsoleProxyClientKeyFile,
		} {
			required[filename] = secrets.SecretFiles[filename]
		}
	}
	return required, nil
}

func (g *Generator) writeResolvedFiles(graph *registry.ResolutionGraph, data TemplateData, options writeOptions) error {
	composeGen := NewComposeGeneratorWithLock(g.Config, g.Registry, g.Lock)
	composeFile, err := composeGen.Generate(graph)
	if err != nil {
		return fmt.Errorf("failed to generate compose file: %w", err)
	}

	composeYAML, err := composeFile.ToYAML()
	if err != nil {
		return fmt.Errorf("failed to serialize compose file: %w", err)
	}

	if err := writeGeneratedFile(g.projectPath("compose.yaml"), composeYAML, 0o644); err != nil {
		return fmt.Errorf("failed to write compose.yaml: %w", err)
	}

	intGen := NewIntegrationsGenerator(g.Config)

	autheliaRules, err := intGen.GenerateAutheliaAccessRules(graph)
	if err != nil {
		return fmt.Errorf("failed to generate Authelia access rules: %w", err)
	}
	data.AutheliaRules = autheliaRules
	authelia, ok := graph.Services["authelia"]
	if !ok || authelia == nil || !authelia.Enabled || authelia.FinalDefinition == nil {
		return fmt.Errorf("resolved graph is missing required authelia service")
	}
	if sdbxrouting.Strategy(g.Config, authelia.FinalDefinition) == config.RoutingStrategyPath {
		data.AutheliaAddress = "tcp://0.0.0.0:9091" +
			sdbxrouting.Path(g.Config, authelia.FinalDefinition)
	} else {
		data.AutheliaAddress = "tcp://0.0.0.0:9091/"
	}
	data.AutheliaURL = sdbxrouting.URL(g.Config, authelia.FinalDefinition)
	if err := g.generateFile(
		"authelia-configuration.yml.tmpl",
		g.configPath("authelia", "configuration.yml"),
		data,
		0o644,
	); err != nil {
		return fmt.Errorf("failed to generate Authelia configuration: %w", err)
	}
	if err := g.generateFile(
		"traefik.yml.tmpl",
		g.configPath("traefik", "traefik.yml"),
		data,
		0o644,
	); err != nil {
		return fmt.Errorf("failed to generate Traefik configuration: %w", err)
	}

	traefikDynamic, err := intGen.GenerateTraefikDynamic(graph)
	if err != nil {
		return fmt.Errorf("failed to generate traefik dynamic: %w", err)
	}
	if err := writeGeneratedFile(
		g.configPath("traefik", "dynamic", "middlewares.yml"),
		traefikDynamic,
		0o644,
	); err != nil {
		return fmt.Errorf("failed to write traefik middlewares: %w", err)
	}

	if options.Env {
		envContent, err := intGen.GenerateEnvFile(graph)
		if err != nil {
			return fmt.Errorf("failed to generate .env: %w", err)
		}
		if err := writeGeneratedFile(g.projectPath(".env"), envContent, 0o600); err != nil {
			return fmt.Errorf("failed to write .env: %w", err)
		}
	}

	if options.ProjectConfig {
		if err := g.Config.SaveFile(g.projectPath(".sdbx.yaml")); err != nil {
			return fmt.Errorf("failed to generate .sdbx.yaml: %w", err)
		}
	}

	return nil
}

func (g *Generator) writeStaticFiles(
	graph *registry.ResolutionGraph,
	data TemplateData,
) error {
	if err := g.Config.SaveFile(g.projectPath(".sdbx.yaml")); err != nil {
		return fmt.Errorf("failed to generate .sdbx.yaml: %w", err)
	}

	staticFiles := []struct {
		template string
		output   string
		mode     os.FileMode
		service  string
	}{
		{"gitignore.tmpl", g.projectPath(".gitignore"), 0o644, ""},
		{
			"authelia-users.yml.tmpl",
			g.configPath("authelia", "users_database.yml"),
			0o600,
			"authelia",
		},
		{
			"gluetun.env.tmpl",
			g.configPath("gluetun", "gluetun.env"),
			0o600,
			"gluetun",
		},
	}

	for _, f := range staticFiles {
		if f.service != "" && !graphServiceEnabled(graph, f.service) {
			continue
		}
		if err := g.generateFile(f.template, f.output, data, f.mode); err != nil {
			return fmt.Errorf("failed to generate %s: %w", f.output, err)
		}
	}

	return nil
}

// ensureDirs creates each absolute directory path if missing.
func (g *Generator) ensureDirs(dirs []string) error {
	for _, dir := range dirs {
		if err := securefs.EnsureDir(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
		info, err := os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("failed to inspect directory %s: %w", dir, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("managed directory %s must be a directory, not a symlink", dir)
		}
	}
	return nil
}

func (g *Generator) ensureTraefikState() error {
	if g.Config.Expose.Mode != config.ExposeModeDirect {
		return nil
	}
	path := g.configPath("traefik", "acme.json")
	before, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := securefs.WriteFileAtomicPreserveDir(path, nil, 0o755, 0o600); err != nil {
			return fmt.Errorf("create Traefik ACME state: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect Traefik ACME state: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return fmt.Errorf("Traefik ACME state %s must be a regular file, not a symlink or special file", path)
	}

	// #nosec G304 -- the generated ACME path is confined to the managed
	// configuration root and Lstat/SameFile reject symlink swaps.
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open Traefik ACME state: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect open Traefik ACME state: %w", err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return fmt.Errorf("Traefik ACME state %s changed while it was being opened", path)
	}
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("secure Traefik ACME state: %w", err)
	}
	return nil
}

func (g *Generator) fullProjectDirs(graph *registry.ResolutionGraph) []string {
	return append([]string{g.OutputDir}, g.runtimeDirs(graph)...)
}

func (g *Generator) runtimeDirs(graph *registry.ResolutionGraph) []string {
	dirs := []string{
		g.configRoot(),
		g.configPath("traefik"),
		g.configPath("traefik", "dynamic"),
	}
	for _, serviceName := range graph.Order {
		resolved := graph.Services[serviceName]
		if resolved != nil && resolved.Enabled {
			dirs = append(dirs, g.configPath(serviceName))
		}
	}
	for _, addonName := range g.Config.Addons {
		dirs = append(dirs, g.configPath(addonName))
	}
	return dirs
}

func graphServiceEnabled(graph *registry.ResolutionGraph, name string) bool {
	resolved := graph.Services[name]
	return resolved != nil && resolved.Enabled && resolved.FinalDefinition != nil
}

// generateFile renders a template to outputPath. outputPath must be absolute
// (callers use g.projectPath / g.configPath / g.secretsPath helpers).
func (g *Generator) generateFile(
	templateName,
	outputPath string,
	data TemplateData,
	mode os.FileMode,
) error {
	tmplContent, err := templatesFS.ReadFile("templates/" + templateName)
	if err != nil {
		return fmt.Errorf("template not found: %s: %w", templateName, err)
	}

	tmpl, err := template.New(templateName).Funcs(template.FuncMap{
		"yamlQuote": strconv.Quote,
	}).Parse(string(tmplContent))
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	if !filepath.IsAbs(outputPath) {
		outputPath = filepath.Join(g.OutputDir, outputPath)
	}

	var rendered bytes.Buffer
	if err := tmpl.Execute(&rendered, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return writeGeneratedFile(outputPath, rendered.Bytes(), mode)
}

func writeGeneratedFile(path string, data []byte, mode os.FileMode) error {
	return securefs.WriteFileAtomicPreserveDir(path, data, 0o755, mode.Perm())
}

// CreateDataDirs creates the data directory structure
func (g *Generator) CreateDataDirs() error {
	if err := g.validateConfig(); err != nil {
		return err
	}
	if err := g.validateManagedPaths(); err != nil {
		return err
	}
	mediaRoot := g.resolvePath(g.Config.MediaPath)
	dataRoot := g.resolvePath(g.Config.DataPath)
	dirs := []string{
		dataRoot,
		filepath.Join(dataRoot, "authelia"),
		g.resolvePath(g.Config.DownloadsPath),
		mediaRoot,
		filepath.Join(mediaRoot, "movies"),
		filepath.Join(mediaRoot, "tv"),
		filepath.Join(mediaRoot, "music"),
		filepath.Join(mediaRoot, "books"),
	}
	if g.Config.VPNEnabled {
		dirs = append(dirs, filepath.Join(dataRoot, "gluetun"))
	}

	for _, dir := range dirs {
		if err := securefs.EnsureDir(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create %s: %w", dir, err)
		}
	}

	return nil
}
