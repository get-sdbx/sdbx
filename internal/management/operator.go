package management

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/get-sdbx/sdbx/internal/addons"
	"github.com/get-sdbx/sdbx/internal/backup"
	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/docker"
	"github.com/get-sdbx/sdbx/internal/doctor"
	"github.com/get-sdbx/sdbx/internal/generator"
	verifiedproject "github.com/get-sdbx/sdbx/internal/project"
	"github.com/get-sdbx/sdbx/internal/recovery"
	"github.com/get-sdbx/sdbx/internal/redact"
	"github.com/get-sdbx/sdbx/internal/registry"
	sdbxrouting "github.com/get-sdbx/sdbx/internal/routing"
	"github.com/get-sdbx/sdbx/internal/settings"
)

const maxManagedLogBytes = 2 << 20

var ErrProjectUnverified = errors.New("project state is not verified")

var brokerReadOnlySettings = map[string]bool{
	"config_path":    true,
	"data_path":      true,
	"downloads_path": true,
	"media_path":     true,
	"secrets_path":   true,
}

// ProjectOperator implements the typed management boundary for exactly one
// registered project.
type ProjectOperator struct {
	ProjectDir string
	CLIVersion string
	Registry   *registry.Registry
	Resolver   registry.ImageDigestResolver
	gate       contextGate
}

type contextGate struct {
	once  sync.Once
	token chan struct{}
}

func (g *contextGate) Lock(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("operation context is required")
	}
	g.once.Do(func() {
		g.token = make(chan struct{}, 1)
	})
	select {
	case g.token <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g *contextGate) Unlock() {
	<-g.token
}

func NewProjectOperator(
	projectDir, cliVersion string,
	reg *registry.Registry,
	resolver registry.ImageDigestResolver,
) (*ProjectOperator, error) {
	if projectDir == "" {
		return nil, fmt.Errorf("project directory is required")
	}
	if cliVersion == "" {
		return nil, fmt.Errorf("CLI version is required")
	}
	projectDir = filepath.Clean(projectDir)
	if err := backup.NewManager(projectDir).RecoverInterruptedRestore(); err != nil {
		return nil, fmt.Errorf("recover interrupted project restore: %w", err)
	}
	if reg == nil {
		var err error
		reg, err = registry.NewWithDefaults()
		if err != nil {
			return nil, err
		}
	}
	if resolver == nil {
		resolver = registry.NewOfficialImageDigestResolver(
			registry.NewDockerImageDigestResolver(),
		)
	}
	operator := &ProjectOperator{
		ProjectDir: projectDir,
		CLIVersion: cliVersion,
		Registry:   reg,
		Resolver:   resolver,
	}
	if _, err := operator.load(context.Background(), false); err != nil {
		return nil, err
	}
	return operator, nil
}

func (o *ProjectOperator) load(
	ctx context.Context,
	requireGenerated bool,
) (*verifiedproject.Verified, error) {
	cfg, err := config.LoadFile(filepath.Join(o.ProjectDir, ".sdbx.yaml"))
	if err != nil {
		return nil, err
	}
	verify := verifiedproject.Verify
	if requireGenerated {
		verify = verifiedproject.VerifyGeneratedRuntime
	}
	verified, err := verify(ctx, o.ProjectDir, cfg, o.Registry, o.CLIVersion)
	if err != nil {
		if requireGenerated {
			return nil, fmt.Errorf("%w: %w", ErrProjectUnverified, err)
		}
		return nil, err
	}
	return verified, nil
}

func (o *ProjectOperator) Preview(
	ctx context.Context,
	request ImpactRequest,
) (*Impact, error) {
	if err := o.gate.Lock(ctx); err != nil {
		return nil, err
	}
	defer o.gate.Unlock()
	verified, err := o.load(ctx, false)
	if err != nil {
		return nil, err
	}
	switch request.Operation {
	case "stack.up":
		return &Impact{
			Operation:    request.Operation,
			Title:        "Start the SDBX stack",
			Consequences: []string{"Starts every service in the active locked graph."},
			Confirmation: "up",
		}, nil
	case "stack.down":
		return &Impact{
			Operation: request.Operation,
			Title:     "Stop the SDBX stack",
			Consequences: []string{
				"Stops every running SDBX service.",
				"Media and automation interfaces remain unavailable until the stack is started.",
			},
			Confirmation: "down",
			HighImpact:   true,
		}, nil
	case "stack.restart":
		return &Impact{
			Operation: request.Operation,
			Title:     "Restart the SDBX stack",
			Consequences: []string{
				"Restarts every service in the active locked graph.",
				"Interfaces may be briefly unavailable.",
			},
			Confirmation: "restart",
			HighImpact:   true,
		}, nil
	case "backup.create":
		return &Impact{
			Operation:    request.Operation,
			Title:        "Create an encrypted recovery archive",
			Consequences: []string{"Reads the current project configuration and writes a new encrypted backup."},
			Confirmation: "backup",
		}, nil
	case "backup.restore":
		if request.Target == "" {
			return nil, fmt.Errorf("backup target is required")
		}
		return &Impact{
			Operation: request.Operation,
			Title:     "Restore encrypted backup " + request.Target,
			Consequences: []string{
				"The verified target project, lock, Compose, environment, and generated policy remain unchanged.",
				"Compatible application configuration and secrets are replaced with state from the selected archive.",
				"Managed-root relocation must be explicitly enabled when archived config or secrets paths differ.",
				"The transaction remains reversible until the restored target verifies.",
			},
			Confirmation: "restore",
			HighImpact:   true,
		}, nil
	case "backup.delete":
		if request.Target == "" {
			return nil, fmt.Errorf("backup target is required")
		}
		return &Impact{
			Operation:    request.Operation,
			Title:        "Delete encrypted backup " + request.Target,
			Consequences: []string{"Permanently removes the selected recovery archive."},
			Confirmation: "delete",
			HighImpact:   true,
		}, nil
	case "addon.enable", "addon.disable":
		if request.Target == "" {
			return nil, fmt.Errorf("addon target is required")
		}
		found := false
		for _, addon := range verified.Config.Addons {
			if addon == request.Target {
				found = true
				break
			}
		}
		if !found {
			services, listErr := o.Registry.ListServices(ctx)
			if listErr != nil {
				return nil, listErr
			}
			for _, service := range services {
				if service.IsAddon && service.Name == request.Target {
					found = true
					break
				}
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown addon target")
		}
		action := strings.TrimPrefix(request.Operation, "addon.")
		return &Impact{
			Operation: request.Operation,
			Title:     strings.ToUpper(action[:1]) + action[1:] + " addon " + request.Target,
			Consequences: []string{
				"Updates the locked service graph and regenerates managed runtime files.",
			},
			Confirmation: action,
			HighImpact:   action == "disable",
		}, nil
	case "setting.update":
		if request.Target == "" {
			return nil, fmt.Errorf("setting target is required")
		}
		if brokerReadOnlySettings[request.Target] {
			return nil, fmt.Errorf(
				"managed-root paths are read-only through the broker; use the local CLI or edit .sdbx.yaml and run sdbx generate",
			)
		}
		valid := false
		for _, key := range settings.ValidKeys() {
			if key == request.Target {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("unknown setting target")
		}
		return &Impact{
			Operation: request.Operation,
			Title:     "Update setting " + request.Target,
			Consequences: []string{
				"Updates project configuration, lock metadata, and generated runtime files.",
			},
			Confirmation: "save",
			HighImpact:   true,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported impact operation")
	}
}

func (o *ProjectOperator) Summary(ctx context.Context) (*Summary, error) {
	if err := o.gate.Lock(ctx); err != nil {
		return nil, err
	}
	defer o.gate.Unlock()
	verified, err := o.load(ctx, false)
	if err != nil {
		return nil, err
	}
	services, _ := o.services(ctx, verified)
	addonList, err := o.addons(ctx, verified)
	if err != nil {
		return nil, err
	}
	backups, err := listBackups(ctx, o.ProjectDir)
	if err != nil {
		return nil, err
	}
	running := 0
	for _, service := range services {
		if service.Running {
			running++
		}
	}
	enabled := 0
	for _, addon := range addonList {
		if addon.Enabled {
			enabled++
		}
	}
	warnings := make([]Warning, 0, len(verified.Graph.Warnings))
	for _, warning := range verified.Graph.Warnings {
		warnings = append(warnings, Warning{
			Service: warning.Service,
			Field:   warning.Field,
			Message: redact.Text(warning.Message),
		})
	}
	return &Summary{
		Domain:           verified.Config.Domain,
		ProjectID:        filepath.Base(o.ProjectDir),
		RunningServices:  running,
		TotalServices:    len(services),
		EnabledAddons:    enabled,
		TotalAddons:      len(addonList),
		Backups:          len(backups),
		RegistryWarnings: len(warnings),
		Warnings:         warnings,
	}, nil
}

func (o *ProjectOperator) Security(ctx context.Context) (*SecurityReport, error) {
	if err := o.gate.Lock(ctx); err != nil {
		return nil, err
	}
	defer o.gate.Unlock()
	verified, err := o.load(ctx, true)
	if err != nil {
		return nil, err
	}
	report := &SecurityReport{
		ProjectVerified:        true,
		GeneratedFilesVerified: true,
		LockSchema:             verified.Lock.Metadata.Version,
		LockedServices:         len(verified.Lock.Services),
		ExposureMode:           verified.Config.Expose.Mode,
		TLSProvider:            verified.Config.Expose.TLS.Provider,
		HTTPSRequired:          true,
		RoutingStrategy:        verified.Config.Routing.Strategy,
		VPNEnabled:             verified.Config.VPNEnabled,
		RouteAuth:              make(map[string]int),
	}
	for _, service := range verified.Lock.Services {
		if strings.HasPrefix(service.Image.Digest, "sha256:") {
			report.ImmutableImages++
		}
	}
	composeModel, err := generator.NewComposeGeneratorWithLock(
		verified.Config,
		o.Registry,
		verified.Lock,
	).Generate(verified.Graph)
	if err != nil {
		return nil, fmt.Errorf("build verified security Compose model: %w", err)
	}
	qbittorrent, qbittorrentEnabled := composeModel.Services["qbittorrent"]
	_, gluetunEnabled := composeModel.Services["gluetun"]
	if verified.Config.VPNEnabled && qbittorrentEnabled && gluetunEnabled {
		report.DownloadVPNEnforced =
			qbittorrent.NetworkMode == "service:gluetun" &&
				len(qbittorrent.Networks) == 0 &&
				len(qbittorrent.Ports) == 0
	}
	for _, name := range verified.Graph.Order {
		resolved := verified.Graph.Services[name]
		if resolved == nil ||
			!resolved.Enabled ||
			resolved.FinalDefinition == nil ||
			!resolved.FinalDefinition.Routing.Enabled {
			continue
		}
		report.RouteAuth[string(resolved.FinalDefinition.Routing.Auth.Mode)]++
	}
	return report, nil
}

func (o *ProjectOperator) Diagnostics(
	ctx context.Context,
) (*DiagnosticsReport, error) {
	if err := o.gate.Lock(ctx); err != nil {
		return nil, err
	}
	defer o.gate.Unlock()
	verified, err := o.load(ctx, true)
	if err != nil {
		return nil, err
	}
	composeModel, err := generator.NewComposeGeneratorWithLock(
		verified.Config,
		o.Registry,
		verified.Lock,
	).Generate(verified.Graph)
	if err != nil {
		return nil, fmt.Errorf("build diagnostic Compose model: %w", err)
	}
	checks := doctor.NewProjectDoctor(
		o.ProjectDir,
		verified.Config,
		verified.Graph,
		composeModel,
	).RunAll(ctx)
	report := &DiagnosticsReport{
		Healthy: true,
		Checks:  make([]DiagnosticCheck, 0, len(checks)),
	}
	for _, check := range checks {
		status := "failed"
		switch check.Status {
		case doctor.StatusPassed:
			status = "passed"
			report.Summary.Passed++
		case doctor.StatusWarning:
			status = "warning"
		default:
			report.Summary.Failed++
			report.Healthy = false
		}
		report.Checks = append(report.Checks, DiagnosticCheck{
			Name:       check.Name,
			Status:     status,
			Message:    redact.Text(check.Message),
			DurationMS: check.Duration.Milliseconds(),
		})
	}
	report.Summary.Total = len(report.Checks)
	return report, nil
}

func (o *ProjectOperator) Services(ctx context.Context) ([]Service, error) {
	if err := o.gate.Lock(ctx); err != nil {
		return nil, err
	}
	defer o.gate.Unlock()
	verified, err := o.load(ctx, false)
	if err != nil {
		return nil, err
	}
	return o.services(ctx, verified)
}

func (o *ProjectOperator) services(
	ctx context.Context,
	verified *verifiedproject.Verified,
) ([]Service, error) {
	runtimeServices, runtimeErr := docker.NewCompose(o.ProjectDir).PS(ctx)
	byService := make(map[string]docker.Service, len(runtimeServices))
	for _, runtimeService := range runtimeServices {
		name := runtimeService.Service
		if name == "" {
			name = strings.TrimPrefix(runtimeService.Name, "sdbx-")
		}
		byService[name] = runtimeService
	}
	result := make([]Service, 0, len(verified.Graph.Order))
	for _, name := range verified.Graph.Order {
		resolved := verified.Graph.Services[name]
		if resolved == nil || !resolved.Enabled || resolved.FinalDefinition == nil {
			continue
		}
		definition := resolved.FinalDefinition
		status := Service{
			Name:        name,
			Description: definition.Metadata.Description,
			Category:    string(definition.Metadata.Category),
			Status:      "missing",
			Definition:  definition.Metadata.Version,
		}
		if definition.Routing.Enabled {
			status.Route = sdbxrouting.URL(verified.Config, definition)
			status.RouteAuth = string(definition.Routing.Auth.Mode)
		}
		if launcher := definition.Presentation.Launcher; launcher != nil {
			status.Launcher = &ServiceLauncher{
				Enabled:  launcher.Enabled,
				Group:    launcher.Group,
				Icon:     launcher.Icon,
				Subtitle: launcher.Subtitle,
			}
		}
		if runtimeService, ok := byService[name]; ok {
			status.Status = runtimeService.Status
			status.Health = runtimeService.Health
			status.Image = runtimeService.Image
			status.Ports = runtimeService.Ports
			status.Running = runtimeService.Running
			status.Present = true
			status.ExitCode = runtimeService.ExitCode
		}
		result = append(result, status)
	}
	return result, runtimeErr
}

func (o *ProjectOperator) Logs(
	ctx context.Context,
	request LogsRequest,
) (*LogsResult, error) {
	if err := o.gate.Lock(ctx); err != nil {
		return nil, err
	}
	defer o.gate.Unlock()
	verified, err := o.load(ctx, false)
	if err != nil {
		return nil, err
	}
	if request.Service != "" && !verified.Config.ActiveServices[request.Service] {
		return nil, fmt.Errorf("service is not in the active locked graph")
	}
	if request.Tail <= 0 || request.Tail > 1000 {
		return nil, fmt.Errorf("log tail must be between 1 and 1000")
	}
	output, err := docker.NewCompose(o.ProjectDir).LogsBounded(
		ctx,
		request.Service,
		request.Tail,
		false,
		maxManagedLogBytes,
	)
	if err != nil {
		return nil, err
	}
	if len(output) > maxManagedLogBytes {
		return nil, fmt.Errorf("log response exceeds %d-byte limit", maxManagedLogBytes)
	}
	return &LogsResult{
		Service: request.Service,
		Logs:    redact.Text(output),
	}, nil
}

func (o *ProjectOperator) Addons(ctx context.Context) ([]Addon, error) {
	if err := o.gate.Lock(ctx); err != nil {
		return nil, err
	}
	defer o.gate.Unlock()
	verified, err := o.load(ctx, false)
	if err != nil {
		return nil, err
	}
	return o.addons(ctx, verified)
}

func (o *ProjectOperator) addons(
	ctx context.Context,
	verified *verifiedproject.Verified,
) ([]Addon, error) {
	services, err := o.Registry.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]Addon, 0)
	for _, service := range services {
		if !service.IsAddon {
			continue
		}
		result = append(result, Addon{
			Name:        service.Name,
			Description: service.Description,
			Category:    string(service.Category),
			Source:      service.Source,
			Enabled:     verified.Config.IsAddonEnabled(service.Name),
		})
	}
	return result, nil
}

func (o *ProjectOperator) SetAddon(
	ctx context.Context,
	request AddonRequest,
) (*addons.Result, error) {
	if err := o.gate.Lock(ctx); err != nil {
		return nil, err
	}
	defer o.gate.Unlock()
	if request.Confirm != request.Action {
		return nil, fmt.Errorf("exact addon action confirmation is required")
	}
	verified, err := o.load(ctx, true)
	if err != nil {
		return nil, err
	}
	manager := &addons.Manager{
		ProjectDir:    o.ProjectDir,
		Config:        verified.Config,
		Registry:      o.Registry,
		Lock:          verified.Lock,
		CLIVersion:    o.CLIVersion,
		ImageResolver: o.Resolver,
	}
	switch request.Action {
	case "enable":
		return manager.Enable(ctx, request.Name)
	case "disable":
		return manager.Disable(ctx, request.Name)
	default:
		return nil, fmt.Errorf("unsupported addon action")
	}
}

func (o *ProjectOperator) Settings(ctx context.Context) (*Settings, error) {
	if err := o.gate.Lock(ctx); err != nil {
		return nil, err
	}
	defer o.gate.Unlock()
	verified, err := o.load(ctx, false)
	if err != nil {
		return nil, err
	}
	return &Settings{
		Values:    settings.Values(verified.Config),
		Fields:    settings.Fields(),
		ValidKeys: settings.ValidKeys(),
	}, nil
}

func (o *ProjectOperator) SetSetting(
	ctx context.Context,
	request SettingRequest,
) (*settings.Result, error) {
	if err := o.gate.Lock(ctx); err != nil {
		return nil, err
	}
	defer o.gate.Unlock()
	if request.Confirm != "save" {
		return nil, fmt.Errorf("exact setting confirmation is required")
	}
	if brokerReadOnlySettings[request.Key] {
		return nil, fmt.Errorf(
			"managed-root paths are read-only through the broker; use the local CLI or edit .sdbx.yaml and run sdbx generate",
		)
	}
	verified, err := o.load(ctx, true)
	if err != nil {
		return nil, err
	}
	return (&settings.Manager{
		ProjectDir:                o.ProjectDir,
		Config:                    verified.Config,
		Registry:                  o.Registry,
		Lock:                      verified.Lock,
		CLIVersion:                o.CLIVersion,
		ImageResolver:             o.Resolver,
		AllowUnprotectedDownloads: request.ConfirmUnprotectedDownloads,
	}).Set(ctx, request.Key, request.Value)
}

func (o *ProjectOperator) Backups(ctx context.Context) ([]Backup, error) {
	if err := o.gate.Lock(ctx); err != nil {
		return nil, err
	}
	defer o.gate.Unlock()
	if _, err := o.load(ctx, false); err != nil {
		return nil, err
	}
	return listBackups(ctx, o.ProjectDir)
}

func listBackups(ctx context.Context, projectDir string) ([]Backup, error) {
	entries, err := backup.NewManager(projectDir).List(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]Backup, 0, len(entries))
	for _, entry := range entries {
		size, err := entry.GetSize()
		if err != nil {
			return nil, err
		}
		result = append(result, Backup{
			Name:      entry.Name,
			Timestamp: entry.Metadata.Timestamp,
			Size:      size,
		})
	}
	return result, nil
}

func (o *ProjectOperator) CreateBackup(
	ctx context.Context,
	request CreateBackupRequest,
) (*Backup, error) {
	if err := o.gate.Lock(ctx); err != nil {
		return nil, err
	}
	defer o.gate.Unlock()
	verified, err := o.load(ctx, true)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(request.Passphrase)
	created, err := backup.NewManager(o.ProjectDir).CreateWithRoots(
		ctx,
		backup.EncryptOptions{
			Recipient:  request.Recipient,
			Passphrase: request.Passphrase,
		},
		backup.ManagedRoots{
			ConfigPath:  verified.Config.ConfigPath,
			SecretsPath: verified.Config.SecretsPath,
		},
	)
	if err != nil {
		return nil, err
	}
	size, err := created.GetSize()
	if err != nil {
		return nil, err
	}
	return &Backup{
		Name:      created.Name,
		Timestamp: created.Metadata.Timestamp,
		Size:      size,
	}, nil
}

func (o *ProjectOperator) RestoreBackup(
	ctx context.Context,
	request RestoreBackupRequest,
) error {
	if err := o.gate.Lock(ctx); err != nil {
		return err
	}
	defer o.gate.Unlock()
	if request.Confirm != "restore" {
		return fmt.Errorf("exact restore confirmation is required")
	}
	if _, err := o.load(ctx, true); err != nil {
		return err
	}
	defer zeroBytes(request.Passphrase)
	hooks, err := recovery.RestoreHooks(
		ctx,
		o.ProjectDir,
		o.Registry,
		o.CLIVersion,
		request.RelocateManagedRoots,
	)
	if err != nil {
		return err
	}
	if err := backup.NewManager(o.ProjectDir).RestoreWithHooks(
		ctx,
		request.Name,
		backup.DecryptOptions{Passphrase: request.Passphrase},
		hooks,
	); err != nil {
		return err
	}
	return nil
}

func (o *ProjectOperator) DeleteBackup(
	ctx context.Context,
	request DeleteBackupRequest,
) error {
	if err := o.gate.Lock(ctx); err != nil {
		return err
	}
	defer o.gate.Unlock()
	if request.Confirm != "delete" {
		return fmt.Errorf("exact delete confirmation is required")
	}
	if _, err := o.load(ctx, true); err != nil {
		return err
	}
	return backup.NewManager(o.ProjectDir).Delete(ctx, request.Name)
}

func (o *ProjectOperator) Stack(ctx context.Context, request StackRequest) error {
	if err := o.gate.Lock(ctx); err != nil {
		return err
	}
	defer o.gate.Unlock()
	if request.Confirm != request.Action {
		return fmt.Errorf("exact stack action confirmation is required")
	}
	if _, err := o.load(ctx, true); err != nil {
		return err
	}
	compose := docker.NewCompose(o.ProjectDir)
	switch request.Action {
	case "up":
		return compose.Up(ctx)
	case "down":
		return compose.Down(ctx)
	case "restart":
		return compose.Restart(ctx, "")
	default:
		return fmt.Errorf("unsupported stack action")
	}
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
