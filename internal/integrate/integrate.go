package integrate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/redact"
	"github.com/get-sdbx/sdbx/internal/registry"
	"github.com/get-sdbx/sdbx/internal/routing"
	sdbxsecrets "github.com/get-sdbx/sdbx/internal/secrets"
)

// Integrator orchestrates service integrations
type Integrator struct {
	config          *Config
	httpClient      *HTTPClient
	services        map[string]*ServiceConfig
	restart         func(context.Context, string) error
	stop            func(context.Context, string) error
	start           func(context.Context, string) error
	wizarrReconcile func(context.Context, string, string, bool) error
}

// NewIntegrator creates a new integrator
func NewIntegrator(cfg *Config) *Integrator {
	integrator := &Integrator{
		config:     cfg,
		httpClient: NewHTTPClient(cfg.Timeout, cfg.RetryAttempts, cfg.RetryDelay),
		services:   cfg.Services,
		restart: func(ctx context.Context, service string) error {
			if err := dockerComposeStop(ctx, service); err != nil {
				return err
			}
			return dockerComposeStart(ctx, service)
		},
	}
	integrator.stop = dockerComposeStop
	integrator.start = dockerComposeStart
	integrator.wizarrReconcile = reconcileWizarrState
	return integrator
}

// Run executes all integrations.
//
// Two-phase: API-driven integrators (Prowlarr ↔ *arrs, qBT ↔ *arrs) require
// access to the app and download trust boundaries. The Linux host command
// rewrites verified Docker-DNS endpoints to inspected bridge addresses before
// constructing the Integrator. An explicit in-cluster runner keeps Docker-DNS
// endpoints unchanged.
func (i *Integrator) Run(ctx context.Context) ([]*IntegrationResult, error) {
	results := make([]*IntegrationResult, 0)

	var decluttarrResult *DecluttarrConfigResult
	var decluttarrErr error
	if IsServiceEnabled(i.config.ProjectConfig, "decluttarr") {
		decluttarrResult, decluttarrErr = ReconcileDecluttarrConfig(
			i.config.ProjectConfig,
			i.config.Graph,
			i.config.DryRun,
		)
	}
	if decluttarrResult != nil || decluttarrErr != nil {
		result := &IntegrationResult{
			Service: "decluttarr",
			Success: decluttarrErr == nil,
		}
		if decluttarrResult != nil {
			result.Message = decluttarrResult.Action
			if decluttarrResult.Reason != "" {
				result.Message += ": " + decluttarrResult.Reason
			}
		}
		if decluttarrErr != nil {
			result.Message = "managed configuration reconciliation failed"
			result.Error = decluttarrErr
		}
		results = append(results, result)
		if decluttarrErr != nil {
			return results, nil
		}
	}

	var janitorrResult *JanitorrConfigResult
	var janitorrErr error
	if IsServiceEnabled(i.config.ProjectConfig, "janitorr") {
		janitorrResult, janitorrErr = ReconcileJanitorrConfig(
			i.config.ProjectConfig,
			i.config.Graph,
			i.config.DryRun,
		)
	}
	if janitorrResult != nil || janitorrErr != nil {
		result := &IntegrationResult{
			Service: "janitorr",
			Success: janitorrErr == nil,
		}
		if janitorrResult != nil {
			result.Message = janitorrResult.Action
			if janitorrResult.Reason != "" {
				result.Message += ": " + janitorrResult.Reason
			}
		}
		if janitorrErr != nil {
			result.Message = "managed configuration reconciliation failed"
			result.Error = janitorrErr
		}
		results = append(results, result)
		if janitorrErr != nil {
			return results, nil
		}
	}

	var recyclarrResult *AddonConfigResult
	var recyclarrErr error
	if IsServiceEnabled(i.config.ProjectConfig, "recyclarr") {
		recyclarrResult, recyclarrErr = ReconcileRecyclarrConfig(
			i.config.ProjectConfig,
			i.config.Graph,
			i.config.DryRun,
		)
	}
	if result := addonConfigIntegrationResult(
		"recyclarr",
		recyclarrResult,
		recyclarrErr,
	); result != nil {
		results = append(results, result)
		if recyclarrErr != nil {
			return results, nil
		}
	}

	var qbitManageResult *AddonConfigResult
	var qbitManageErr error
	if IsServiceEnabled(i.config.ProjectConfig, "qbit-manage") {
		qbitManageResult, qbitManageErr = ReconcileQbitManageConfig(
			i.config.ProjectConfig,
			i.config.DryRun,
		)
	}
	if result := addonConfigIntegrationResult(
		"qbit-manage",
		qbitManageResult,
		qbitManageErr,
	); result != nil {
		results = append(results, result)
		if qbitManageErr != nil {
			return results, nil
		}
	}

	if i.config.DryRun {
		results = append(results, i.reconcileArrAuthentication(ctx)...)
		integrationResults, err := i.runIntegrators(ctx)
		return append(results, integrationResults...), err
	}
	needsAPIIntegrations := i.needsNetworkIntegrations()
	needsArrAuthentication := i.needsArrAuthentication()
	if !needsAPIIntegrations && !needsArrAuthentication {
		return results, nil
	}

	runtimeResults := i.reconcileArrRuntimeState(ctx)
	results = append(results, runtimeResults...)
	for _, result := range runtimeResults {
		if !result.Success {
			return results, nil
		}
	}

	// Probe a single representative service before committing to the full
	// 30s wait. If the probe fails, we're almost certainly running outside
	// the docker network and the legacy integrators won't work.
	if !i.config.InCluster && !i.integrationEndpointsReachable(ctx) {
		results = append(results, &IntegrationResult{
			Service: "prowlarr/qBT ↔ *arrs",
			Success: false,
			Message: "Linux host could not reach the inspected container endpoints; use --in-cluster only from a trusted runner attached to both project networks",
		})
		return results, nil
	}

	if err := i.waitForServices(ctx); err != nil {
		results = append(results, &IntegrationResult{
			Service: "service health",
			Success: false,
			Message: redact.Text(err.Error()),
		})
		return results, nil
	}
	if needsArrAuthentication {
		authResults := i.reconcileArrAuthentication(ctx)
		results = append(results, authResults...)
		for _, result := range authResults {
			if !result.Success {
				return results, nil
			}
		}
	}
	if !needsAPIIntegrations {
		return results, nil
	}
	integrationResults, err := i.runIntegrators(ctx)
	return append(results, integrationResults...), err
}

func (i *Integrator) needsNetworkIntegrations() bool {
	if i.hasService("tautulli") &&
		IsServiceEnabled(i.config.ProjectConfig, "plex") {
		return true
	}
	if i.hasService("prowlarr") && i.hasService("flaresolverr") {
		return true
	}
	if i.hasService("profilarr") &&
		(i.hasService("radarr") || i.hasService("sonarr")) {
		return true
	}
	if i.hasService("wizarr") && i.hasService("plex") {
		return true
	}
	hasArr := i.hasService("sonarr") ||
		i.hasService("radarr") ||
		i.hasService("lidarr") ||
		i.hasService("whisparr")
	if !hasArr {
		return false
	}
	if i.hasService("plex") {
		return true
	}
	return i.hasService("prowlarr") || i.hasService("qbittorrent") ||
		i.hasService("seerr") || i.hasService("bazarr") ||
		i.hasService("maintainerr") || i.hasService("qui")
}

func (i *Integrator) needsArrAuthentication() bool {
	if i.config.ProjectConfig == nil {
		return false
	}
	for _, spec := range arrManagedAuthSpecs {
		if i.hasService(spec.name) {
			return true
		}
	}
	return false
}

// runIntegrators kicks off prowlarr + qBT integrators (the API-driven ones).
func (i *Integrator) runIntegrators(ctx context.Context) ([]*IntegrationResult, error) {
	results := make([]*IntegrationResult, 0)
	if i.hasService("seerr") {
		results = append(results, i.integrateSeerr(ctx)...)
	}
	if i.hasService("bazarr") {
		results = append(results, i.integrateBazarr(ctx))
	}
	if i.hasService("tautulli") {
		results = append(results, i.integrateTautulli(ctx))
	}
	if i.hasService("profilarr") {
		results = append(results, i.integrateProfilarr(ctx)...)
	}
	if i.hasService("wizarr") {
		results = append(results, i.integrateWizarr(ctx))
	}
	if i.hasService("maintainerr") {
		results = append(results, i.integrateMaintainerr(ctx)...)
	}
	if i.hasService("qui") {
		results = append(results, i.integrateQui(ctx)...)
	}
	if i.hasService("prowlarr") {
		results = append(results, i.integrateProwlarr(ctx)...)
	}
	if i.hasService("qbittorrent") {
		results = append(results, i.integrateQBittorrent(ctx)...)
	}
	if i.hasService("plex") {
		results = append(results, i.integrateArrPlexNotifications(ctx)...)
	}
	return results, nil
}

// integrationEndpointsReachable returns true if at least one enabled service
// responds to a quick authenticated probe. Fast-fails in three seconds so a
// host firewall or unsupported rootless network does not trigger the full
// retry window.
func (i *Integrator) integrationEndpointsReachable(ctx context.Context) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Probe a deterministic API integration endpoint. Unrelated enabled
	// services intentionally return nil from checkServiceHealth, so selecting
	// an arbitrary map entry could falsely claim Docker DNS was reachable.
	for _, name := range []string{
		"seerr",
		"bazarr",
		"maintainerr",
		"qui",
		"tautulli",
		"flaresolverr",
		"profilarr",
		"plex",
		"wizarr",
		"prowlarr",
		"sonarr",
		"radarr",
		"lidarr",
		"whisparr",
		"qbittorrent",
	} {
		svc, exists := i.services[name]
		if !exists || svc == nil || !svc.Enabled {
			continue
		}
		if err := i.checkServiceHealth(probeCtx, name, svc); err == nil {
			return true
		}
		// One failed probe is decisive — don't keep retrying.
		return false
	}
	return false
}

// waitForServices waits for all services to be ready, capped at 30s total.
func (i *Integrator) waitForServices(ctx context.Context) error {
	timeout := 30 * time.Second

	for _, name := range sortedEnabledServiceNames(i.services) {
		svc := i.services[name]
		if !svc.Enabled {
			continue
		}

		if i.config.Verbose {
			fmt.Printf("Waiting for %s to be ready...\n", name)
		}

		deadline := time.Now().Add(timeout)
		ready := false
		for time.Now().Before(deadline) {
			if err := i.checkServiceHealth(ctx, name, svc); err == nil {
				if i.config.Verbose {
					fmt.Printf("✓ %s is ready\n", name)
				}
				ready = true
				break
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
				// Retry
			}
		}

		if !ready {
			return fmt.Errorf("timeout waiting for %s", name)
		}
	}

	return nil
}

// reconcileArrRuntimeState repairs the common generate-while-running split
// brain: config.xml contains the new API key/auth policy, while the running
// process still holds the previous values. Only an authenticated rejection
// triggers a bounded restart; network failures remain diagnostic failures and
// never cause restart loops.
func (i *Integrator) reconcileArrRuntimeState(
	ctx context.Context,
) []*IntegrationResult {
	results := make([]*IntegrationResult, 0)
	for _, name := range []string{
		"prowlarr", "sonarr", "radarr", "lidarr", "whisparr",
	} {
		service := i.services[name]
		if service == nil || !service.Enabled {
			continue
		}
		if err := i.checkServiceHealth(ctx, name, service); err == nil {
			continue
		} else if !isAuthenticationRejection(err) {
			continue
		}

		result := &IntegrationResult{
			Service: name + " runtime authentication",
			Success: false,
			Message: "Failed to reload application authentication configuration",
		}
		if i.restart == nil {
			result.Error = fmt.Errorf("service restart handler is unavailable")
			results = append(results, result)
			continue
		}
		if err := i.restart(ctx, name); err != nil {
			result.Error = err
			results = append(results, result)
			continue
		}

		deadline := time.Now().Add(60 * time.Second)
		var healthErr error
		for time.Now().Before(deadline) {
			healthErr = i.checkServiceHealth(ctx, name, service)
			if healthErr == nil {
				break
			}
			select {
			case <-ctx.Done():
				healthErr = ctx.Err()
				deadline = time.Time{}
			case <-time.After(time.Second):
			}
		}
		if healthErr != nil {
			result.Error = healthErr
			results = append(results, result)
			continue
		}
		result.Success = true
		result.Message = "Reloaded and verified application authentication configuration"
		results = append(results, result)
	}
	return results
}

func isAuthenticationRejection(err error) bool {
	var statusErr *HTTPStatusError
	return errors.As(err, &statusErr) &&
		(statusErr.StatusCode == http.StatusUnauthorized ||
			statusErr.StatusCode == http.StatusForbidden)
}

func sortedEnabledServiceNames(services map[string]*ServiceConfig) []string {
	names := make([]string, 0, len(services))
	for name, service := range services {
		if service != nil && service.Enabled {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// checkServiceHealth checks if a service is healthy
func (i *Integrator) checkServiceHealth(ctx context.Context, name string, svc *ServiceConfig) error {
	controlConfig := serviceControlConfig(svc)
	switch name {
	case "prowlarr":
		client := NewProwlarrClient(i.httpClient, controlConfig)
		return client.CheckHealth(ctx)
	case "sonarr", "radarr", "lidarr", "whisparr":
		client := NewArrClient(i.httpClient, controlConfig)
		return client.CheckHealth(ctx)
	case "qbittorrent":
		qbitCfg := &QBittorrentConfig{
			Host:     controlConfig.URL,
			Port:     8080,
			Username: "admin",
			Password: svc.APIKey,
		}
		client := NewQBittorrentClient(i.httpClient, qbitCfg)
		if err := client.Login(ctx); err != nil {
			return err
		}
		return client.CheckHealth(ctx)
	case "seerr":
		client := NewSeerrClient(i.httpClient, controlConfig)
		return client.CheckHealth(ctx)
	case "bazarr":
		client := NewBazarrClient(i.httpClient, controlConfig)
		_, err := client.GetSettings(ctx)
		return err
	case "maintainerr":
		client := newMaintainerrClient(i.httpClient, controlConfig)
		return client.check(ctx)
	case "qui":
		client := newQuiClient(i.httpClient, controlConfig)
		_, err := client.setupState(ctx)
		return err
	case "tautulli":
		_, err := i.httpClient.Get(ctx, strings.TrimRight(controlConfig.URL, "/")+"/", nil)
		return err
	case "flaresolverr":
		_, err := i.httpClient.Get(ctx, strings.TrimRight(controlConfig.URL, "/")+"/health", nil)
		return err
	case "profilarr":
		client := newProfilarrClient(i.httpClient, controlConfig)
		return client.health(ctx)
	case "plex":
		return verifyPlexConnection(ctx, i.httpClient, svc)
	case "wizarr":
		_, err := i.httpClient.Get(ctx, strings.TrimRight(controlConfig.URL, "/")+"/", nil)
		return err
	default:
		return nil
	}
}

func (i *Integrator) integrateSeerr(ctx context.Context) []*IntegrationResult {
	results := make([]*IntegrationResult, 0, 3)
	seerr := NewSeerrClient(
		i.httpClient,
		serviceControlConfig(i.services["seerr"]),
	)
	if plex := i.services["plex"]; plex != nil && plex.Enabled {
		results = append(results, i.integrateSeerrPlex(ctx, seerr, plex))
	}
	for _, kind := range []string{"radarr", "sonarr"} {
		service := i.services[kind]
		if service == nil || !service.Enabled {
			continue
		}
		result := &IntegrationResult{
			Service: "seerr → " + kind,
			Success: false,
		}
		desired, err := seerrDesiredConnection(kind, service)
		if err != nil {
			result.Message = "Failed to build managed connection"
			result.Error = err
			results = append(results, result)
			continue
		}
		existingServices, err := seerr.GetServices(ctx, kind)
		if err != nil {
			result.Message = "Failed to read existing connection"
			result.Error = err
			results = append(results, result)
			continue
		}
		var existing map[string]any
		for _, candidate := range existingServices {
			if strings.EqualFold(fmt.Sprint(candidate["name"]), kind) {
				existing = candidate
				break
			}
		}
		if existing == nil {
			discovery, testErr := seerr.TestService(ctx, kind, desired)
			if testErr != nil {
				result.Message = "New managed connection failed its preflight test"
				result.Error = testErr
				results = append(results, result)
				continue
			}
			createdSettings, buildErr := seerrNewServiceSettings(kind, desired, discovery)
			if buildErr != nil {
				result.Message = "New managed connection has no safe default profile or root folder"
				result.Error = buildErr
				results = append(results, result)
				continue
			}
			if i.config.DryRun {
				result.Success = true
				result.Message = "[DRY RUN] Would create and verify managed connection"
				results = append(results, result)
				continue
			}
			if addErr := seerr.AddService(ctx, kind, createdSettings); addErr != nil {
				result.Message = "Failed to create managed connection"
				result.Error = addErr
				results = append(results, result)
				continue
			}
			createdServices, readErr := seerr.GetServices(ctx, kind)
			if readErr != nil {
				result.Message = "Created managed connection but could not read it back"
				result.Error = readErr
				results = append(results, result)
				continue
			}
			var created map[string]any
			for _, candidate := range createdServices {
				if strings.EqualFold(fmt.Sprint(candidate["name"]), kind) &&
					seerrConnectionMatches(candidate, desired) {
					created = candidate
					break
				}
			}
			if created == nil {
				result.Message = "Created managed connection did not match read-back state"
				result.Error = fmt.Errorf("Seerr %s connection read-back mismatch", kind)
				results = append(results, result)
				continue
			}
			if _, verifyErr := seerr.TestService(ctx, kind, createdSettings); verifyErr != nil {
				createdID := seerrSettingsID(created)
				if createdID >= 0 {
					_ = seerr.DeleteService(ctx, kind, createdID)
				}
				result.Message = "Created managed connection failed verification and was rolled back"
				result.Error = verifyErr
				results = append(results, result)
				continue
			}
			result.Success = true
			result.Message = "Created and verified"
			results = append(results, result)
			continue
		}
		merged := mergeSeerrSettings(existing, desired)
		_, testErr := seerr.TestService(ctx, kind, merged)
		if seerrConnectionMatches(existing, desired) && testErr == nil {
			result.Success = true
			result.Message = "Already configured and verified"
			results = append(results, result)
			continue
		}
		if testErr != nil {
			result.Message = "Managed connection failed its preflight test"
			result.Error = testErr
			results = append(results, result)
			continue
		}
		if i.config.DryRun {
			result.Success = true
			result.Message = "[DRY RUN] Would repair managed connection"
			results = append(results, result)
			continue
		}
		updated, err := seerr.UpdateService(
			ctx,
			kind,
			seerrSettingsID(existing),
			seerrWritableServiceSettings(merged),
		)
		if err != nil {
			result.Message = "Failed to repair managed connection"
			result.Error = err
			results = append(results, result)
			continue
		}
		if !seerrConnectionMatches(updated, desired) {
			result.Message = "Repaired connection failed read-back verification"
			result.Error = fmt.Errorf("Seerr %s connection read-back mismatch", kind)
			results = append(results, result)
			continue
		}
		if _, err := seerr.TestService(ctx, kind, updated); err != nil {
			result.Message = "Repaired connection failed verification"
			result.Error = err
			results = append(results, result)
			continue
		}
		result.Success = true
		result.Message = "Repaired and verified"
		results = append(results, result)
	}
	return results
}

func (i *Integrator) integrateSeerrPlex(
	ctx context.Context,
	seerr *SeerrClient,
	plex *ServiceConfig,
) *IntegrationResult {
	result := &IntegrationResult{Service: "seerr → plex"}
	desired, err := seerrDesiredPlexConnection(plex)
	if err != nil {
		result.Message, result.Error = "Failed to build managed Plex connection", err
		return result
	}
	current, err := seerr.GetPlexSettings(ctx)
	if err != nil {
		result.Message, result.Error = "Failed to read Plex connection", err
		return result
	}
	if err := verifyPlexConnection(ctx, i.httpClient, plex); err != nil {
		result.Message, result.Error = "Managed Plex endpoint failed preflight", err
		return result
	}
	if seerrPlexConnectionMatches(current, desired) {
		result.Success = true
		result.Message = "Already configured and stable Plex endpoint verified"
		return result
	}
	if i.config.DryRun {
		result.Success = true
		result.Message = "[DRY RUN] Would repair managed Plex connection"
		return result
	}
	updated, err := seerr.UpdatePlexSettings(
		ctx,
		desired,
	)
	if err != nil {
		result.Message, result.Error = "Failed to repair managed Plex connection", err
		return result
	}
	if !seerrPlexConnectionMatches(updated, desired) ||
		!seerrPlexOperatorSettingsPreserved(current, updated) {
		result.Message = "Repaired Plex connection failed read-back verification"
		result.Error = fmt.Errorf("Seerr Plex connection read-back mismatch")
		return result
	}
	result.Success = true
	result.Message = "Repaired and verified through Seerr"
	return result
}

func serviceControlConfig(service *ServiceConfig) *ServiceConfig {
	if service == nil || service.ControlURL == "" {
		return service
	}
	control := *service
	control.URL = service.ControlURL
	return &control
}

// integrateProwlarr integrates Prowlarr with *arr apps
func (i *Integrator) integrateProwlarr(ctx context.Context) []*IntegrationResult {
	results := make([]*IntegrationResult, 0)

	prowlarrSvc := i.services["prowlarr"]
	prowlarr := NewProwlarrClient(i.httpClient, serviceControlConfig(prowlarrSvc))
	if i.hasService("flaresolverr") {
		results = append(results, i.integrateFlaresolverr(ctx, prowlarr))
	}

	// Get existing applications
	existingApps, err := prowlarr.GetApplications(ctx)
	if err != nil {
		results = append(results, &IntegrationResult{
			Service: "prowlarr",
			Success: false,
			Message: "Failed to get existing applications",
			Error:   err,
		})
		return results
	}

	// Prowlarr canonicalises display names with leading capital ("Sonarr",
	// "Radarr", "Lidarr"), but our internal addon names are lowercase. Index
	// existing apps under the lowercase form so the idempotency check hits
	// regardless of who wrote the original entry (sdbx vs the WebUI).
	existingNames := make(map[string]*ProwlarrApplication)
	for idx := range existingApps {
		existingNames[strings.ToLower(existingApps[idx].Name)] = &existingApps[idx]
	}

	// Integrate with each *arr app
	arrApps := []string{"sonarr", "radarr", "lidarr", "whisparr"}
	for _, appName := range arrApps {
		if !i.hasService(appName) {
			continue
		}

		svc := i.services[appName]
		result := i.addProwlarrApplication(
			ctx,
			prowlarr,
			prowlarrSvc.URL,
			appName,
			svc,
			existingNames,
		)
		results = append(results, result)
	}

	return results
}

func (i *Integrator) integrateFlaresolverr(
	ctx context.Context,
	prowlarr *ProwlarrClient,
) *IntegrationResult {
	result := &IntegrationResult{Service: "prowlarr → flaresolverr"}
	service := i.services["flaresolverr"]
	desired := map[string]any{
		"name":                  "FlareSolverr",
		"implementation":        "FlareSolverr",
		"implementationName":    "FlareSolverr",
		"configContract":        "FlareSolverrSettings",
		"includeHealthWarnings": true,
		"onHealthIssue":         0,
		"tags":                  []int{},
		"fields": []map[string]any{
			{"name": "host", "value": strings.TrimRight(service.URL, "/") + "/"},
			{"name": "requestTimeout", "value": 60},
		},
	}
	proxies, err := prowlarr.GetIndexerProxies(ctx)
	if err != nil {
		result.Message, result.Error = "Failed to inspect indexer proxies", err
		return result
	}
	var current map[string]any
	for _, proxy := range proxies {
		if strings.EqualFold(fmt.Sprint(proxy["name"]), "FlareSolverr") &&
			strings.EqualFold(fmt.Sprint(proxy["implementation"]), "FlareSolverr") {
			current = proxy
			break
		}
	}
	merged := desired
	id := 0
	if current != nil {
		merged = mergeManagedMap(current, desired)
		id = intFromAny(current["id"])
	}
	if err := prowlarr.TestIndexerProxy(ctx, merged); err != nil {
		result.Message, result.Error = "Managed proxy failed preflight", err
		return result
	}
	if current != nil && managedMapField(current, "host") == managedMapField(desired, "host") {
		result.Success, result.Message = true, "Already configured and verified"
		return result
	}
	if i.config.DryRun {
		result.Success, result.Message = true, "[DRY RUN] Would repair managed proxy"
		return result
	}
	if err := prowlarr.SaveIndexerProxy(ctx, id, merged); err != nil {
		result.Message, result.Error = "Failed to repair managed proxy", err
		return result
	}
	if err := i.verifyProwlarrIndexerProxy(ctx, prowlarr, merged); err != nil {
		result.Message, result.Error = "Repaired proxy failed verification", err
		return result
	}
	result.Success, result.Message = true, "Repaired and verified"
	return result
}

func (i *Integrator) verifyProwlarrIndexerProxy(
	ctx context.Context,
	prowlarr *ProwlarrClient,
	proxy map[string]any,
) error {
	var lastErr error
	for attempt := 0; attempt <= i.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(i.config.RetryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		if err := prowlarr.TestIndexerProxy(ctx, proxy); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}

func mergeManagedMap(current, desired map[string]any) map[string]any {
	merged := make(map[string]any, len(current)+len(desired))
	for key, value := range current {
		merged[key] = value
	}
	for key, value := range desired {
		merged[key] = value
	}
	return merged
}

func managedMapField(value map[string]any, name string) string {
	fields, _ := value["fields"].([]any)
	for _, raw := range fields {
		field, _ := raw.(map[string]any)
		if fmt.Sprint(field["name"]) == name {
			return fmt.Sprint(field["value"])
		}
	}
	if typed, ok := value["fields"].([]map[string]any); ok {
		for _, field := range typed {
			if fmt.Sprint(field["name"]) == name {
				return fmt.Sprint(field["value"])
			}
		}
	}
	return ""
}

func intFromAny(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case float64:
		return int(typed)
	default:
		parsed, _ := strconv.Atoi(fmt.Sprint(value))
		return parsed
	}
}

// addProwlarrApplication adds or updates a *arr app in Prowlarr
func (i *Integrator) addProwlarrApplication(
	ctx context.Context,
	prowlarr *ProwlarrClient,
	prowlarrURL string,
	appName string,
	svc *ServiceConfig,
	existing map[string]*ProwlarrApplication,
) *IntegrationResult {
	// Build the desired stable service-to-service configuration before
	// inspecting the existing entry. A matching display name is not proof that
	// its URL, API key, or sync policy still works.
	var app *ProwlarrApplication
	syncLevel := "fullSync"

	switch appName {
	case "sonarr":
		app = CreateSonarrApplication(appName, prowlarrURL, svc.URL, svc.APIKey, syncLevel)
	case "radarr":
		app = CreateRadarrApplication(appName, prowlarrURL, svc.URL, svc.APIKey, syncLevel)
	case "lidarr":
		app = CreateLidarrApplication(appName, prowlarrURL, svc.URL, svc.APIKey, syncLevel)
	case "whisparr":
		app = CreateWhisparrApplication(appName, prowlarrURL, svc.URL, svc.APIKey, syncLevel)
	default:
		return &IntegrationResult{
			Service: fmt.Sprintf("prowlarr → %s", appName),
			Success: false,
			Message: "Unsupported application type",
			Error:   fmt.Errorf("unknown app: %s", appName),
		}
	}

	if existingApp, exists := existing[strings.ToLower(appName)]; exists {
		matches := prowlarrApplicationMatches(existingApp, app)
		if matches && prowlarr.TestApplication(ctx, existingApp) == nil {
			return &IntegrationResult{
				Service: fmt.Sprintf("prowlarr → %s", appName),
				Success: true,
				Message: fmt.Sprintf("Already configured and verified (ID: %d)", existingApp.ID),
			}
		}
		if i.config.DryRun {
			return &IntegrationResult{
				Service: fmt.Sprintf("prowlarr → %s", appName),
				Success: true,
				Message: "[DRY RUN] Would repair managed application",
			}
		}
		repaired := mergeManagedProwlarrApplication(existingApp, app)
		if err := prowlarr.UpdateApplication(ctx, repaired); err != nil {
			return &IntegrationResult{
				Service: fmt.Sprintf("prowlarr → %s", appName),
				Success: false,
				Message: "Failed to repair managed application",
				Error:   err,
			}
		}
		if err := prowlarr.TestApplication(ctx, repaired); err != nil {
			return &IntegrationResult{
				Service: fmt.Sprintf("prowlarr → %s", appName),
				Success: false,
				Message: "Repaired application failed its connection test",
				Error:   err,
			}
		}
		return &IntegrationResult{
			Service: fmt.Sprintf("prowlarr → %s", appName),
			Success: true,
			Message: fmt.Sprintf("Repaired and verified (ID: %d)", existingApp.ID),
		}
	}

	// Add application
	if i.config.DryRun {
		return &IntegrationResult{
			Service: fmt.Sprintf("prowlarr → %s", appName),
			Success: true,
			Message: "[DRY RUN] Would add application",
			Error:   nil,
		}
	}

	result, err := prowlarr.AddApplication(ctx, app)
	if err != nil {
		return &IntegrationResult{
			Service: fmt.Sprintf("prowlarr → %s", appName),
			Success: false,
			Message: "Failed to add application",
			Error:   err,
		}
	}
	if err := prowlarr.TestApplication(ctx, result); err != nil {
		return &IntegrationResult{
			Service: fmt.Sprintf("prowlarr → %s", appName),
			Success: false,
			Message: "Added application failed its connection test",
			Error:   err,
		}
	}

	return &IntegrationResult{
		Service: fmt.Sprintf("prowlarr → %s", appName),
		Success: true,
		Message: fmt.Sprintf("Added successfully (ID: %d)", result.ID),
		Error:   nil,
	}
}

func prowlarrApplicationMatches(existing, desired *ProwlarrApplication) bool {
	if existing == nil || desired == nil ||
		!strings.EqualFold(existing.Name, desired.Name) ||
		!strings.EqualFold(existing.Implementation, desired.Implementation) ||
		existing.SyncLevel != desired.SyncLevel ||
		!existing.Enable {
		return false
	}
	for _, name := range []string{"prowlarrUrl", "baseUrl"} {
		existingValue, existingFound := prowlarrField(existing, name)
		desiredValue, desiredFound := prowlarrField(desired, name)
		if !existingFound || !desiredFound || existingValue != desiredValue {
			return false
		}
	}
	return true
}

func mergeManagedProwlarrApplication(
	existing, desired *ProwlarrApplication,
) *ProwlarrApplication {
	merged := *existing
	merged.Name = desired.Name
	merged.Enable = true
	merged.SyncLevel = desired.SyncLevel
	merged.Implementation = desired.Implementation
	merged.ConfigContract = desired.ConfigContract
	merged.Fields = append([]ProwlarrField(nil), existing.Fields...)
	for _, field := range desired.Fields {
		setProwlarrField(&merged, field.Name, field.Value)
	}
	return &merged
}

func setProwlarrField(application *ProwlarrApplication, name string, value any) {
	for index := range application.Fields {
		if application.Fields[index].Name == name {
			application.Fields[index].Value = value
			return
		}
	}
	application.Fields = append(application.Fields, ProwlarrField{
		Name:  name,
		Value: value,
	})
}

func prowlarrField(application *ProwlarrApplication, name string) (string, bool) {
	for _, field := range application.Fields {
		if field.Name == name {
			return fmt.Sprint(field.Value), true
		}
	}
	return "", false
}

// integrateQBittorrent integrates qBittorrent with *arr apps
func (i *Integrator) integrateQBittorrent(ctx context.Context) []*IntegrationResult {
	results := make([]*IntegrationResult, 0)

	qbitSvc := i.services["qbittorrent"]
	qbitControlCfg := &QBittorrentConfig{
		Host:     serviceControlConfig(qbitSvc).URL,
		Port:     8080,
		Username: "admin",
		Password: qbitSvc.APIKey,
	}
	qbitInternalCfg := &QBittorrentConfig{
		Host:     qbitSvc.URL,
		Port:     8080,
		Username: "admin",
		Password: qbitSvc.APIKey,
	}
	qbit := NewQBittorrentClient(i.httpClient, qbitControlCfg)

	// Authentication is read-only and required even in dry-run mode so the
	// preview can distinguish a safe empty-category repair from a category
	// that already owns active torrents.
	if err := qbit.Login(ctx); err != nil {
		results = append(results, &IntegrationResult{
			Service: "qbittorrent",
			Success: false,
			Message: "Failed to login",
			Error:   err,
		})
		return results
	}

	automaticManagement := i.reconcileQBittorrentAutomaticManagement(ctx, qbit)
	results = append(results, automaticManagement)

	// Integrate with each *arr app
	arrApps := []string{"sonarr", "radarr", "lidarr", "whisparr"}
	for _, appName := range arrApps {
		if !i.hasService(appName) {
			continue
		}

		svc := i.services[appName]
		results = append(results, i.reconcileQBittorrentCategory(
			ctx,
			qbit,
			appName,
		))
		result := i.addQBittorrentToArr(ctx, qbit, appName, svc, qbitInternalCfg)
		results = append(results, result)
	}

	return results
}

func (i *Integrator) reconcileQBittorrentAutomaticManagement(
	ctx context.Context,
	qbit *QBittorrentClient,
) *IntegrationResult {
	result := &IntegrationResult{
		Service: "qbittorrent automatic category paths",
		Success: false,
	}
	preferences, err := qbit.GetPreferences(ctx)
	if err != nil {
		result.Message = "Failed to inspect automatic torrent management"
		result.Error = err
		return result
	}
	if enabled, ok := preferences["auto_tmm_enabled"].(bool); ok && enabled {
		result.Success = true
		result.Message = "Automatic category paths already enabled for new torrents"
		return result
	}
	if i.config.DryRun {
		result.Success = true
		result.Message = "[DRY RUN] Would enable automatic category paths for new torrents"
		return result
	}
	// This changes only the default for torrents added after reconciliation.
	// Never toggle management on existing torrents: doing so can relocate their
	// payloads to category paths and invalidate operator-managed resume state.
	if err := qbit.SetPreferences(ctx, map[string]interface{}{
		"auto_tmm_enabled": true,
	}); err != nil {
		result.Message = "Failed to enable automatic category paths for new torrents"
		result.Error = err
		return result
	}
	preferences, err = qbit.GetPreferences(ctx)
	if err != nil {
		result.Message = "Failed to verify automatic torrent management"
		result.Error = err
		return result
	}
	if enabled, ok := preferences["auto_tmm_enabled"].(bool); !ok || !enabled {
		result.Message = "Automatic torrent management failed read-back verification"
		result.Error = fmt.Errorf("qBittorrent automatic category paths remain disabled")
		return result
	}
	result.Success = true
	result.Message = "Enabled automatic category paths for new torrents"
	return result
}

func (i *Integrator) reconcileQBittorrentCategory(
	ctx context.Context,
	qbit *QBittorrentClient,
	appName string,
) *IntegrationResult {
	result := &IntegrationResult{
		Service: "qbittorrent category " + appName,
		Success: false,
	}
	desiredPath := qbtCategorySavePath(appName)
	categories, err := qbit.GetCategories(ctx)
	if err != nil {
		result.Message = "Failed to inspect category"
		result.Error = err
		return result
	}
	category, exists := categories[appName]
	if !exists {
		if i.config.DryRun {
			result.Success = true
			result.Message = "[DRY RUN] Would create category with managed save path"
			return result
		}
		if err := qbit.CreateCategory(ctx, appName, desiredPath); err != nil {
			result.Message = "Failed to create category"
			result.Error = err
			return result
		}
		result.Success = true
		result.Message = "Created category with managed save path"
		return result
	}
	if category.SavePath == desiredPath {
		result.Success = true
		result.Message = "Managed save path already configured"
		return result
	}
	count, err := qbit.CountTorrentsInCategory(ctx, appName)
	if err != nil {
		result.Message = "Failed to prove category is unused"
		result.Error = err
		return result
	}
	if count > 0 {
		result.Success = true
		result.Message = fmt.Sprintf(
			"Preserved existing save path because %d torrent(s) use the category",
			count,
		)
		return result
	}
	if i.config.DryRun {
		result.Success = true
		result.Message = "[DRY RUN] Would update unused category save path"
		return result
	}
	if err := qbit.EditCategory(ctx, appName, desiredPath); err != nil {
		result.Message = "Failed to update unused category save path"
		result.Error = err
		return result
	}
	result.Success = true
	result.Message = "Updated unused category save path"
	return result
}

func qbtCategorySavePath(appName string) string {
	switch appName {
	case "sonarr":
		return "/downloads/tv"
	case "radarr":
		return "/downloads/movies"
	case "lidarr":
		return "/downloads/music"
	case "whisparr":
		return "/downloads/stash"
	default:
		return "/downloads/other"
	}
}

// addQBittorrentToArr adds qBittorrent as download client to *arr app
func (i *Integrator) addQBittorrentToArr(ctx context.Context, qbit *QBittorrentClient, appName string, arrSvc *ServiceConfig, qbitCfg *QBittorrentConfig) *IntegrationResult {
	arr := NewArrClient(i.httpClient, serviceControlConfig(arrSvc))

	// Get existing download clients
	existingClients, err := arr.GetDownloadClients(ctx)
	if err != nil {
		return &IntegrationResult{
			Service: fmt.Sprintf("%s → qbittorrent", appName),
			Success: false,
			Message: "Failed to get download clients",
			Error:   err,
		}
	}

	// Build the stable service-to-service configuration before inspecting
	// existing entries. Host control addresses must never be persisted here.
	qbitHost, qbitPort := qbtDownloadClientEndpoint(qbitCfg)
	client := CreateQBittorrentClient(
		"qBittorrent",
		qbitHost,
		qbitPort,
		qbitCfg.Username,
		qbitCfg.Password,
	)
	setDownloadClientField(client, qbtCategoryField(appName), appName)

	// Respect unmanaged qBittorrent clients. An exact SDBX-managed name can
	// be repaired when its stable host, port, username, or category drifted.
	for _, existing := range existingClients {
		if !strings.EqualFold(existing.Implementation, "qbittorrent") {
			continue
		}
		if !strings.EqualFold(existing.Name, client.Name) {
			return &IntegrationResult{
				Service: fmt.Sprintf("%s → qbittorrent", appName),
				Success: true,
				Message: fmt.Sprintf("Existing unmanaged qBittorrent client preserved (ID: %d)", existing.ID),
				Error:   nil,
			}
		}
		if qbtDownloadClientMatches(&existing, client) &&
			arr.TestDownloadClient(ctx, &existing) == nil {
			return &IntegrationResult{
				Service: fmt.Sprintf("%s → qbittorrent", appName),
				Success: true,
				Message: fmt.Sprintf("Already configured (ID: %d)", existing.ID),
				Error:   nil,
			}
		}
		if i.config.DryRun {
			return &IntegrationResult{
				Service: fmt.Sprintf("%s → qbittorrent", appName),
				Success: true,
				Message: "[DRY RUN] Would repair managed download client",
				Error:   nil,
			}
		}
		if err := qbit.CreateCategory(ctx, appName, ""); err != nil && i.config.Verbose {
			fmt.Printf(
				"Warning: Failed to create category %s: %s\n",
				appName,
				redact.Text(err.Error()),
			)
		}
		repaired := mergeManagedDownloadClient(&existing, client)
		if err := arr.UpdateDownloadClient(ctx, repaired); err != nil {
			return &IntegrationResult{
				Service: fmt.Sprintf("%s → qbittorrent", appName),
				Success: false,
				Message: "Failed to repair managed download client",
				Error:   err,
			}
		}
		if err := arr.TestDownloadClient(ctx, repaired); err != nil {
			return &IntegrationResult{
				Service: fmt.Sprintf("%s → qbittorrent", appName),
				Success: false,
				Message: "Repaired download client failed its connection test",
				Error:   err,
			}
		}
		return &IntegrationResult{
			Service: fmt.Sprintf("%s → qbittorrent", appName),
			Success: true,
			Message: fmt.Sprintf("Repaired managed configuration (ID: %d)", existing.ID),
			Error:   nil,
		}
	}

	// Create category in qBittorrent
	if !i.config.DryRun {
		if err := qbit.CreateCategory(ctx, appName, ""); err != nil {
			// Non-fatal, continue anyway
			if i.config.Verbose {
				fmt.Printf(
					"Warning: Failed to create category %s: %s\n",
					appName,
					redact.Text(err.Error()),
				)
			}
		}
	}

	// Add download client
	if i.config.DryRun {
		return &IntegrationResult{
			Service: fmt.Sprintf("%s → qbittorrent", appName),
			Success: true,
			Message: "[DRY RUN] Would add download client",
			Error:   nil,
		}
	}

	result, err := arr.AddDownloadClient(ctx, client)
	if err != nil {
		return &IntegrationResult{
			Service: fmt.Sprintf("%s → qbittorrent", appName),
			Success: false,
			Message: "Failed to add download client",
			Error:   err,
		}
	}
	if err := arr.TestDownloadClient(ctx, result); err != nil {
		return &IntegrationResult{
			Service: fmt.Sprintf("%s → qbittorrent", appName),
			Success: false,
			Message: "Added download client failed its connection test",
			Error:   err,
		}
	}

	return &IntegrationResult{
		Service: fmt.Sprintf("%s → qbittorrent", appName),
		Success: true,
		Message: fmt.Sprintf("Added successfully (ID: %d)", result.ID),
		Error:   nil,
	}
}

func qbtDownloadClientMatches(existing, desired *DownloadClient) bool {
	if existing == nil || desired == nil ||
		!strings.EqualFold(existing.Name, desired.Name) ||
		!strings.EqualFold(existing.Implementation, desired.Implementation) {
		return false
	}
	categoryField := ""
	for _, candidate := range []string{
		"tvCategory",
		"movieCategory",
		"musicCategory",
	} {
		if _, found := downloadClientField(desired, candidate); found {
			categoryField = candidate
			break
		}
	}
	if categoryField == "" {
		return false
	}
	for _, name := range []string{"host", "port", "username", categoryField} {
		existingValue, existingFound := downloadClientField(existing, name)
		desiredValue, desiredFound := downloadClientField(desired, name)
		if !existingFound || !desiredFound {
			return false
		}
		if name == "host" {
			if !strings.EqualFold(existingValue, desiredValue) {
				return false
			}
			continue
		}
		if existingValue != desiredValue {
			return false
		}
	}
	return true
}

func qbtCategoryField(appName string) string {
	switch appName {
	case "sonarr":
		return "tvCategory"
	case "radarr", "whisparr":
		return "movieCategory"
	case "lidarr":
		return "musicCategory"
	default:
		return "category"
	}
}

func mergeManagedDownloadClient(existing, desired *DownloadClient) *DownloadClient {
	merged := *existing
	merged.Name = desired.Name
	merged.Enable = true
	merged.Fields = append([]DownloadClientField(nil), existing.Fields...)
	for _, field := range desired.Fields {
		setDownloadClientField(&merged, field.Name, field.Value)
	}
	return &merged
}

func setDownloadClientField(client *DownloadClient, name string, value any) {
	for idx := range client.Fields {
		if client.Fields[idx].Name == name {
			client.Fields[idx].Value = value
			return
		}
	}
	client.Fields = append(client.Fields, DownloadClientField{
		Name:  name,
		Value: value,
	})
}

func downloadClientField(client *DownloadClient, name string) (string, bool) {
	for _, field := range client.Fields {
		if field.Name == name {
			return fmt.Sprint(field.Value), true
		}
	}
	return "", false
}

// hasService checks if a service is enabled
func (i *Integrator) hasService(name string) bool {
	svc, exists := i.services[name]
	return exists && svc != nil && svc.Enabled
}

// LoadServicesFromConfig loads service configurations from SDBX config.
// Path-aware: honours cfg.ConfigPath / cfg.SecretsPath rather than the
// hardcoded "configs/" / "secrets/" directories so post-path-migration
// deployments work without rewiring.
func LoadServicesFromConfig(cfg *config.Config) (map[string]*ServiceConfig, error) {
	return loadServicesFromConfig(cfg, nil)
}

// LoadServicesFromGraph loads integration credentials and derives stable
// service URLs from the same verified graph that drives Compose and Traefik.
// This is required for path-routed applications whose URL base is injected by
// an environment variable and therefore is intentionally absent from
// application-owned config.xml.
func LoadServicesFromGraph(
	cfg *config.Config,
	graph *registry.ResolutionGraph,
) (map[string]*ServiceConfig, error) {
	if graph == nil {
		return nil, fmt.Errorf("verified service graph is required")
	}
	return loadServicesFromConfig(cfg, graph)
}

// StableArrServiceURL returns the canonical Docker-network URL for an Arr
// service. The verified graph is required because service-level routing
// overrides are resolved user intent.
func StableArrServiceURL(
	cfg *config.Config,
	graph *registry.ResolutionGraph,
	name string,
) (string, error) {
	return StableServiceURL(cfg, graph, name, ArrDockerURL(name))
}

// StableServiceURL applies the verified routing path to a trusted internal
// service origin when the application consumes its base path itself.
func StableServiceURL(
	cfg *config.Config,
	graph *registry.ResolutionGraph,
	name string,
	base string,
) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("project config is required")
	}
	if graph == nil {
		return "", fmt.Errorf("verified service graph is required")
	}
	resolved := graph.Services[name]
	if resolved == nil || !resolved.Enabled || resolved.FinalDefinition == nil {
		return "", fmt.Errorf("%s is absent from the verified service graph", name)
	}
	definition := resolved.FinalDefinition
	if routing.Strategy(cfg, definition) == config.RoutingStrategyPath &&
		definition.Routing.PathRouting.URLBaseEnvVar != "" {
		base += routing.Path(cfg, definition)
	}
	return base, nil
}

func loadServicesFromConfig(
	cfg *config.Config,
	graph *registry.ResolutionGraph,
) (map[string]*ServiceConfig, error) {
	if cfg == nil || cfg.ActiveServices == nil {
		return nil, fmt.Errorf("verified active service graph is required")
	}

	services := make(map[string]*ServiceConfig)

	// readAPIKey resolves to <ConfigPath>/<svc>/config.xml. Returns "" with
	// no error if the file or key is missing — keeps the original loose
	// semantics (a service without a discoverable key is just skipped).
	readAPIKey := func(serviceName string) (string, error) {
		key, err := ReadArrAPIKey(cfg, serviceName)
		if err != nil {
			return "", err
		}
		if key == "" {
			return "", fmt.Errorf("api key not found in config")
		}
		return key, nil
	}
	// arrServiceURL builds the docker-network base URL for an *arr,
	// honouring its UrlBase so calls like /api/v3/system/status hit the
	// right path when the *arr is configured for sub-path routing.
	arrServiceURL := func(name string) string {
		if graph != nil {
			if stableURL, err := StableArrServiceURL(cfg, graph, name); err == nil {
				return stableURL
			}
		}
		base := ArrDockerURL(name)
		if urlBase, _ := ReadArrUrlBase(cfg, name); urlBase != "" {
			base += urlBase
		}
		return base
	}

	for _, arr := range []string{"prowlarr", "sonarr", "radarr", "lidarr", "whisparr"} {
		if !IsServiceEnabled(cfg, arr) {
			continue
		}
		apiKey, err := readAPIKey(arr)
		if err != nil {
			continue
		}
		services[arr] = &ServiceConfig{
			Name:    arr,
			URL:     arrServiceURL(arr),
			APIKey:  apiKey,
			Enabled: true,
		}
	}

	// qBittorrent — credentials come from <SecretsPath>/qbittorrent_password.txt
	// (provisioned by EnsureQBittorrentInitialised). The in-cluster endpoint
	// follows qBT's own namespace or Gluetun's shared namespace when VPN is on.
	if password, err := sdbxsecrets.ReadSecret(
		cfg.SecretsPath,
		"qbittorrent_password.txt",
	); IsServiceEnabled(cfg, "qbittorrent") && err == nil {
		services["qbittorrent"] = &ServiceConfig{
			Name:    "qbittorrent",
			URL:     QBittorrentDockerURL(cfg),
			APIKey:  password,
			Enabled: true,
		}
	}

	if IsServiceEnabled(cfg, "seerr") {
		apiKey, err := ReadSeerrAPIKey(cfg)
		if err != nil {
			return nil, err
		}
		if apiKey != "" {
			services["seerr"] = &ServiceConfig{
				Name:    "seerr",
				URL:     "http://sdbx-seerr:5055",
				APIKey:  apiKey,
				Enabled: true,
			}
		}
	}

	if IsServiceEnabled(cfg, "bazarr") {
		apiKey, err := ReadBazarrAPIKey(cfg)
		if err != nil {
			return nil, err
		}
		if apiKey != "" && graph != nil {
			serviceURL, urlErr := StableServiceURL(
				cfg,
				graph,
				"bazarr",
				"http://sdbx-bazarr:6767",
			)
			if urlErr != nil {
				return nil, urlErr
			}
			services["bazarr"] = &ServiceConfig{
				Name:    "bazarr",
				URL:     serviceURL,
				APIKey:  apiKey,
				Enabled: true,
			}
		}
	}

	if IsServiceEnabled(cfg, "maintainerr") && graph != nil {
		serviceURL, err := StableServiceURL(
			cfg,
			graph,
			"maintainerr",
			"http://sdbx-maintainerr:6246",
		)
		if err != nil {
			return nil, err
		}
		services["maintainerr"] = &ServiceConfig{
			Name:    "maintainerr",
			URL:     serviceURL,
			Enabled: true,
		}
	}

	if IsServiceEnabled(cfg, "qui") && graph != nil {
		resolved := graph.Services["qui"]
		if resolved == nil || !resolved.Enabled || resolved.FinalDefinition == nil {
			return nil, fmt.Errorf("qui is absent from the verified service graph")
		}
		serviceURL := "http://sdbx-qui:7476"
		if routing.Strategy(cfg, resolved.FinalDefinition) == config.RoutingStrategyPath {
			serviceURL += routing.Path(cfg, resolved.FinalDefinition)
		}
		services["qui"] = &ServiceConfig{
			Name:    "qui",
			URL:     serviceURL,
			Enabled: true,
		}
	}

	if IsServiceEnabled(cfg, "tautulli") && graph != nil {
		serviceURL, err := StableServiceURL(
			cfg,
			graph,
			"tautulli",
			"http://sdbx-tautulli:8181",
		)
		if err != nil {
			return nil, err
		}
		services["tautulli"] = &ServiceConfig{
			Name:    "tautulli",
			URL:     serviceURL,
			Enabled: true,
		}
	}

	if IsServiceEnabled(cfg, "flaresolverr") && graph != nil {
		services["flaresolverr"] = &ServiceConfig{
			Name:    "flaresolverr",
			URL:     "http://sdbx-flaresolverr:8191",
			Enabled: true,
		}
	}

	if IsServiceEnabled(cfg, "profilarr") && graph != nil {
		services["profilarr"] = &ServiceConfig{
			Name:    "profilarr",
			URL:     "http://sdbx-profilarr:6868",
			Enabled: true,
		}
	}

	if IsServiceEnabled(cfg, "plex") && graph != nil {
		token, err := ReadPlexToken(cfg)
		if err != nil {
			return nil, err
		}
		if token != "" {
			services["plex"] = &ServiceConfig{
				Name:    "plex",
				URL:     "http://sdbx-plex:32400",
				APIKey:  token,
				Enabled: true,
			}
		}
	}

	if IsServiceEnabled(cfg, "wizarr") && graph != nil {
		services["wizarr"] = &ServiceConfig{
			Name:    "wizarr",
			URL:     "http://sdbx-wizarr:5690",
			Enabled: true,
		}
	}

	return services, nil
}
