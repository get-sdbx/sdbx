package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/integrate"
	"github.com/get-sdbx/sdbx/internal/routing"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
)

var integrateCmd = &cobra.Command{
	Use:   "integrate",
	Short: "Auto-configure service integrations",
	Long: `Automatically configure integrations between services.

Reconciliation phases:
  1. Local service post-init (filesystem-driven, idempotent):
     - Generates a permanent admin password (persisted to
       secrets/qbittorrent_password.txt; viewable via
       'sdbx secrets show qbittorrent --confirm reveal')
     - Requires authentication from every caller, restores qBT's host,
       CSRF, and clickjacking protections, and writes credentials into
       restricted per-service configs where an upstream lacks secret files
     - Records configs/qbittorrent/.sdbx-init-stamp after a successful
       reconciliation. The stamp is only a fast-path hint: every run also
       verifies the managed credential against qBittorrent.conf and repairs
       drift instead of trusting the stamp alone.

  2. Layered *arr authentication (HTTP-driven, idempotent):
     - Keeps Authelia's admin-only route for every Arr service whose catalog
       declares SDBX-managed Forms authentication
     - Enables native Forms authentication for every direct caller
     - Reconciles separate SDBX-managed credentials, recoverable with
       'sdbx secrets show SERVICE --confirm reveal'

  3. Managed worker configuration (filesystem-driven, ownership-aware):
     - Reconciles marked Recyclarr, Janitorr, and qbit-manage files
     - Preserves unmarked operator-owned files
     - Keeps cleanup workers in non-destructive/test modes

  4. Service-to-service API integrations (HTTP-driven):
     - Seerr → Plex, Radarr, and Sonarr
     - Prowlarr → Arr applications and FlareSolverr
     - Radarr/Sonarr/Lidarr/Whisparr → qBittorrent
     - Bazarr, Maintainerr, Profilarr, Qui, Tautulli, and Wizarr
     - Safe per-app download categories and stable save paths
     - Arr → Plex library refresh after imports, upgrades, and renames

  Existing connections are tested before a write and read back afterwards.
  Existing torrent categories with assigned torrents are never relocated.
  The managed download layout creates missing directories only; it never
  moves existing files.

  On Linux, the host command resolves only the verified SDBX containers'
  bridge addresses through Docker inspect and calls their authenticated
  APIs directly. It never launches a helper or mounts the Docker socket
  inside a container. --in-cluster remains an explicit fallback for a trusted
  runner already attached to the app and download networks.

Examples:
  sdbx integrate                    # Run supported phases from the Linux host
	  sdbx integrate --dry-run          # Preview without applying API changes
	  sdbx integrate --verbose          # Show detailed progress
	  sdbx integrate --rotate-managed-credentials --confirm rotate-managed-credentials
	  sdbx integrate --in-cluster       # Run API phases inside a trusted runner`,
	Args: cobra.NoArgs,
	RunE: runIntegrate,
}

// Flags
var (
	integrateDryRun                   bool
	integrateVerbose                  bool
	integrateInCluster                bool
	integrateRotateManagedCredentials bool
	integrateRotateConfirmation       string

	resolveHostIntegrationEndpoints = integrate.ResolveHostServiceEndpoints
)

func init() {
	rootCmd.AddCommand(integrateCmd)

	integrateCmd.Flags().BoolVar(&integrateDryRun, "dry-run", false, "Preview integrations without applying changes")
	integrateCmd.Flags().BoolVar(&integrateVerbose, "verbose", false, "Show detailed progress")
	integrateCmd.Flags().BoolVar(&integrateInCluster, "in-cluster", false, "Use Docker DNS from an explicitly trusted runner already attached to the app and download networks")
	integrateCmd.Flags().BoolVar(&integrateRotateManagedCredentials, "rotate-managed-credentials", false, "Rotate supported SDBX-managed native credentials transactionally")
	integrateCmd.Flags().StringVar(&integrateRotateConfirmation, "confirm", "", "required exact credential-rotation confirmation: rotate-managed-credentials")
}

func runIntegrate(command *cobra.Command, _ []string) (runErr error) {
	if integrateRotateManagedCredentials &&
		integrateRotateConfirmation != "rotate-managed-credentials" {
		return fmt.Errorf("credential rotation changes every supported managed native login; pass --confirm rotate-managed-credentials after creating a recovery point")
	}
	if !integrateRotateManagedCredentials && integrateRotateConfirmation != "" {
		return fmt.Errorf("--confirm is only valid with --rotate-managed-credentials")
	}
	if integrateRotateManagedCredentials && integrateInCluster {
		return fmt.Errorf("managed credential rotation must run on the verified Linux host")
	}
	ctx := commandContext(command)
	verified, err := loadVerifiedProject(ctx)
	if err != nil {
		return err
	}
	projectDir := verified.Project.Dir
	projectCfg := verified.Project.Config

	// Change to project directory (subsequent docker compose calls rely on this)
	originalDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("read current working directory: %w", err)
	}
	if err := os.Chdir(projectDir); err != nil {
		return fmt.Errorf("failed to change directory: %w", err)
	}
	defer func() {
		if err := os.Chdir(originalDir); err != nil {
			restoreErr := fmt.Errorf("restore working directory: %w", err)
			if runErr == nil {
				runErr = restoreErr
				return
			}
			runErr = errors.Join(runErr, restoreErr)
		}
	}()

	initialization := make(map[string]any)
	var initializationWarnings []string
	recordWarning := func(label string, phaseErr error) {
		if phaseErr == nil {
			return
		}
		initializationWarnings = append(initializationWarnings, label)
		if !IsJSONOutput() {
			fmt.Fprintf(
				os.Stderr,
				"warning: %s: %s\n",
				label,
				redactCLIError(phaseErr.Error()),
			)
		}
	}
	if !integrateInCluster {
		layoutErr := integrate.PrepareDownloadLayout(projectCfg, integrateDryRun)
		recordWarning("managed download layout failed", layoutErr)
		action := "prepared"
		if integrateDryRun {
			action = "would-prepare"
		}
		initialization["download_layout"] = map[string]any{
			"action":      action,
			"directories": append([]string(nil), integrate.ManagedDownloadDirectories...),
		}
	}

	// Phase 1: qBT post-init (idempotent). Locks in a permanent password
	// (sdbx-generated, persisted to secrets/) and enforces authenticated
	// WebUI access for every caller. Runs once per project; skipped thereafter
	// via stamp file.
	if !integrateDryRun && !integrateInCluster {
		var qbtRes *integrate.QBTInitResult
		var qErr error
		if integrateRotateManagedCredentials {
			qbtRes, qErr = integrate.RotateQBittorrentCredential(
				ctx,
				projectCfg,
				resolvedQBTPublicHostname(verified),
			)
		} else {
			qbtRes, qErr = integrate.EnsureQBittorrentInitialised(
				ctx,
				projectCfg,
				resolvedQBTPublicHostname(verified),
			)
		}
		recordWarning("qBittorrent post-init failed", qErr)
		if qbtRes != nil {
			initialization["qbittorrent"] = map[string]any{
				"action":        qbtRes.Action,
				"password_set":  qbtRes.PasswordSet,
				"restarted":     qbtRes.RestartedQBT,
				"deferred_note": redactCLIError(qbtRes.Reason),
			}
		}
		reportQBTInit(qbtRes)
		// filebrowser post-init: same pattern. Generates an admin password,
		// persists to secrets/filebrowser_admin_password.txt, and writes it
		// to the filebrowser DB so an explicitly confirmed
		// `sdbx secrets show filebrowser --confirm reveal` works.
		var fbRes *integrate.FBInitResult
		var fErr error
		if integrateRotateManagedCredentials {
			fbRes, fErr = integrate.RotateFilebrowserCredential(ctx, projectCfg)
		} else {
			fbRes, fErr = integrate.EnsureFilebrowserInitialised(ctx, projectCfg)
		}
		recordWarning("File Browser post-init failed", fErr)
		if fbRes != nil {
			initialization["filebrowser"] = map[string]any{
				"action":        fbRes.Action,
				"password_set":  fbRes.PasswordSet,
				"deferred_note": redactCLIError(fbRes.Reason),
			}
		}
		reportFBInit(fbRes)
	}

	// Load service configurations (path-aware via cfg.ConfigPath)
	services, err := integrate.LoadServicesFromGraph(projectCfg, verified.Graph)
	if err != nil {
		return fmt.Errorf("failed to load service configurations: %w", err)
	}

	if integrateDryRun && !integrateInCluster {
		addHostInitializationPreview(
			initialization,
			projectCfg,
			integrateRotateManagedCredentials,
		)
	}

	// A fresh project has no qBittorrent managed password or *arr API keys
	// yet. Its local initialization preview is still useful and must not
	// require Docker or running service APIs.
	if len(services) == 0 &&
		!integrate.IsServiceEnabled(projectCfg, "decluttarr") &&
		(!integrateDryRun || len(initialization) == 0) {
		if IsJSONOutput() {
			result := map[string]interface{}{
				"success":        false,
				"message":        "No services with usable integration credentials were found",
				"initialization": initialization,
				"warnings":       initializationWarnings,
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return markCLIErrorReported(
				fmt.Errorf("no services with usable integration credentials were found"),
			)
		}

		fmt.Println(tui.WarningStyle.Render(
			"⚠ No services with usable integration credentials were found",
		))
		fmt.Println()
		fmt.Println(tui.MutedStyle.Render("Make sure services are enabled and running."))
		fmt.Println(tui.MutedStyle.Render("Run 'sdbx up', then retry integration."))
		return fmt.Errorf(
			"no services with usable integration credentials were found",
		)
	}

	networkRequired := networkIntegrationsRequired(services)
	nativeAuthenticationRequired := nativeArrAuthenticationRequired(services)
	hostControlRequired := networkRequired || nativeAuthenticationRequired
	if hostControlRequired && !integrateInCluster {
		if err := resolveHostIntegrationEndpoints(
			ctx,
			projectCfg,
			services,
			integrate.DockerContainerAddressResolver{},
		); err != nil {
			return fmt.Errorf(
				"resolve Linux host integration endpoints: %w; use --in-cluster only from a trusted runner attached to both project networks",
				err,
			)
		}
	}

	// Create integration config
	cfg := integrate.DefaultConfig()
	cfg.Services = services
	cfg.ProjectConfig = projectCfg
	cfg.Graph = verified.Graph
	cfg.DryRun = integrateDryRun
	cfg.Verbose = integrateVerbose || !IsJSONOutput()
	cfg.InCluster = integrateInCluster
	cfg.RotateCredentials = integrateRotateManagedCredentials

	// Create integrator
	integrator := integrate.NewIntegrator(cfg)

	if !IsJSONOutput() {
		fmt.Println(tui.TitleStyle.Render("Service Integration"))
		fmt.Println()

		if integrateDryRun {
			fmt.Println(tui.WarningStyle.Render("🔍 DRY RUN MODE - No changes will be made"))
			fmt.Println()
		}

		if integrateDryRun {
			printHostInitializationPreview(initialization)
		}

		// Show services with credentials ready for API-driven phases.
		fmt.Println(tui.MutedStyle.Render("Services with API credentials detected:"))
		names := sortedIntegrationServiceNames(services)
		if len(names) == 0 {
			fmt.Println("  • none")
		} else {
			for _, name := range names {
				fmt.Printf("  • %s\n", name)
			}
		}
		fmt.Println()

		if !integrateDryRun {
			fmt.Println(tui.MutedStyle.Render("Waiting for services to be ready..."))
			fmt.Println()
		}
	}

	// Run integrations
	results, err := integrator.Run(ctx)
	if err != nil {
		if IsJSONOutput() {
			result := map[string]interface{}{
				"success":        false,
				"error":          redactCLIError(err.Error()),
				"initialization": initialization,
				"warnings":       initializationWarnings,
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return markCLIErrorReported(err)
		}

		return fmt.Errorf("integration failed: %w", err)
	}

	// JSON output
	if IsJSONOutput() {
		output := make([]map[string]interface{}, 0, len(results))
		successCount := 0
		for _, r := range results {
			if r.Success {
				successCount++
			}
			entry := map[string]interface{}{
				"service": redactCLIError(r.Service),
				"success": r.Success,
				"message": redactCLIError(r.Message),
			}
			if r.Error != nil {
				entry["error"] = redactCLIError(r.Error.Error())
			}
			output = append(output, entry)
		}

		result := map[string]interface{}{
			"success":        successCount == len(results) && len(initializationWarnings) == 0,
			"total":          len(results),
			"successful":     successCount,
			"failed":         len(results) - successCount,
			"integrations":   output,
			"initialization": initialization,
			"warnings":       initializationWarnings,
			"network_integrations": buildNetworkIntegrationReport(
				hostControlRequired,
				networkRequired,
				nativeAuthenticationRequired,
				integrateDryRun,
				integrateInCluster,
			),
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		if successCount != len(results) {
			return markCLIErrorReported(fmt.Errorf(
				"%d service integrations failed",
				len(results)-successCount,
			))
		}
		if len(initializationWarnings) > 0 {
			return markCLIErrorReported(fmt.Errorf(
				"%d initialization step(s) failed",
				len(initializationWarnings),
			))
		}
		return nil
	}

	// Human-readable output
	fmt.Println(tui.TitleStyle.Render("Integration Results"))
	fmt.Println()

	successCount := 0
	if len(results) == 0 {
		fmt.Println(tui.MutedStyle.Render(
			"No API integrations are ready; local initialization actions are previewed above.",
		))
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, tui.TableHeaderStyle.Render("INTEGRATION")+"\t"+tui.TableHeaderStyle.Render("STATUS")+"\t"+tui.TableHeaderStyle.Render("MESSAGE"))

		for _, result := range results {
			if result.Success {
				successCount++
			}

			status := "✓"
			statusStyle := tui.SuccessStyle
			if !result.Success {
				status = "✗"
				statusStyle = tui.ErrorStyle
			}

			fmt.Fprintf(w, "%s\t%s\t%s\n",
				redactCLIError(result.Service),
				statusStyle.Render(status),
				redactCLIError(result.Message),
			)
		}
		if err := w.Flush(); err != nil {
			return fmt.Errorf("render integration results: %w", err)
		}
	}

	fmt.Println()

	// Summary
	if len(results) == 0 {
		fmt.Println(tui.SuccessStyle.Render("✓ Local initialization preview completed"))
	} else if successCount == len(results) {
		fmt.Println(tui.SuccessStyle.Render(fmt.Sprintf("✓ All %d integrations completed successfully", len(results))))
	} else {
		failCount := len(results) - successCount
		fmt.Println(tui.WarningStyle.Render(fmt.Sprintf("⚠ %d succeeded, %d failed", successCount, failCount)))
	}

	if integrateDryRun {
		fmt.Println()
		fmt.Println(tui.MutedStyle.Render("This was a dry run. Run without --dry-run to apply changes."))
	}

	if successCount != len(results) {
		return fmt.Errorf("%d service integrations failed", len(results)-successCount)
	}
	if len(initializationWarnings) > 0 {
		return fmt.Errorf("%d initialization step(s) failed", len(initializationWarnings))
	}
	return nil
}

func resolvedQBTPublicHostname(verified *verifiedProject) string {
	if verified == nil || verified.Project == nil ||
		verified.Project.Config == nil || verified.Graph == nil {
		return ""
	}
	resolved := verified.Graph.Services["qbittorrent"]
	if resolved == nil || !resolved.Enabled ||
		resolved.FinalDefinition == nil ||
		!resolved.FinalDefinition.Routing.Enabled {
		return ""
	}
	return routing.Hostname(
		verified.Project.Config,
		resolved.FinalDefinition,
	)
}

func buildNetworkIntegrationReport(
	hostControlRequired bool,
	serviceToServiceRequired bool,
	nativeAuthenticationRequired bool,
	dryRun bool,
	inCluster bool,
) map[string]interface{} {
	status := "not-required"
	runner := "none"
	if hostControlRequired {
		status = "executed"
		if dryRun {
			status = "previewed"
		}
		runner = "linux-host-docker-bridge"
		if inCluster {
			runner = "explicit-in-cluster"
		}
	}
	return map[string]interface{}{
		"required":                       hostControlRequired,
		"service_to_service_required":    serviceToServiceRequired,
		"native_authentication_required": nativeAuthenticationRequired,
		"status":                         status,
		"runner":                         runner,
	}
}

func nativeArrAuthenticationRequired(
	services map[string]*integrate.ServiceConfig,
) bool {
	for _, name := range []string{
		"prowlarr", "sonarr", "radarr", "lidarr", "whisparr",
	} {
		service := services[name]
		if service != nil && service.Enabled {
			return true
		}
	}
	return false
}

func sortedIntegrationServiceNames(
	services map[string]*integrate.ServiceConfig,
) []string {
	names := make([]string, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func addHostInitializationPreview(
	initialization map[string]any,
	projectCfg *config.Config,
	rotate bool,
) {
	action := "would-initialize-if-needed"
	if rotate {
		action = "would-rotate"
	}
	if integrate.IsServiceEnabled(projectCfg, "qbittorrent") {
		initialization["qbittorrent"] = map[string]any{
			"action":       action,
			"password_set": false,
			"restarted":    false,
		}
	}
	if integrate.IsServiceEnabled(projectCfg, "filebrowser") {
		initialization["filebrowser"] = map[string]any{
			"action":       action,
			"password_set": false,
		}
	}
}

func printHostInitializationPreview(initialization map[string]any) {
	if len(initialization) == 0 {
		return
	}
	fmt.Println(tui.MutedStyle.Render("Local initialization preview:"))
	names := make([]string, 0, len(initialization))
	for name := range initialization {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "download_layout" {
			fmt.Println("  • download layout: create missing managed directories only")
			continue
		}
		fmt.Printf("  • %s: initialize or repair managed credentials if needed\n", name)
	}
	fmt.Println()
}

func networkIntegrationsRequired(
	services map[string]*integrate.ServiceConfig,
) bool {
	if serviceEnabledForIntegration(services, "tautulli") &&
		serviceEnabledForIntegration(services, "plex") {
		return true
	}
	if serviceEnabledForIntegration(services, "prowlarr") &&
		serviceEnabledForIntegration(services, "flaresolverr") {
		return true
	}
	if serviceEnabledForIntegration(services, "profilarr") &&
		(serviceEnabledForIntegration(services, "radarr") ||
			serviceEnabledForIntegration(services, "sonarr")) {
		return true
	}
	if serviceEnabledForIntegration(services, "wizarr") &&
		serviceEnabledForIntegration(services, "plex") {
		return true
	}
	hasArr := serviceEnabledForIntegration(services, "sonarr") ||
		serviceEnabledForIntegration(services, "radarr") ||
		serviceEnabledForIntegration(services, "lidarr") ||
		serviceEnabledForIntegration(services, "whisparr")
	hasCoordinator := serviceEnabledForIntegration(services, "prowlarr") ||
		serviceEnabledForIntegration(services, "qbittorrent") ||
		serviceEnabledForIntegration(services, "seerr") ||
		serviceEnabledForIntegration(services, "bazarr") ||
		serviceEnabledForIntegration(services, "maintainerr") ||
		serviceEnabledForIntegration(services, "qui")
	return hasArr && hasCoordinator
}

func serviceEnabledForIntegration(
	services map[string]*integrate.ServiceConfig,
	name string,
) bool {
	service, ok := services[name]
	return ok && service != nil && service.Enabled
}

// reportQBTInit prints a one-line summary of the qBT post-init phase. Silent
// for "skipped-already-init" (the steady-state for any project that's been
// integrated at least once) so the common case stays quiet.
func reportQBTInit(res *integrate.QBTInitResult) {
	if res == nil || IsJSONOutput() {
		return
	}
	switch res.Action {
	case "stamped", "rotated":
		fmt.Println(tui.SuccessStyle.Render("✓ qBittorrent initialised"))
		fmt.Printf("  • permanent admin password set (run `sdbx secrets show qbittorrent --confirm reveal`)\n")
	case "skipped-already-init":
		// silent — already done
	case "skipped-not-enabled":
		// silent — qBT not in this stack
	case "skipped-no-conf":
		fmt.Println(tui.WarningStyle.Render("⚠ qBittorrent post-init deferred"))
		fmt.Printf("  %s\n", redactCLIError(res.Reason))
	}
}

func reportFBInit(res *integrate.FBInitResult) {
	if res == nil || IsJSONOutput() {
		return
	}
	switch res.Action {
	case "stamped", "rotated":
		fmt.Println(tui.SuccessStyle.Render("✓ filebrowser initialised"))
		fmt.Printf("  • permanent admin password set (run `sdbx secrets show filebrowser --confirm reveal`)\n")
	case "skipped-already-init", "skipped-not-enabled":
		// silent
	case "skipped-not-running":
		fmt.Println(tui.WarningStyle.Render("⚠ filebrowser post-init deferred"))
		fmt.Printf("  %s\n", redactCLIError(res.Reason))
	}
}

// Helper to format duration
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%.1fm", d.Minutes())
}
