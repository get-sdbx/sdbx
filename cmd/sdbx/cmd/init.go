package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/generator"
	"github.com/get-sdbx/sdbx/internal/registry"
	"github.com/get-sdbx/sdbx/internal/registry/presets"
	sdbxrouting "github.com/get-sdbx/sdbx/internal/routing"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/argon2"
)

var (
	initDomain                    string
	initExposeMode                string
	initACMEEmail                 string
	initRoutingStrategy           string
	initTimezone                  string
	initMediaPath                 string
	initDownloadsPath             string
	initConfigPath                string
	initLegacyConfigPath          string
	initMediaServer               string
	initPreset                    string
	initAddons                    []string
	initVPNEnabled                bool
	initVPNProvider               string
	initVPNCountry                string
	initTorrentPort               int
	initAllowUnprotectedDownloads bool
	initSkipWizard                bool
	initAdminUser                 string
	initAdminPasswordFile         string
	initAdminPasswordStdin        bool
	initDryRun                    bool
	initYes                       bool
	initForce                     bool
	initAllowNonemptyDirectory    bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Bootstrap a new SDBX project",
	Long: `Initialize a new SDBX seedbox project in the current directory.

This command will:
  • Guide you through configuration with an interactive wizard
  • Generate compose.yaml, .env, and config files
  • Create secrets for Authelia authentication
  • Set up directory structure for media and downloads

Use --skip-wizard with explicit media, preset, credential, and confirmation
flags to run non-interactively. Use --dry-run to resolve and preview the full
deployment without writing files.`,
	Args: cobra.NoArgs,
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)

	initCmd.Flags().StringVar(&initDomain, "domain", "", "Base domain (e.g., box.sdbx.one)")
	initCmd.Flags().StringVar(
		&initExposeMode,
		"expose",
		"",
		"Exposure mode: lan, direct, or cloudflared (remote-managed)",
	)
	initCmd.Flags().StringVar(
		&initACMEEmail,
		"acme-email",
		"",
		"ACME contact email required for direct exposure",
	)
	initCmd.Flags().StringVar(&initRoutingStrategy, "routing", "", "Routing strategy: subdomain or path")
	initCmd.Flags().StringVar(&initTimezone, "timezone", "", "Timezone (e.g., Europe/Paris)")
	initCmd.Flags().StringVar(&initMediaPath, "media", "", "Media storage path")
	initCmd.Flags().StringVar(&initDownloadsPath, "downloads", "", "Downloads storage path")
	initCmd.Flags().StringVar(&initConfigPath, "config-path", "", "Service configuration storage path")
	initCmd.Flags().StringVar(&initLegacyConfigPath, "config", "", "Deprecated alias for --config-path")
	_ = initCmd.Flags().MarkDeprecated("config", "use --config-path; this alias will be removed after v1")
	initCmd.Flags().StringVar(
		&initMediaServer,
		"media-server",
		"",
		"Required media choice: plex, jellyfin, both, or none",
	)
	initCmd.Flags().StringVar(
		&initPreset,
		"preset",
		"",
		"Required automation choice: none or a name from 'sdbx preset list'",
	)
	initCmd.Flags().StringSliceVar(
		&initAddons,
		"addon",
		nil,
		"Additional addon to enable (repeatable)",
	)
	initCmd.Flags().BoolVar(&initVPNEnabled, "vpn", false, "Enable VPN for downloads (requires --vpn-provider)")
	initCmd.Flags().StringVar(&initVPNProvider, "vpn-provider", "", "VPN provider (nordvpn, mullvad, pia, surfshark, protonvpn, expressvpn, windscribe, ipvanish, cyberghost, ivpn, torguard, vyprvpn, purevpn, hidemyass, perfectprivacy, airvpn, custom)")
	initCmd.Flags().StringVar(&initVPNCountry, "vpn-country", "France", "VPN server country")
	initCmd.Flags().IntVar(&initTorrentPort, "torrent-peer-port", 6881, "TCP/UDP peer port published for qBittorrent")
	initCmd.Flags().BoolVar(
		&initAllowUnprotectedDownloads,
		"allow-unprotected-downloads",
		false,
		"Acknowledge that disabling VPN exposes torrent traffic through the host public IP",
	)
	initCmd.Flags().BoolVar(&initSkipWizard, "skip-wizard", false, "Skip interactive wizard")
	initCmd.Flags().StringVar(&initAdminUser, "admin-user", "admin", "Admin username for Authelia")
	initCmd.Flags().StringVar(
		&initAdminPasswordFile,
		"admin-password-file",
		"",
		"Read the Authelia admin password from a private regular file",
	)
	initCmd.Flags().BoolVar(
		&initAdminPasswordStdin,
		"admin-password-stdin",
		false,
		"Read one Authelia admin password line from non-terminal stdin",
	)
	initCmd.Flags().BoolVar(&initDryRun, "dry-run", false, "Resolve, preflight, and preview without writing files")
	initCmd.Flags().BoolVar(&initYes, "yes", false, "Approve the displayed non-interactive deployment plan")
	initCmd.Flags().BoolVar(&initForce, "force", false, "Regenerate an existing SDBX project")
	initCmd.Flags().BoolVar(
		&initAllowNonemptyDirectory,
		"allow-nonempty-directory",
		false,
		"Acknowledge initialization in a reviewed non-empty directory that is not an SDBX project",
	)
}

func runInit(cmd *cobra.Command, _ []string) error {
	ctx := commandContext(cmd)
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}
	pending, err := generator.ProjectTransactionPending(cwd)
	if err != nil {
		return fmt.Errorf("inspect initializer transaction: %w", err)
	}
	if pending {
		if initDryRun {
			return fmt.Errorf(
				"an interrupted initializer transaction requires recovery; rerun without --dry-run",
			)
		}
		if err := generator.RecoverProjectTransaction(cwd); err != nil {
			return err
		}
		fmt.Println(tui.InfoStyle.Render("Recovered an interrupted initializer transaction."))
	}

	entries, err := os.ReadDir(cwd)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	hasExisting, foreignEntries := classifyInitDirectory(entries)
	if hasExisting && initAllowNonemptyDirectory {
		return fmt.Errorf(
			"existing SDBX project detected; use --force, not --allow-nonempty-directory",
		)
	}
	if len(foreignEntries) > 0 && initForce {
		return fmt.Errorf(
			"directory is not an existing SDBX project; use --allow-nonempty-directory only after reviewing --dry-run",
		)
	}

	// Load existing config if available, otherwise default
	cfg, err := config.Load()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	// Initialize registry for addon selection
	reg, err := registry.NewWithDefaults()
	if err != nil {
		return fmt.Errorf("failed to initialize registry: %w", err)
	}

	interactive := !initSkipWizard && IsTUIEnabled()
	if interactive {
		// Show logo with style
		fmt.Println()
		fmt.Println(tui.LogoStyled())
		fmt.Println()

		tagline := lipgloss.NewStyle().
			Foreground(tui.ColorHot).
			Render("/dev/tty0 :: bootstrap the box, keep the receipts")
		fmt.Println(tagline)
		fmt.Println()

		if hasExisting && !initDryRun {
			var confirm bool
			if err := huh.NewConfirm().
				Title("Existing project detected. Regenerate it?").
				Description("The transaction will preserve existing secrets and roll back on failure.").
				Value(&confirm).
				Run(); err != nil {
				return fmt.Errorf("confirmation prompt failed: %w", err)
			}
			if !confirm {
				fmt.Println(tui.MutedStyle.Render("Aborted."))
				return nil
			}
		}
		if len(foreignEntries) > 0 && !initDryRun {
			var confirm bool
			if err := huh.NewConfirm().
				Title("This non-empty directory is not an SDBX project. Initialize it?").
				Description(
					"Managed files such as .gitignore may be replaced. " +
						"Other files are preserved; review the dry-run first.",
				).
				Value(&confirm).
				Run(); err != nil {
				return fmt.Errorf("confirmation prompt failed: %w", err)
			}
			if !confirm {
				fmt.Println(tui.MutedStyle.Render("Aborted."))
				return nil
			}
		}

		// Run interactive wizard
		if err := runWizard(ctx, cfg, reg); err != nil {
			return err
		}
	} else {
		if hasExisting && !initDryRun && !initForce {
			return fmt.Errorf("existing project detected; pass --force after reviewing the regeneration plan")
		}
		if !initDryRun && !initYes {
			return fmt.Errorf("non-interactive initialization requires --yes after reviewing with --dry-run")
		}
		if len(foreignEntries) > 0 &&
			!initDryRun &&
			!initAllowNonemptyDirectory {
			return fmt.Errorf(
				"non-empty directory is not an SDBX project (%s); pass --allow-nonempty-directory only after reviewing --dry-run",
				summarizeInitEntries(foreignEntries),
			)
		}
		if err := configureInitFromFlags(cmd, cfg, hasExisting); err != nil {
			return err
		}
	}

	cfg.ProjectDir = cwd
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := validateSelectedAddons(ctx, reg, cfg.Addons); err != nil {
		return err
	}

	lock, warnings, err := reg.GenerateLockFileWithOptions(
		ctx,
		cfg,
		registry.LockOptions{
			CLIVersion:    Version,
			ImageResolver: imageDigestResolverFactory(),
		},
	)
	if err != nil {
		return fmt.Errorf("failed to create reproducible lock: %w", err)
	}
	planner := generator.NewGeneratorWithLock(cfg, cwd, reg, lock, Version)
	graph, err := planner.Plan()
	if err != nil {
		return fmt.Errorf("failed to plan project: %w", err)
	}
	preflight, err := runInitPreflight(ctx, cfg, reg, lock, graph, hasExisting)
	if err != nil {
		return fmt.Errorf("preflight failed: %w", err)
	}
	printInitPreflight(preflight)
	printInitPreview(cfg, graph, lock, preflight.Compose)
	allWarnings := uniqueResolutionWarnings(append(
		append([]registry.ResolutionWarning(nil), graph.Warnings...),
		warnings...,
	))
	if len(allWarnings) > 0 {
		fmt.Print(formatResolutionWarnings(allWarnings))
	}

	if interactive && !initDryRun {
		var confirm bool
		if err := huh.NewConfirm().
			Title("Generate this exact deployment?").
			Description("All generated files are staged and validated before promotion.").
			Value(&confirm).
			Run(); err != nil {
			return fmt.Errorf("confirmation prompt failed: %w", err)
		}
		if !confirm {
			fmt.Println(tui.MutedStyle.Render("Aborted."))
			return nil
		}
	}
	if initDryRun {
		fmt.Println(tui.SuccessStyle.Render("✓ Dry run complete. No files were written."))
		return nil
	}

	fmt.Printf("  %s Generating and validating staged project...\n", tui.InfoStyle.Render(tui.IconSpinner))
	if err := generator.GenerateProjectTransactional(
		cfg,
		cwd,
		reg,
		lock,
		Version,
		generator.ProjectTransactionOptions{
			ValidateStage: func(stageProject string) error {
				return validateStagedCompose(ctx, stageProject)
			},
		},
	); err != nil {
		return fmt.Errorf("failed to generate project transactionally: %w", err)
	}

	// Success message
	fmt.Println()
	printSuccessMessage(cfg, graph)

	return nil
}

func classifyInitDirectory(entries []os.DirEntry) (bool, []string) {
	for _, entry := range entries {
		if entry.Name() == ".sdbx.yaml" {
			return true, nil
		}
	}

	foreign := make([]string, 0, len(entries))
	for _, entry := range entries {
		switch entry.Name() {
		case ".DS_Store", ".git":
			continue
		default:
			foreign = append(foreign, entry.Name())
		}
	}
	return false, foreign
}

func summarizeInitEntries(entries []string) string {
	const limit = 5
	if len(entries) <= limit {
		return strings.Join(entries, ", ")
	}
	return fmt.Sprintf(
		"%s, and %d more",
		strings.Join(entries[:limit], ", "),
		len(entries)-limit,
	)
}

func configureInitFromFlags(
	command *cobra.Command,
	cfg *config.Config,
	hasExisting bool,
) error {
	if !hasExisting && initDomain == "" {
		return fmt.Errorf("--domain is required for non-interactive initialization")
	}
	if initDomain != "" {
		cfg.Domain = initDomain
	}
	if initExposeMode != "" {
		cfg.Expose.Mode = initExposeMode
	}
	cfg.SetExposureMode(cfg.Expose.Mode)
	if command.Flags().Changed("acme-email") {
		cfg.Expose.TLS.Email = strings.TrimSpace(initACMEEmail)
	}
	if cfg.Expose.Mode == config.ExposeModeDirect && cfg.Expose.TLS.Email == "" {
		return fmt.Errorf("--acme-email is required when --expose direct is selected")
	}
	if cfg.Expose.Mode != config.ExposeModeDirect && command.Flags().Changed("acme-email") {
		return fmt.Errorf("--acme-email is used only with --expose direct")
	}
	if initRoutingStrategy != "" {
		cfg.Routing.Strategy = initRoutingStrategy
	}
	if initTimezone != "" {
		cfg.Timezone = initTimezone
	}
	if initMediaPath != "" {
		cfg.MediaPath = initMediaPath
	}
	if initDownloadsPath != "" {
		cfg.DownloadsPath = initDownloadsPath
	}
	if initConfigPath != "" && initLegacyConfigPath != "" {
		return fmt.Errorf("--config-path and deprecated --config are mutually exclusive")
	}
	switch {
	case initConfigPath != "":
		cfg.ConfigPath = initConfigPath
	case initLegacyConfigPath != "":
		cfg.ConfigPath = initLegacyConfigPath
	}

	if initMediaServer == "" {
		return fmt.Errorf("--media-server is required: choose plex, jellyfin, both, or none")
	}
	if err := applyMediaServerChoice(cfg, initMediaServer); err != nil {
		return err
	}
	if initPreset == "" {
		return fmt.Errorf("--preset is required: choose none or a name from 'sdbx preset list'")
	}
	if err := applyInitPreset(cfg, initPreset, initAddons); err != nil {
		return err
	}

	if command.Flags().Changed("vpn") || !hasExisting {
		cfg.VPNEnabled = initVPNEnabled
	}
	if command.Flags().Changed("torrent-peer-port") || !hasExisting {
		cfg.TorrentPort = initTorrentPort
	}
	if cfg.VPNEnabled {
		if initVPNProvider != "" {
			cfg.VPNProvider = initVPNProvider
		}
		if cfg.VPNProvider == "" {
			return fmt.Errorf("--vpn-provider is required when VPN protection is enabled")
		}
		if initVPNCountry != "" {
			cfg.VPNCountry = initVPNCountry
		}
	} else if err := validateDownloadProtection(
		false,
		initAllowUnprotectedDownloads,
	); err != nil {
		return err
	}

	if command.Flags().Changed("admin-user") || !hasExisting {
		cfg.AdminUser = initAdminUser
	}
	password, err := readInitAdminPassword()
	if err != nil {
		return err
	}
	defer zeroBytes(password)
	if err := validateAdminPasswordBytes(password); err != nil {
		return err
	}
	hash, err := generateArgon2Hash(password)
	if err != nil {
		return fmt.Errorf("failed to generate password hash: %w", err)
	}
	cfg.AdminPasswordHash = hash
	return nil
}

func readInitAdminPassword() ([]byte, error) {
	if initAdminPasswordFile != "" && initAdminPasswordStdin {
		return nil, fmt.Errorf("--admin-password-file and --admin-password-stdin are mutually exclusive")
	}
	switch {
	case initAdminPasswordFile != "":
		return readPrivateCredentialFile(initAdminPasswordFile, "admin password")
	case initAdminPasswordStdin:
		return readCredentialStdin("admin password")
	default:
		return nil, fmt.Errorf(
			"non-interactive initialization requires --admin-password-file or --admin-password-stdin",
		)
	}
}

func applyMediaServerChoice(cfg *config.Config, choice string) error {
	cfg.PlexEnabled = false
	cfg.JellyfinEnabled = false
	switch strings.ToLower(strings.TrimSpace(choice)) {
	case "plex":
		cfg.PlexEnabled = true
	case "jellyfin":
		cfg.JellyfinEnabled = true
	case "both":
		cfg.PlexEnabled = true
		cfg.JellyfinEnabled = true
	case "none":
		// Explicitly valid for downloader-only and library-only projects.
	default:
		return fmt.Errorf("media server must be one of: plex, jellyfin, both, none")
	}
	return nil
}

func applyInitPreset(cfg *config.Config, name string, extras []string) error {
	var selected []string
	if name != "none" {
		collection, err := presets.Load()
		if err != nil {
			return fmt.Errorf("load automation presets: %w", err)
		}
		preset := collection.Find(name)
		if preset == nil {
			return fmt.Errorf("unknown preset %q; use 'sdbx preset list'", name)
		}
		selected = append(selected, preset.Addons...)
		switch name {
		case "media-plex":
			if !cfg.PlexEnabled {
				return fmt.Errorf("preset %q requires Plex in --media-server", name)
			}
		case "media-jellyfin":
			if !cfg.JellyfinEnabled {
				return fmt.Errorf("preset %q requires Jellyfin in --media-server", name)
			}
		}
	}
	selected = append(selected, extras...)
	seen := make(map[string]struct{}, len(selected))
	cfg.Addons = cfg.Addons[:0]
	for _, addon := range selected {
		addon = strings.TrimSpace(addon)
		if addon == "" {
			return fmt.Errorf("addon name must not be empty")
		}
		if _, duplicate := seen[addon]; duplicate {
			continue
		}
		seen[addon] = struct{}{}
		cfg.Addons = append(cfg.Addons, addon)
	}
	return nil
}

func validateSelectedAddons(
	ctx context.Context,
	reg *registry.Registry,
	addons []string,
) error {
	for _, addon := range addons {
		definition, _, err := reg.GetService(ctx, addon)
		if err != nil {
			return fmt.Errorf("selected addon %q is unavailable: %w", addon, err)
		}
		if !definition.Conditions.RequireAddon {
			return fmt.Errorf("%q is a core service and cannot be selected as an addon", addon)
		}
	}
	return nil
}

func runWizard(
	ctx context.Context,
	cfg *config.Config,
	reg *registry.Registry,
) error {
	// Step 1: Domain configuration
	form1 := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Base Domain").
				Description("Your root domain for all services").
				Placeholder("box.sdbx.one").
				Value(&cfg.Domain).
				Validate(validateWizardDomain),

			huh.NewSelect[string]().
				Title("Exposure Mode").
				Description("How should services be accessible?").
				Options(
					huh.NewOption("LAN only (local HTTPS, no public ingress)", "lan"),
					huh.NewOption("Direct HTTPS (Let's Encrypt, ports 80/443)", "direct"),
					huh.NewOption(
						"Cloudflare Tunnel (remote-managed; no inbound ports)",
						"cloudflared",
					),
				).
				Value(&cfg.Expose.Mode),

			huh.NewSelect[string]().
				Title("Routing Strategy").
				Description("How should services be accessed?").
				Options(
					huh.NewOption("Subdomain (sonarr.domain.tld, prowlarr.domain.tld)", "subdomain"),
					huh.NewOption("Path (sdbx.domain.tld/sonarr, sdbx.domain.tld/prowlarr)", "path"),
				).
				Value(&cfg.Routing.Strategy),
		).Title("Domain Configuration"),
	)

	if err := form1.Run(); err != nil {
		return err
	}
	cfg.SetExposureMode(cfg.Expose.Mode)
	if cfg.Expose.Mode == config.ExposeModeDirect {
		formACME := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("ACME Contact Email").
					Description("Used by Let's Encrypt for certificate expiry and account notices.").
					Placeholder("ops@example.test").
					Value(&cfg.Expose.TLS.Email).
					Validate(validateACMEContactEmail),
			).Title("Direct HTTPS"),
		)
		if err := formACME.Run(); err != nil {
			return err
		}
	}

	// If path routing: ask for base subdomain
	if cfg.Routing.Strategy == config.RoutingStrategyPath {
		formBaseDomain := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Base Subdomain").
					Description("Subdomain for path-based access (e.g., 'sdbx' → sdbx.domain.tld/...)").
					Placeholder("sdbx").
					Value(&cfg.Routing.BaseDomain).
					Validate(validateWizardBaseDomain),
			).Title("Path Routing Configuration"),
		)
		if err := formBaseDomain.Run(); err != nil {
			return err
		}
	}

	// Step 2: Admin User
	applyWizardDefaults(cfg)
	var adminPassword string
	formAuth := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Admin Username").
				Description("Username for Authelia SSO").
				Placeholder("admin").
				Value(&cfg.AdminUser).
				Validate(validateWizardAdminUser),

			huh.NewInput().
				Title("Admin Password").
				Description("Password for Authelia (will be hashed securely)").
				Placeholder("At least 12 characters").
				EchoMode(huh.EchoModePassword).
				Value(&adminPassword).
				Validate(func(s string) error {
					return validateAdminPassword(s)
				}),
		).Title("Admin Configuration"),
	)

	if err := formAuth.Run(); err != nil {
		return err
	}

	// Hash password
	passwordBytes := []byte(adminPassword)
	hash, err := generateArgon2Hash(passwordBytes)
	zeroBytes(passwordBytes)
	adminPassword = ""
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	cfg.AdminPasswordHash = hash

	// Step 3: Media-server selection. The first placeholder forces an
	// explicit choice rather than silently shipping Plex.
	mediaChoice := ""
	formMedia := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Media Server").
				Description("Choose exactly what this project should run.").
				Options(
					huh.NewOption("Choose a media-server policy…", ""),
					huh.NewOption("Plex", "plex"),
					huh.NewOption("Jellyfin", "jellyfin"),
					huh.NewOption("Both Plex and Jellyfin", "both"),
					huh.NewOption("No media server", "none"),
				).
				Value(&mediaChoice).
				Validate(func(value string) error {
					if value == "" {
						return fmt.Errorf("choose Plex, Jellyfin, both, or no media server")
					}
					return nil
				}),
		).Title("Media Server"),
	)
	if err := formMedia.Run(); err != nil {
		return err
	}
	if err := applyMediaServerChoice(cfg, mediaChoice); err != nil {
		return err
	}

	// Step 4: Storage configuration
	form2 := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Media Path").
				Description("Where to store movies, TV shows, music").
				Placeholder("./data/media").
				Value(&cfg.MediaPath).
				Validate(func(value string) error {
					return validateWizardManagedPath("media_path", value)
				}),

			huh.NewInput().
				Title("Downloads Path").
				Description("Where torrent client stores downloads").
				Placeholder("./data/downloads").
				Value(&cfg.DownloadsPath).
				Validate(func(value string) error {
					return validateWizardManagedPath("downloads_path", value)
				}),

			huh.NewInput().
				Title("Config Path").
				Description("Where service configs are stored").
				Placeholder("./config").
				Value(&cfg.ConfigPath).
				Validate(func(value string) error {
					return validateWizardManagedPath("config_path", value)
				}),
		).Title("Storage Configuration"),
	)

	if err := form2.Run(); err != nil {
		return err
	}

	// Step 5: VPN configuration
	var wantVPN bool
	formVPN := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Enable VPN for downloads?").
				Description("Routes torrent traffic through VPN with kill-switch. Recommended for privacy.").
				Value(&wantVPN),
		).Title("VPN Configuration"),
	)

	if err := formVPN.Run(); err != nil {
		return err
	}

	cfg.VPNEnabled = wantVPN

	// Only ask VPN details if enabled
	if wantVPN {
		form3 := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().
					Title("VPN Provider").
					Description("Select your VPN service (Gluetun supports 30+ providers). Credentials configured after init.").
					Options(
						huh.NewOption("NordVPN", "nordvpn"),
						huh.NewOption("Mullvad", "mullvad"),
						huh.NewOption("Private Internet Access (PIA)", "pia"),
						huh.NewOption("Surfshark", "surfshark"),
						huh.NewOption("ProtonVPN", "protonvpn"),
						huh.NewOption("ExpressVPN", "expressvpn"),
						huh.NewOption("Windscribe", "windscribe"),
						huh.NewOption("IPVanish", "ipvanish"),
						huh.NewOption("CyberGhost", "cyberghost"),
						huh.NewOption("IVPN", "ivpn"),
						huh.NewOption("TorGuard", "torguard"),
						huh.NewOption("VyprVPN", "vyprvpn"),
						huh.NewOption("PureVPN", "purevpn"),
						huh.NewOption("HideMyAss (HMA)", "hidemyass"),
						huh.NewOption("Perfect Privacy", "perfectprivacy"),
						huh.NewOption("AirVPN", "airvpn"),
						huh.NewOption("Custom/OpenVPN", "custom"),
					).
					Value(&cfg.VPNProvider),

				huh.NewInput().
					Title("VPN Server Country").
					Description("Preferred VPN exit location").
					Placeholder("France").
					Value(&cfg.VPNCountry),
			).Title("VPN Details"),
		)

		if err := form3.Run(); err != nil {
			return err
		}
	} else {
		var acknowledge bool
		if err := huh.NewConfirm().
			Title("Continue without VPN protection?").
			Description(
				"qBittorrent peer traffic will use the host public IP. " +
					"Only continue if this is intentional.",
			).
			Value(&acknowledge).
			Run(); err != nil {
			return fmt.Errorf("VPN acknowledgement prompt failed: %w", err)
		}
		if err := validateDownloadProtection(false, acknowledge); err != nil {
			return err
		}
	}

	// Step 6: Timezone
	form4 := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Timezone").
				Description("System timezone for all services").
				Placeholder("Europe/Paris").
				Value(&cfg.Timezone).
				Validate(validateWizardTimezone),
		).Title("System Configuration"),
	)

	if err := form4.Run(); err != nil {
		return err
	}

	// Step 7: Select an explicit automation preset, including "none".
	collection, err := presets.Load()
	if err != nil {
		return fmt.Errorf("failed to load automation presets: %w", err)
	}
	presetChoice := ""
	presetOptions := []huh.Option[string]{
		huh.NewOption("Choose an automation policy…", ""),
		huh.NewOption("None — select individual addons only", "none"),
	}
	for _, preset := range collection.Presets {
		presetOptions = append(
			presetOptions,
			huh.NewOption(
				fmt.Sprintf("%s (%d addons)", preset.Title, len(preset.Addons)),
				preset.Name,
			),
		)
	}
	formPreset := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Automation Preset").
				Description("Presets are visible choices; none is a valid policy.").
				Options(presetOptions...).
				Value(&presetChoice).
				Validate(func(value string) error {
					if value == "" {
						return fmt.Errorf("choose a named preset or none")
					}
					return nil
				}),
		).Title("Automation"),
	)
	if err := formPreset.Run(); err != nil {
		return err
	}
	if err := applyInitPreset(cfg, presetChoice, nil); err != nil {
		return err
	}

	// Step 8: Addons - Load from registry and start from the selected preset.
	addonOptions, err := getAddonOptions(ctx, reg)
	if err != nil {
		return fmt.Errorf("failed to load addons: %w", err)
	}

	selectedAddons := append([]string(nil), cfg.Addons...)
	form5 := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Optional Addons").
				Description("Select additional services to enable").
				Options(addonOptions...).
				Value(&selectedAddons),
		).Title("Addons"),
	)

	if err := form5.Run(); err != nil {
		return err
	}

	cfg.Addons = selectedAddons

	return nil
}

func applyWizardDefaults(cfg *config.Config) {
	if strings.TrimSpace(cfg.AdminUser) == "" {
		cfg.AdminUser = "admin"
	}
}

func validateWizardCandidate(apply func(*config.Config)) error {
	candidate := config.DefaultConfig()
	apply(candidate)
	return candidate.Validate()
}

func validateWizardDomain(value string) error {
	return validateWizardCandidate(func(candidate *config.Config) {
		candidate.Domain = value
	})
}

func validateWizardBaseDomain(value string) error {
	return validateWizardCandidate(func(candidate *config.Config) {
		candidate.Routing.Strategy = config.RoutingStrategyPath
		candidate.Routing.BaseDomain = value
	})
}

func validateWizardAdminUser(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("admin username is required")
	}
	return validateWizardCandidate(func(candidate *config.Config) {
		candidate.AdminUser = value
	})
}

func validateWizardTimezone(value string) error {
	return validateWizardCandidate(func(candidate *config.Config) {
		candidate.Timezone = value
	})
}

func validateWizardManagedPath(field string, value string) error {
	var apply func(*config.Config)
	switch field {
	case "config_path":
		apply = func(candidate *config.Config) {
			candidate.ConfigPath = value
		}
	case "downloads_path":
		apply = func(candidate *config.Config) {
			candidate.DownloadsPath = value
		}
	case "media_path":
		apply = func(candidate *config.Config) {
			candidate.MediaPath = value
		}
	default:
		return fmt.Errorf("unsupported wizard managed path %q", field)
	}
	return validateWizardCandidate(apply)
}

// getAddonOptions loads addon options from the registry
func getAddonOptions(
	ctx context.Context,
	reg *registry.Registry,
) ([]huh.Option[string], error) {
	services, err := reg.ListServices(ctx)
	if err != nil {
		return nil, err
	}

	var options []huh.Option[string]
	for _, svc := range services {
		if svc.IsAddon {
			label := fmt.Sprintf("%s - %s", capitalizeFirst(svc.Name), svc.Description)
			options = append(options, huh.NewOption(label, svc.Name))
		}
	}

	return options, nil
}

// capitalizeFirst capitalizes the first letter of a string
func capitalizeFirst(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// printConfigSummary prints a styled configuration summary
func printConfigSummary(cfg *config.Config) {
	fmt.Println()

	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(tui.ColorPrimary).
		MarginBottom(1)

	labelStyle := lipgloss.NewStyle().
		Foreground(tui.ColorMuted).
		Width(14)

	valueStyle := lipgloss.NewStyle().
		Foreground(tui.ColorText)

	fmt.Println(headerStyle.Render("CONFIGURATION // REVIEW BEFORE WRITE"))

	printRow := func(label, value string) {
		fmt.Printf("  %s %s\n", labelStyle.Render(label+":"), valueStyle.Render(value))
	}

	printRow("Domain", cfg.Domain)
	printRow("Admin User", cfg.AdminUser)
	exposeMode := cfg.Expose.Mode
	if exposeMode == config.ExposeModeCloudflared {
		exposeMode += " (remote-managed)"
	}
	printRow("Expose Mode", exposeMode)
	printRow("Routing", cfg.Routing.Strategy)

	if cfg.Routing.Strategy == config.RoutingStrategyPath {
		printRow("Base Domain", fmt.Sprintf("%s.%s", cfg.Routing.BaseDomain, cfg.Domain))
	}

	printRow("Media Path", cfg.MediaPath)

	if cfg.VPNEnabled {
		printRow("VPN", fmt.Sprintf("%s (%s)", cfg.VPNProvider, cfg.VPNCountry))
	} else {
		printRow("VPN", tui.WarningStyle.Render("disabled — torrent traffic is unprotected"))
	}
	printRow("Peer Port", fmt.Sprintf("%d/tcp+udp", cfg.TorrentPort))

	printRow("Timezone", cfg.Timezone)

	if len(cfg.Addons) > 0 {
		printRow("Addons", strings.Join(cfg.Addons, ", "))
	}

	fmt.Println()
}

func validateDownloadProtection(vpnEnabled, acknowledged bool) error {
	if vpnEnabled || acknowledged {
		return nil
	}
	return fmt.Errorf(
		"refusing unprotected torrent traffic; enable VPN or pass --allow-unprotected-downloads after reviewing the exposure",
	)
}

func validateACMEContactEmail(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("ACME contact email is required for direct exposure")
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value {
		return fmt.Errorf("enter one plain email address")
	}
	return nil
}

// printSuccessMessage prints the success message with next steps
func printSuccessMessage(cfg *config.Config, graph *registry.ResolutionGraph) {
	var steps []string
	step := 1

	autheliaURL := "the Authelia route shown in the deployment preview"
	if resolved := graph.Services["authelia"]; resolved != nil &&
		resolved.Enabled &&
		resolved.FinalDefinition != nil {
		autheliaURL = sdbxrouting.URL(cfg, resolved.FinalDefinition)
	}

	if cfg.VPNEnabled {
		steps = append(steps, fmt.Sprintf(
			"%d. Add VPN provider credentials to %s",
			step,
			tui.CommandStyle.Render(filepath.Join(cfg.ConfigPath, "gluetun", "gluetun.env")),
		))
		step++
	}

	if cfg.Expose.Mode == config.ExposeModeCloudflared {
		steps = append(steps, fmt.Sprintf(
			"%d. Configure every Published application mapping shown by %s",
			step,
			tui.CommandStyle.Render("sdbx tunnel routes"),
		))
		step++
		steps = append(steps, fmt.Sprintf(
			"%d. Add the remote-managed tunnel connector token to %s",
			step,
			tui.CommandStyle.Render(filepath.Join(cfg.SecretsPath, "cloudflared_tunnel_token.txt")),
		))
		step++
	}

	if cfg.PlexEnabled {
		steps = append(steps, fmt.Sprintf(
			"%d. Add a fresh Plex claim token to %s before first start",
			step,
			tui.CommandStyle.Render(filepath.Join(cfg.SecretsPath, "plex_claim_token.txt")),
		))
		step++
	}

	steps = append(steps, fmt.Sprintf("%d. Run %s to start services", step, tui.CommandStyle.Render("sdbx up")))
	step++

	steps = append(steps, fmt.Sprintf(
		"%d. Run %s after services settle to apply idempotent credentials and integrations",
		step,
		tui.CommandStyle.Render("sdbx integrate"),
	))
	step++

	steps = append(steps, fmt.Sprintf("%d. Login at %s (User: %s)", step, tui.CommandStyle.Render(autheliaURL), cfg.AdminUser))
	step++

	steps = append(steps, fmt.Sprintf("%d. Run %s to verify setup", step, tui.CommandStyle.Render("sdbx doctor")))

	message := strings.Join(steps, "\n")
	fmt.Print(tui.RenderSuccessBox("Project initialized successfully!", message))
	fmt.Println()
}

// generateArgon2Hash generates an Argon2id hash compatible with Authelia.
// The caller retains ownership of password and must zero it after this call.
func generateArgon2Hash(password []byte) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Authelia defaults: time=3, memory=64MB, threads=4, keyLen=32
	time := uint32(3)
	memory := uint32(64 * 1024)
	threads := uint8(4)
	keyLen := uint32(32)

	hash := argon2.IDKey(password, salt, time, memory, threads, keyLen)
	defer zeroBytes(hash)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memory, time, threads, b64Salt, b64Hash), nil
}

func validateAdminPassword(password string) error {
	return validateAdminPasswordBytes([]byte(password))
}

func validateAdminPasswordBytes(password []byte) error {
	if len(password) < 12 {
		return fmt.Errorf("admin password must be at least 12 characters")
	}

	common := map[string]bool{
		"admin":         true,
		"password":      true,
		"changeme":      true,
		"sdbx":          true,
		"seedbox":       true,
		"administrator": true,
	}
	trimmed := bytes.TrimSpace(password)
	for candidate := range common {
		if bytes.EqualFold(trimmed, []byte(candidate)) {
			return fmt.Errorf("admin password is too common")
		}
	}

	return nil
}
