package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/get-sdbx/sdbx/internal/addons"
	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
)

var addonCmd = &cobra.Command{
	Use:   "addon",
	Short: "Manage SDBX addons",
	Long: `Manage optional SDBX services (addons).

Addons are optional services that extend SDBX functionality.
Use 'sdbx addon search' to find available addons from all sources.

Examples:
  sdbx addon list                  # List enabled addons
  sdbx addon list --all            # List all available addons
  sdbx addon search media          # Search for media-related addons
  sdbx addon info sonarr           # Show addon details
  sdbx addon enable sonarr         # Enable an addon
  sdbx addon disable sonarr        # Disable an addon`,
}

var addonListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available and enabled addons",
	Args:  cobra.NoArgs,
	RunE:  runAddonList,
}

var addonSearchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search for addons across all sources",
	Long: `Search for addons by name, description, or category.

Examples:
  sdbx addon search               # List all addons
  sdbx addon search media         # Search for media-related addons
  sdbx addon search --category media`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAddonSearch,
}

var addonInfoCmd = &cobra.Command{
	Use:   "info <addon>",
	Short: "Show detailed addon information",
	Args:  cobra.ExactArgs(1),
	RunE:  runAddonInfo,
}

var addonEnableCmd = &cobra.Command{
	Use:   "enable <addon>",
	Short: "Enable an addon",
	Long: `Enable an optional addon service.

After enabling, run 'sdbx up' to start the addon.`,
	Args: cobra.ExactArgs(1),
	RunE: runAddonEnable,
}

var addonDisableCmd = &cobra.Command{
	Use:   "disable <addon>",
	Short: "Disable an addon",
	Long: `Disable an optional addon service.

After disabling, run 'sdbx up' to converge the locked graph and remove the
retired container. Application data is preserved.`,
	Args: cobra.ExactArgs(1),
	RunE: runAddonDisable,
}

// Flags
var (
	addonListAll  bool
	addonCategory string
)

func init() {
	rootCmd.AddCommand(addonCmd)
	addonCmd.AddCommand(addonListCmd)
	addonCmd.AddCommand(addonSearchCmd)
	addonCmd.AddCommand(addonInfoCmd)
	addonCmd.AddCommand(addonEnableCmd)
	addonCmd.AddCommand(addonDisableCmd)

	// Flags
	addonListCmd.Flags().BoolVarP(&addonListAll, "all", "a", false, "Show all available addons")
	addonSearchCmd.Flags().StringVarP(&addonCategory, "category", "c", "", "Filter by category")
}

func runAddonList(command *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	ctx := commandContext(command)

	// Get addons from registry
	reg, err := getRegistry()
	if err != nil {
		return err
	}

	services, err := reg.ListServices(ctx)
	if err != nil {
		return fmt.Errorf("failed to list services: %w", err)
	}

	// Filter to addons only
	var addons []registry.ServiceInfo
	for _, svc := range services {
		if svc.IsAddon {
			addons = append(addons, svc)
		}
	}

	// JSON output
	if IsJSONOutput() {
		result := make([]map[string]interface{}, 0, len(addons))
		for _, addon := range addons {
			if !addonListAll && !cfg.IsAddonEnabled(addon.Name) {
				continue
			}
			result = append(result, map[string]interface{}{
				"name":        addon.Name,
				"description": addon.Description,
				"category":    addon.Category,
				"source":      addon.Source,
				"enabled":     cfg.IsAddonEnabled(addon.Name),
			})
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	if addonListAll {
		fmt.Println(tui.TitleStyle.Render("Available Addons"))
	} else {
		fmt.Println(tui.TitleStyle.Render("Enabled Addons"))
	}
	fmt.Println()

	enabled := 0
	displayed := 0
	for _, addon := range addons {
		isEnabled := cfg.IsAddonEnabled(addon.Name)

		if !addonListAll && !isEnabled {
			continue
		}

		var icon, status string
		var style = tui.MutedStyle

		if isEnabled {
			icon = tui.IconRunning
			status = "enabled"
			style = tui.SuccessStyle
			enabled++
		} else {
			icon = tui.IconStopped
			status = "available"
		}

		fmt.Printf("  %s %-14s %s  %s\n",
			style.Render(icon),
			tui.EscapeText(addon.Name),
			tui.MutedStyle.Render(status),
			tui.MutedStyle.Render("— "+tui.EscapeText(addon.Description)),
		)
		displayed++
	}

	if displayed == 0 {
		fmt.Println(tui.MutedStyle.Render("  No addons enabled"))
		fmt.Println()
		fmt.Printf("Use '%s' to see available addons\n", tui.CommandStyle.Render("sdbx addon list --all"))
	} else {
		fmt.Println()
		fmt.Printf("%s enabled, %s available\n",
			tui.SuccessStyle.Render(fmt.Sprintf("%d", enabled)),
			tui.MutedStyle.Render(fmt.Sprintf("%d", len(addons)-enabled)),
		)
	}

	return nil
}

func runAddonSearch(command *cobra.Command, args []string) error {
	query := ""
	if len(args) > 0 {
		query = args[0]
	}

	ctx := commandContext(command)

	reg, err := getRegistry()
	if err != nil {
		return err
	}

	var category registry.ServiceCategory
	if addonCategory != "" {
		category = registry.ServiceCategory(addonCategory)
	}

	results, err := reg.SearchServices(ctx, query, category)
	if err != nil {
		return fmt.Errorf("search failed: %w", err)
	}

	// Filter to addons only
	var addons []registry.ServiceInfo
	for _, svc := range results {
		if svc.IsAddon {
			addons = append(addons, svc)
		}
	}

	// JSON output
	if IsJSONOutput() {
		data, _ := json.MarshalIndent(addons, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	if len(addons) == 0 {
		fmt.Println(tui.MutedStyle.Render("No addons found matching your query"))
		return nil
	}

	if query != "" {
		fmt.Println(tui.TitleStyle.Render(
			fmt.Sprintf("Search Results for '%s'", tui.EscapeText(query)),
		))
	} else {
		fmt.Println(tui.TitleStyle.Render("Available Addons"))
	}
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
		tui.MutedStyle.Render("NAME"),
		tui.MutedStyle.Render("CATEGORY"),
		tui.MutedStyle.Render("SOURCE"),
		tui.MutedStyle.Render("DESCRIPTION"),
	)

	for _, addon := range addons {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			tui.SuccessStyle.Render(tui.EscapeText(addon.Name)),
			tui.RenderCategory(string(addon.Category)),
			tui.MutedStyle.Render(tui.EscapeText(addon.Source)),
			truncateDesc(tui.EscapeText(addon.Description), 40),
		)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("render addon list: %w", err)
	}

	fmt.Println()
	fmt.Printf("%s %d addons. Use '%s' for details.\n",
		tui.IconPackage,
		len(addons),
		tui.CommandStyle.Render("sdbx addon info <name>"),
	)

	return nil
}

func runAddonInfo(command *cobra.Command, args []string) error {
	addonName := args[0]

	ctx := commandContext(command)

	reg, err := getRegistry()
	if err != nil {
		return err
	}

	def, source, err := reg.GetService(ctx, addonName)
	if err != nil {
		return fmt.Errorf("addon not found: %s", addonName)
	}

	if !def.Conditions.RequireAddon {
		return fmt.Errorf("%s is a core service, not an addon", addonName)
	}

	cfg, _ := config.Load()
	isEnabled := cfg != nil && cfg.IsAddonEnabled(addonName)

	// JSON output
	if IsJSONOutput() {
		result := map[string]interface{}{
			"name":        def.Metadata.Name,
			"version":     def.Metadata.Version,
			"description": def.Metadata.Description,
			"category":    def.Metadata.Category,
			"source":      source,
			"homepage":    def.Metadata.Homepage,
			"image":       def.Spec.Image.Repository + ":" + def.Spec.Image.Tag,
			"port":        def.Routing.Port,
			"enabled":     isEnabled,
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	fmt.Println(tui.TitleStyle.Render(
		tui.IconPackage + " " + tui.EscapeText(def.Metadata.Name),
	))
	fmt.Println()

	// Status badge
	if isEnabled {
		fmt.Printf("  %s  %s  %s\n",
			tui.SuccessStyle.Render(tui.IconRunning+" enabled"),
			tui.MutedStyle.Render("|"),
			tui.RenderCategory(string(def.Metadata.Category)),
		)
	} else {
		fmt.Printf("  %s  %s  %s\n",
			tui.MutedStyle.Render(tui.IconStopped+" not enabled"),
			tui.MutedStyle.Render("|"),
			tui.RenderCategory(string(def.Metadata.Category)),
		)
	}
	fmt.Println()

	// Description
	fmt.Println(tui.MutedStyle.Render("  " + tui.EscapeText(def.Metadata.Description)))
	fmt.Println()

	// Details section
	fmt.Println(tui.RenderSection("  Details"))
	fmt.Printf("  %s\n", tui.RenderKeyValue("Version", def.Metadata.Version))
	fmt.Printf("  %s\n", tui.RenderKeyValue("Source", source))
	fmt.Printf("  %s\n", tui.RenderKeyValue("Image", def.Spec.Image.Repository+":"+def.Spec.Image.Tag))
	if def.Routing.Enabled {
		fmt.Printf("  %s\n", tui.RenderKeyValue("Port", fmt.Sprintf("%d", def.Routing.Port)))
	}
	fmt.Println()

	if def.Routing.Enabled {
		fmt.Println(tui.RenderSection("  " + tui.IconNetwork + " Routing"))
		fmt.Printf("  %s\n", tui.RenderKeyValue("Subdomain", def.Routing.Subdomain))
		fmt.Printf("  %s\n", tui.RenderKeyValue("Path", def.Routing.Path))
		fmt.Printf("  %s\n", tui.RenderKeyValue("Auth", string(def.Routing.Auth.Mode)))
		fmt.Println()
	}

	if def.Metadata.Homepage != "" {
		fmt.Println(tui.RenderSection("  Links"))
		fmt.Printf("  %s\n", tui.RenderKeyValue("Homepage", def.Metadata.Homepage))
		if def.Metadata.Documentation != "" {
			fmt.Printf("  %s\n", tui.RenderKeyValue("Docs", def.Metadata.Documentation))
		}
		fmt.Println()
	}

	fmt.Println(tui.RenderDivider(50))
	if !isEnabled {
		fmt.Printf("  %s Enable with: %s\n", tui.IconArrow, tui.CommandStyle.Render("sdbx addon enable "+addonName))
	} else {
		fmt.Printf("  %s Disable with: %s\n", tui.IconArrow, tui.CommandStyle.Render("sdbx addon disable "+addonName))
	}

	return nil
}

func runAddonEnable(command *cobra.Command, args []string) error {
	addonName := args[0]

	ctx := commandContext(command)
	manager, err := newAddonManager(ctx)
	if err != nil {
		return err
	}

	result, err := manager.Enable(ctx, addonName)
	if err != nil {
		return fmt.Errorf("%w\nRun 'sdbx addon search' to see available addons", err)
	}
	if !result.Changed {
		fmt.Printf("%s Addon '%s' is already enabled\n", tui.IconInfo, addonName)
		return nil
	}

	fmt.Println(tui.SuccessStyle.Render(fmt.Sprintf("%s Enabled: %s", tui.IconSuccess, addonName)))
	fmt.Println()
	fmt.Printf("  %s Runtime files regenerated. Run %s to start the service\n",
		tui.IconArrow,
		tui.CommandStyle.Render("sdbx up"))
	if manager.Config.Expose.Mode == config.ExposeModeCloudflared {
		fmt.Printf(
			"  %s Reconcile the remote tunnel with %s before expecting a public route\n",
			tui.IconArrow,
			tui.CommandStyle.Render("sdbx tunnel routes"),
		)
	}

	return nil
}

func runAddonDisable(command *cobra.Command, args []string) error {
	addonName := args[0]

	ctx := commandContext(command)
	manager, err := newAddonManager(ctx)
	if err != nil {
		return err
	}

	result, err := manager.Disable(ctx, addonName)
	if err != nil {
		return err
	}
	if !result.Changed {
		fmt.Printf("%s Addon '%s' is not enabled\n", tui.IconInfo, addonName)
		return nil
	}

	fmt.Println(tui.SuccessStyle.Render(fmt.Sprintf("%s Disabled: %s", tui.IconSuccess, addonName)))
	fmt.Println()
	fmt.Printf("  %s Runtime files regenerated. Run %s to apply changes\n",
		tui.IconArrow,
		tui.CommandStyle.Render("sdbx up"))
	if manager.Config.Expose.Mode == config.ExposeModeCloudflared {
		fmt.Printf(
			"  %s Remove retired Published application mappings after reviewing %s\n",
			tui.IconArrow,
			tui.CommandStyle.Render("sdbx tunnel routes"),
		)
	}

	return nil
}

func newAddonManager(ctx context.Context) (*addons.Manager, error) {
	project, err := newProjectContext()
	if err != nil {
		return nil, err
	}
	lock, err := verifyProjectLock(ctx, project)
	if err != nil {
		return nil, err
	}

	return &addons.Manager{
		ProjectDir:    project.Dir,
		Config:        project.Config,
		Registry:      project.Registry,
		Lock:          lock,
		CLIVersion:    Version,
		ImageResolver: imageDigestResolverFactory(),
	}, nil
}

// getRegistry returns a registry instance
func getRegistry() (*registry.Registry, error) {
	// Use registry with default sources (embedded + configured sources)
	return registry.NewWithDefaults()
}

// truncateDesc truncates a description string
func truncateDesc(s string, maxLen int) string {
	characters := []rune(s)
	if len(characters) <= maxLen {
		return s
	}
	return string(characters[:maxLen-3]) + "..."
}
