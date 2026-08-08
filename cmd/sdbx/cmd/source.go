package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/get-sdbx/sdbx/internal/registry"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
)

var sourceCmd = &cobra.Command{
	Use:   "source",
	Short: "Manage service definition sources",
	Long: `Manage Git and local sources for service definitions.

SDBX loads service definitions from multiple sources, similar to Homebrew taps.
Sources are checked in priority order (highest first).

Examples:
  sdbx source list                           # List all configured sources
  sdbx source add community https://forgejo.example.com/sdbx-community/services.git \
    --ref <commit> --signing-key <fingerprint> --allow-registry docker.io
  sdbx source update                         # Re-fetch and verify pinned sources
  sdbx source remove community               # Remove a source`,
}

var sourceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured sources",
	Args:  cobra.NoArgs,
	RunE:  runSourceList,
}

var sourceAddCmd = &cobra.Command{
	Use:   "add <name> <url>",
	Short: "Add a new Git source",
	Long: `Add a new Git repository as a service definition source.

Examples:
  sdbx source add community https://forgejo.example.com/sdbx-community/services.git \
    --ref <commit> --signing-key <fingerprint> --allow-registry docker.io
  sdbx source add internal git@forgejo.example.com:company/services.git \
    --ref <commit> --signing-key <fingerprint> --priority 50 \
    --allow-permission host-network`,
	Args: cobra.ExactArgs(2),
	RunE: runSourceAdd,
}

var sourceRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a source",
	Args:  cobra.ExactArgs(1),
	RunE:  runSourceRemove,
}

var sourceUpdateCmd = &cobra.Command{
	Use:   "update [name]",
	Short: "Re-fetch and verify pinned sources",
	Long: `Re-fetch immutable Git commits and verify their signatures.

Examples:
  sdbx source update           # Verify all configured Git sources
  sdbx source update community # Verify a specific source`,
	Args: cobra.MaximumNArgs(1),
	RunE: runSourceUpdate,
}

var sourceInfoCmd = &cobra.Command{
	Use:   "info <name>",
	Short: "Show detailed source information",
	Args:  cobra.ExactArgs(1),
	RunE:  runSourceInfo,
}

// Flags
var (
	sourcePriority           int
	sourceRef                string
	sourceSigningKey         string
	sourceSSHKey             string
	sourceAllowedPermissions []string
	sourceAllowedRegistries  []string
)

func init() {
	rootCmd.AddCommand(sourceCmd)
	sourceCmd.AddCommand(sourceListCmd)
	sourceCmd.AddCommand(sourceAddCmd)
	sourceCmd.AddCommand(sourceRemoveCmd)
	sourceCmd.AddCommand(sourceUpdateCmd)
	sourceCmd.AddCommand(sourceInfoCmd)

	// Add flags
	sourceAddCmd.Flags().IntVarP(&sourcePriority, "priority", "p", 10, "Source priority (higher = checked first)")
	sourceAddCmd.Flags().StringVar(&sourceRef, "ref", "", "Exact signed Git commit (40- or 64-character hash)")
	sourceAddCmd.Flags().StringVar(&sourceSigningKey, "signing-key", "", "Expected OpenPGP or SSH signing-key fingerprint")
	sourceAddCmd.Flags().StringVar(&sourceSSHKey, "ssh-key", "", "Path to SSH key for private repos")
	sourceAddCmd.Flags().StringSliceVar(
		&sourceAllowedPermissions,
		"allow-permission",
		nil,
		"Catalog permission to grant (repeatable; for example host-network)",
	)
	sourceAddCmd.Flags().StringSliceVar(
		&sourceAllowedRegistries,
		"allow-registry",
		nil,
		"Container registry hostname the source may use (repeatable)",
	)
}

func runSourceList(_ *cobra.Command, _ []string) error {
	cfg, err := loadSourceConfig()
	if err != nil {
		return err
	}
	for _, source := range cfg.Sources {
		if err := registry.ValidateSourceConfig(source); err != nil {
			return fmt.Errorf(
				"refusing to display invalid source %q: %w",
				source.Name,
				err,
			)
		}
	}

	// JSON output
	if IsJSONOutput() {
		data, _ := json.MarshalIndent(cfg.Sources, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	fmt.Println(tui.TitleStyle.Render("Service Sources"))
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tTYPE\tPRIORITY\tREF\tURL\tSTATUS")

	for _, src := range cfg.Sources {
		status := tui.SuccessStyle.Render("active")
		if !src.Enabled {
			status = tui.MutedStyle.Render("disabled")
		}

		url := src.URL
		if src.Type == "local" {
			url = src.Path
		}

		ref := "-"
		if src.Ref != "" {
			ref = truncate(src.Ref, 12)
		}

		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\n",
			tui.EscapeText(src.Name),
			tui.EscapeText(src.Type),
			src.Priority,
			tui.EscapeText(ref),
			truncate(tui.EscapeText(url), 50),
			status,
		)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("render service sources: %w", err)
	}

	fmt.Println()
	fmt.Printf("Use '%s' to add a new source\n", tui.CommandStyle.Render("sdbx source add <name> <url>"))

	return nil
}

func runSourceAdd(_ *cobra.Command, args []string) error {
	name := args[0]
	url := args[1]
	if sourceRef == "" {
		return fmt.Errorf("--ref is required; mutable branches are not accepted")
	}
	if sourceSigningKey == "" {
		return fmt.Errorf("--signing-key is required")
	}

	cfg, err := loadSourceConfig()
	if err != nil {
		return fmt.Errorf("load source configuration: %w", err)
	}

	// Check for duplicate
	for _, src := range cfg.Sources {
		if src.Name == name {
			return fmt.Errorf("source %s already exists", name)
		}
	}

	// Add new source
	newSource := registry.Source{
		Name:       name,
		Type:       "git",
		URL:        url,
		Ref:        sourceRef,
		SigningKey: sourceSigningKey,
		SSHKey:     sourceSSHKey,
		Priority:   sourcePriority,
		Enabled:    true,
		Trust: registry.TrustLevel{
			AllowCatalogPermissions: sourceAllowedPermissions,
			AllowedRegistries:       sourceAllowedRegistries,
		},
	}
	if err := registry.ValidateSourceConfig(newSource); err != nil {
		return err
	}

	fmt.Println(tui.TitleStyle.Render("Source trust policy"))
	fmt.Printf("  %s\n", tui.RenderKeyValue("Name", newSource.Name))
	fmt.Printf("  %s\n", tui.RenderKeyValue("URL", newSource.URL))
	fmt.Printf("  %s\n", tui.RenderKeyValue("Commit", newSource.Ref))
	fmt.Printf("  %s\n", tui.RenderKeyValue("Signer", newSource.SigningKey))
	fmt.Printf(
		"  %s\n",
		tui.RenderKeyValue(
			"Registries",
			renderSourceGrants(
				newSource.Trust.AllowedRegistries,
				"none (external images denied)",
			),
		),
	)
	fmt.Printf(
		"  %s\n",
		tui.RenderKeyValue(
			"Permissions",
			renderSourceGrants(newSource.Trust.AllowCatalogPermissions, "none"),
		),
	)
	fmt.Println()

	cfg.Sources = append(cfg.Sources, newSource)

	// Save config
	if err := saveSourceConfig(cfg); err != nil {
		return err
	}

	fmt.Println(tui.SuccessStyle.Render(
		fmt.Sprintf("✓ Added source: %s", tui.EscapeText(name)),
	))
	fmt.Println()
	fmt.Printf("Run '%s' to fetch and verify the pinned catalog\n", tui.CommandStyle.Render("sdbx source update "+name))

	return nil
}

func runSourceRemove(_ *cobra.Command, args []string) error {
	name := args[0]

	// Embedded is compiled into the binary and is never stored in the user
	// source configuration. Keep the guard explicit for a clear error.
	if name == "embedded" {
		return fmt.Errorf("cannot remove built-in source: %s", name)
	}

	cfg, err := loadSourceConfig()
	if err != nil {
		return err
	}

	// Find and remove
	found := false
	newSources := make([]registry.Source, 0, len(cfg.Sources))
	for _, src := range cfg.Sources {
		if src.Name == name {
			found = true
			continue
		}
		newSources = append(newSources, src)
	}

	if !found {
		return fmt.Errorf("source %s not found", name)
	}

	cfg.Sources = newSources

	// Save config
	if err := saveSourceConfig(cfg); err != nil {
		return err
	}

	fmt.Println(tui.SuccessStyle.Render(fmt.Sprintf("✓ Removed source: %s", name)))

	return nil
}

func runSourceUpdate(command *cobra.Command, args []string) error {
	reg, err := registry.NewWithDefaults()
	if err != nil {
		return fmt.Errorf("failed to initialize registry: %w", err)
	}

	ctx := commandContext(command)

	if len(args) == 1 {
		// Update specific source
		name := args[0]
		src, err := reg.GetSource(name)
		if err != nil {
			return err
		}

		fmt.Printf("Verifying source %s...\n", name)
		if err := src.Update(ctx); err != nil {
			return fmt.Errorf("failed to verify %s: %w", name, err)
		}

		fmt.Println(tui.SuccessStyle.Render(fmt.Sprintf("✓ Verified source: %s", name)))
	} else {
		fmt.Println("Verifying all Git sources...")

		var updateErrors []error
		for _, src := range reg.Sources() {
			if src.Type() == "local" || src.Type() == "embedded" {
				continue
			}

			fmt.Printf("  Verifying %s...", src.Name())
			if err := src.Update(ctx); err != nil {
				fmt.Printf(" %s\n", tui.ErrorStyle.Render("failed"))
				updateErrors = append(updateErrors, fmt.Errorf("%s: %w", src.Name(), err))
				continue
			}
			fmt.Printf(" %s\n", tui.SuccessStyle.Render("done"))
		}

		fmt.Println()
		if len(updateErrors) > 0 {
			return fmt.Errorf("one or more sources failed verification: %w", errors.Join(updateErrors...))
		}
		fmt.Println(tui.SuccessStyle.Render("✓ All Git sources verified"))
	}

	return nil
}

func runSourceInfo(command *cobra.Command, args []string) error {
	name := args[0]

	reg, err := registry.NewWithDefaults()
	if err != nil {
		return fmt.Errorf("failed to initialize registry: %w", err)
	}

	src, err := reg.GetSource(name)
	if err != nil {
		return err
	}

	ctx := commandContext(command)
	services, err := src.ListServices(ctx)
	if err != nil {
		return err
	}

	fmt.Println(tui.TitleStyle.Render("Source: " + tui.EscapeText(name)))
	fmt.Println()

	fmt.Printf("Type:     %s\n", tui.EscapeText(src.Type()))
	fmt.Printf("Priority: %d\n", src.Priority())
	fmt.Printf("Enabled:  %t\n", src.IsEnabled())

	if gitSrc, ok := src.(*registry.GitSource); ok {
		fmt.Printf("URL:         %s\n", tui.EscapeText(gitSrc.GetURL()))
		fmt.Printf("Ref:         %s\n", gitSrc.GetRef())
		fmt.Printf("Commit:      %s\n", gitSrc.GetCommit())
		fmt.Printf("Signing key: %s\n", gitSrc.GetSigningKey())
		fmt.Printf("Verified:    %t\n", gitSrc.IsVerified())
		fmt.Printf("Checked:     %s\n", gitSrc.GetLastUpdated().Format("2006-01-02 15:04:05"))
	}

	fmt.Println()

	fmt.Printf("Services: %d\n", len(services))
	if len(services) > 0 && len(services) <= 20 {
		for _, svcName := range services {
			def, err := src.LoadService(ctx, svcName)
			if err != nil {
				return fmt.Errorf("load service %s: %w", svcName, err)
			}
			addonTag := ""
			if def.Conditions.RequireAddon {
				addonTag = tui.MutedStyle.Render(" (addon)")
			}
			fmt.Printf("  - %s%s\n", tui.EscapeText(svcName), addonTag)
		}
	}

	return nil
}

// loadSourceConfig loads the source configuration
func loadSourceConfig() (*registry.SourceConfig, error) {
	return registry.LoadDefaultSourceConfig()
}

// saveSourceConfig saves the source configuration
func saveSourceConfig(cfg *registry.SourceConfig) error {
	configPath := registry.DefaultSourceConfigPath()

	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	loader := registry.NewLoader()
	return loader.SaveSourceConfig(configPath, cfg)
}

// truncate truncates a string to maxLen
func truncate(s string, maxLen int) string {
	characters := []rune(s)
	if len(characters) <= maxLen {
		return s
	}
	return string(characters[:maxLen-3]) + "..."
}

func renderSourceGrants(grants []string, empty string) string {
	if len(grants) == 0 {
		return empty
	}
	return strings.Join(grants, ", ")
}
