package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/settings"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage SDBX configuration",
	Long: `View and modify SDBX configuration values.

Use 'sdbx config get' to view current settings.
Use 'sdbx config set' to modify settings.`,
}

var configGetCmd = &cobra.Command{
	Use:   "get [key]",
	Short: "Get configuration value(s)",
	Long: `Get one or all configuration values.

If no key is specified, displays every readable configuration value grouped
by the same settings metadata used by the CLI and Web UI. Run without a key
to discover the complete current key set.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runConfigGet,
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Long: `Set a configuration value.

Example:
  sdbx config set domain sdbx.example.com
  sdbx config set expose_mode cloudflared
  sdbx config set expose.tunnel_protocol http2
  sdbx config set routing.strategy path
  sdbx config set auth.factor two_factor
  sdbx config set timezone America/New_York`,
	Args: cobra.ExactArgs(2),
	RunE: runConfigSet,
}

var configAllowUnprotectedDownloads bool

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configGetCmd)
	configCmd.AddCommand(configSetCmd)
	configSetCmd.Flags().BoolVar(
		&configAllowUnprotectedDownloads,
		"allow-unprotected-downloads",
		false,
		"Acknowledge that disabling VPN exposes torrent traffic through the host public IP",
	)
}

func runConfigGet(_ *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	values := settings.Values(cfg)

	// JSON output
	if IsJSONOutput() {
		if len(args) == 1 {
			value, ok := settings.Value(cfg, args[0])
			if !ok {
				return fmt.Errorf("unknown configuration key: %s", args[0])
			}
			data, _ := json.MarshalIndent(map[string]interface{}{args[0]: value}, "", "  ")
			fmt.Println(string(data))
		} else {
			data, _ := json.MarshalIndent(values, "", "  ")
			fmt.Println(string(data))
		}
		return nil
	}

	// Single key
	if len(args) == 1 {
		key := args[0]
		value, ok := settings.Value(cfg, key)
		if !ok {
			return fmt.Errorf("unknown configuration key: %s", key)
		}
		fmt.Printf("%s = %v\n", key, value)
		return nil
	}

	// All keys
	fmt.Println(tui.TitleStyle.Render("SDBX Configuration"))
	fmt.Println()

	for _, group := range settings.ReadGroups() {
		fmt.Println(tui.InfoStyle.Render(group.Name + ":"))
		for _, key := range group.Keys {
			valueStr := fmt.Sprintf("%v", values[key])
			if valueStr == "" {
				valueStr = tui.MutedStyle.Render("(not set)")
			}
			fmt.Printf("  %-20s %s\n", key, valueStr)
		}
		fmt.Println()
	}

	return nil
}

func runConfigSet(command *cobra.Command, args []string) error {
	key := args[0]
	value := args[1]

	project, err := newProjectContext()
	if err != nil {
		return err
	}
	ctx := commandContext(command)
	lock, err := verifyProjectLock(ctx, project)
	if err != nil {
		return err
	}
	manager := &settings.Manager{
		ProjectDir:                project.Dir,
		Config:                    project.Config,
		Registry:                  project.Registry,
		Lock:                      lock,
		CLIVersion:                Version,
		ImageResolver:             imageDigestResolverFactory(),
		AllowUnprotectedDownloads: configAllowUnprotectedDownloads,
	}

	if _, err := manager.Set(ctx, key, value); err != nil {
		return fmt.Errorf("%w\nValid keys: %s", err, strings.Join(settings.ValidKeys(), ", "))
	}

	fmt.Println(tui.SuccessStyle.Render(fmt.Sprintf("✓ Set %s = %s", key, value)))
	fmt.Println(tui.MutedStyle.Render("Runtime files regenerated."))
	return nil
}
