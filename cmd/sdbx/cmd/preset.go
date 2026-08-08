package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/get-sdbx/sdbx/internal/addons"
	"github.com/get-sdbx/sdbx/internal/registry/presets"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
)

var presetCmd = &cobra.Command{
	Use:   "preset",
	Short: "Manage recommended addon stacks (tasksel-style)",
	Long: `Recommended SDBX addon stacks. Each preset bundles a coherent set of
addons under a memorable name so you can adopt a complete profile in one
command rather than enabling 15 things individually.

Built-in presets are bundled into the binary; you can override or add your
own in ~/.config/sdbx/presets.yaml. Core services (traefik, authelia, etc.)
are never part of a preset — they're always on.

Examples:
  sdbx preset list                    # show all available presets
  sdbx preset show media-plex         # show one preset's contents
  sdbx preset apply media-plex        # enable every addon in the preset
                                      # (then run sdbx up && sdbx integrate)`,
}

var presetListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available presets",
	Args:  cobra.NoArgs,
	RunE:  runPresetList,
}

var presetShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show one preset's addons + description",
	Args:  cobra.ExactArgs(1),
	RunE:  runPresetShow,
}

var presetApplyCmd = &cobra.Command{
	Use:   "apply <name>",
	Short: "Enable every addon in the named preset (idempotent)",
	Long: `Enable every addon in the named preset. Already-enabled addons are kept
as-is; addons not in the registry are reported and skipped. Runtime files
are regenerated once at the end (not per-addon).

After applying, run:
  sdbx up         # start the new containers
  sdbx integrate  # wire up service-to-service integrations`,
	Args: cobra.ExactArgs(1),
	RunE: runPresetApply,
}

func init() {
	rootCmd.AddCommand(presetCmd)
	presetCmd.AddCommand(presetListCmd)
	presetCmd.AddCommand(presetShowCmd)
	presetCmd.AddCommand(presetApplyCmd)
}

func runPresetList(_ *cobra.Command, _ []string) error {
	col, err := presets.Load()
	if err != nil {
		return fmt.Errorf("load presets: %w", err)
	}

	if IsJSONOutput() {
		out, _ := json.MarshalIndent(col.Presets, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	fmt.Println(tui.TitleStyle.Render("Recommended addon stacks"))
	fmt.Println()
	fmt.Println(tui.MutedStyle.Render("Each preset bundles a coherent set of addons. Apply with `sdbx preset apply <name>`."))
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w,
		tui.TableHeaderStyle.Render("NAME")+"\t"+
			tui.TableHeaderStyle.Render("TITLE")+"\t"+
			tui.TableHeaderStyle.Render("ADDONS"))
	for _, p := range col.Presets {
		titleWithIcon := strings.TrimSpace(p.Icon + " " + p.Title)
		fmt.Fprintf(w, "%s\t%s\t%d\n", p.Name, titleWithIcon, len(p.Addons))
	}
	_ = w.Flush()
	fmt.Println()
	fmt.Println(tui.MutedStyle.Render("Run `sdbx preset show <name>` for the full description + addon list."))
	return nil
}

func runPresetShow(_ *cobra.Command, args []string) error {
	col, err := presets.Load()
	if err != nil {
		return fmt.Errorf("load presets: %w", err)
	}
	p := col.Find(args[0])
	if p == nil {
		return fmt.Errorf("preset not found: %s (try `sdbx preset list`)", args[0])
	}

	if IsJSONOutput() {
		out, _ := json.MarshalIndent(p, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	header := strings.TrimSpace(p.Icon + " " + p.Title)
	fmt.Println(tui.TitleStyle.Render(header))
	fmt.Println()
	fmt.Println(strings.TrimSpace(p.Description))
	fmt.Println()
	fmt.Printf("%s %d addon%s:\n", tui.IconArrow, len(p.Addons), plural(len(p.Addons)))
	for _, a := range p.Addons {
		fmt.Printf("  • %s\n", a)
	}
	fmt.Println()
	fmt.Printf("Apply with: %s\n", tui.CommandStyle.Render("sdbx preset apply "+p.Name))
	return nil
}

func runPresetApply(command *cobra.Command, args []string) error {
	col, err := presets.Load()
	if err != nil {
		return fmt.Errorf("load presets: %w", err)
	}
	p := col.Find(args[0])
	if p == nil {
		return fmt.Errorf("preset not found: %s (try `sdbx preset list`)", args[0])
	}

	project, err := newProjectContext()
	if err != nil {
		return err
	}
	ctx := commandContext(command)
	lock, err := verifyProjectLock(ctx, project)
	if err != nil {
		return err
	}
	mgr := &addons.Manager{
		ProjectDir:    project.Dir,
		Config:        project.Config,
		Registry:      project.Registry,
		Lock:          lock,
		CLIVersion:    Version,
		ImageResolver: imageDigestResolverFactory(),
	}

	results, err := mgr.BulkEnable(ctx, p.Addons)
	if err != nil {
		// BulkEnable rolls back changes on failure; surface results so the
		// user sees what we attempted before the rollback.
		printBulkResults(p, results)
		return err
	}

	if IsJSONOutput() {
		out := map[string]any{
			"preset":   p.Name,
			"results":  results,
			"warnings": []string{},
			"success":  true,
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	printBulkResults(p, results)

	// Next-steps hint
	fmt.Println()
	fmt.Println(tui.SuccessStyle.Render("Next:"))
	fmt.Printf("  %s %s    # start the new services\n", tui.IconArrow, tui.CommandStyle.Render("sdbx up"))
	fmt.Printf("  %s %s   # wire service-to-service integrations\n", tui.IconArrow, tui.CommandStyle.Render("sdbx integrate"))
	return nil
}

func printBulkResults(p *presets.Preset, results []addons.BulkResult) {
	if IsJSONOutput() {
		return
	}
	header := strings.TrimSpace(p.Icon + " " + p.Title)
	fmt.Println(tui.TitleStyle.Render("Applying preset: " + header))
	fmt.Println()
	enabled, kept, missing := 0, 0, 0
	for _, r := range results {
		switch r.Action {
		case "enabled":
			fmt.Printf("  %s %s\n", tui.SuccessStyle.Render("✓ enabled"), r.Name)
			enabled++
		case "already-enabled":
			fmt.Printf("  %s %s\n", tui.MutedStyle.Render("• kept (already enabled)"), r.Name)
			kept++
		case "missing-from-registry":
			fmt.Printf("  %s %s %s\n", tui.WarningStyle.Render("⚠ missing"), r.Name, tui.MutedStyle.Render("(not in registry — run `sdbx source update`?)"))
			missing++
		}
	}
	fmt.Println()
	fmt.Printf("%s %d enabled, %d kept, %d missing\n",
		tui.SuccessStyle.Render("✓"), enabled, kept, missing)
}
