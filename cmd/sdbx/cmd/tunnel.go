package cmd

import (
	"encoding/json"
	"fmt"

	sdbxcloudflare "github.com/get-sdbx/sdbx/internal/cloudflare"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
)

var tunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Inspect Cloudflare Tunnel requirements",
	Long: `Inspect the remotely managed Cloudflare Tunnel configuration required
by the active locked service graph. SDBX never writes Cloudflare account state
and a connector token cannot create or update published application routes.`,
}

var tunnelRoutesCmd = &cobra.Command{
	Use:   "routes",
	Short: "Show required Cloudflare published application routes",
	Long: `Show the exact public-hostname mappings that must exist in the
Cloudflare dashboard for the active locked graph.

Every hostname targets the private http://traefik:8081 origin on the SDBX edge
network. Run this command after changing media services, addons, domains, or
routing strategy, then reconcile the remotely managed tunnel before deployment.`,
	Args: cobra.NoArgs,
	RunE: runTunnelRoutes,
}

func init() {
	rootCmd.AddCommand(tunnelCmd)
	tunnelCmd.AddCommand(tunnelRoutesCmd)
}

func runTunnelRoutes(command *cobra.Command, _ []string) error {
	verified, err := loadVerifiedProject(command.Context())
	if err != nil {
		return err
	}
	plan, err := sdbxcloudflare.BuildPlan(
		verified.Project.Config,
		verified.Graph,
	)
	if err != nil {
		return err
	}

	if IsJSONOutput() {
		data, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			return fmt.Errorf("encode Cloudflare route plan: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	fmt.Println(tui.TitleStyle.Render("Cloudflare Tunnel Routes"))
	fmt.Println()
	fmt.Println(tui.MutedStyle.Render(
		"Management: remote (Cloudflare dashboard or API)",
	))
	fmt.Println(tui.MutedStyle.Render(
		"The tunnel token runs the connector; it cannot configure these routes.",
	))
	fmt.Println()
	for _, route := range plan.Routes {
		fmt.Printf("  %-36s → %s\n", route.Hostname, route.Service)
	}
	fmt.Println()
	fmt.Println(tui.MutedStyle.Render(
		"Create one Published application route per hostname, then run 'sdbx doctor'.",
	))
	return nil
}
