package cmd

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"sort"
	"strings"

	"github.com/get-sdbx/sdbx/internal/registry"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
)

var openCmd = &cobra.Command{
	Use:   "open [service]",
	Short: "Open SDBX service URLs in browser",
	Long: `Open one or all SDBX service URLs in your default browser.

Examples:
  sdbx open          # List all URLs
  sdbx open plex     # Open Plex in browser
  sdbx open sonarr   # Open Sonarr in browser`,
	Args: cobra.MaximumNArgs(1),
	RunE: runOpen,
}

func init() {
	rootCmd.AddCommand(openCmd)
}

type openRoute struct {
	Name     string
	Category string
	URL      string
}

var openBrowserFn = openBrowser

func runOpen(command *cobra.Command, args []string) error {
	verified, err := loadVerifiedProject(command.Context())
	if err != nil {
		return err
	}
	routes, aliases := graphOpenRoutes(verified)

	if len(args) == 0 {
		fmt.Println(tui.TitleStyle.Render("SDBX Service URLs"))
		fmt.Println()
		if len(routes) == 0 {
			fmt.Println(tui.MutedStyle.Render("The active locked graph has no routed services."))
			return nil
		}
		for _, route := range routes {
			fmt.Printf("  %-20s %-14s %s\n", route.Name, route.Category, route.URL)
		}
		return nil
	}

	requested := strings.ToLower(strings.TrimSpace(args[0]))
	route, ok := aliases[requested]
	if !ok {
		if verified.Project.Config.ActiveServices[requested] {
			return fmt.Errorf(
				"service %q is active but has no browser route",
				requested,
			)
		}
		return fmt.Errorf(
			"service %q is not a routed service in the active locked graph; run 'sdbx open' to list routes",
			requested,
		)
	}

	fmt.Printf("Opening %s...\n", route.URL)
	return openBrowserFn(command.Context(), route.URL)
}

func graphOpenRoutes(
	verified *verifiedProject,
) ([]openRoute, map[string]openRoute) {
	routes := make([]openRoute, 0)
	aliases := make(map[string]openRoute)
	for _, name := range verified.Graph.Order {
		resolved := verified.Graph.Services[name]
		if resolved == nil || !resolved.Enabled || resolved.FinalDefinition == nil {
			continue
		}
		definition := resolved.FinalDefinition
		if !definition.Routing.Enabled {
			continue
		}
		route := openRoute{
			Name:     name,
			Category: string(definition.Metadata.Category),
			URL:      initServiceURL(verified.Project.Config, definition),
		}
		routes = append(routes, route)
		for _, alias := range serviceRouteAliases(definition) {
			if _, exists := aliases[alias]; !exists {
				aliases[alias] = route
			}
		}
	}
	sort.SliceStable(routes, func(i, j int) bool {
		if routes[i].Category != routes[j].Category {
			return routes[i].Category < routes[j].Category
		}
		return routes[i].Name < routes[j].Name
	})
	return routes, aliases
}

func serviceRouteAliases(definition *registry.ServiceDefinition) []string {
	aliases := []string{
		strings.ToLower(definition.Metadata.Name),
		strings.ToLower(definition.Routing.Subdomain),
		strings.ToLower(strings.TrimPrefix(definition.Routing.Path, "/")),
	}
	result := make([]string, 0, len(aliases))
	seen := make(map[string]struct{}, len(aliases))
	for _, alias := range aliases {
		if alias == "" {
			continue
		}
		if _, duplicate := seen[alias]; duplicate {
			continue
		}
		seen[alias] = struct{}{}
		result = append(result, alias)
	}
	return result
}

// openBrowser opens the specified URL in the default browser
func openBrowser(ctx context.Context, url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		// #nosec G204 -- the URL comes from the validated locked route graph
		// and remains a distinct argument to a fixed executable.
		cmd = exec.CommandContext(ctx, "open", url)
	case "linux":
		// #nosec G204 -- the URL comes from the validated locked route graph
		// and remains a distinct argument to a fixed executable.
		cmd = exec.CommandContext(ctx, "xdg-open", url)
	case "windows":
		// #nosec G204 -- the URL comes from the validated locked route graph;
		// its domain and path character sets exclude command metacharacters.
		cmd = exec.CommandContext(ctx, "cmd", "/c", "start", "", url)
	default:
		return fmt.Errorf("unsupported platform")
	}

	return cmd.Start()
}
