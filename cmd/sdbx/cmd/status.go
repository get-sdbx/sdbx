package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/get-sdbx/sdbx/internal/docker"
	"github.com/get-sdbx/sdbx/internal/registry"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show status of all SDBX services",
	Long: `Display the current status of all SDBX services.

Shows:
  • Service name and health status
  • Container state (running/stopped)
  • Port mappings
  • VPN connection status`,
	Args: cobra.NoArgs,
	RunE: runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

type statusCompose interface {
	PS(context.Context) ([]docker.Service, error)
}

var statusComposeFactory = func(projectDir string) statusCompose {
	return docker.NewCompose(projectDir)
}

type serviceStatus struct {
	Name          string `json:"name"`
	Category      string `json:"category"`
	Route         string `json:"route,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
	Status        string `json:"status"`
	Health        string `json:"health,omitempty"`
	Ports         string `json:"ports,omitempty"`
	Image         string `json:"image,omitempty"`
	Running       bool   `json:"running"`
	Present       bool   `json:"present"`
	ExitCode      int    `json:"exit_code,omitempty"`
}

type statusReport struct {
	Domain   string          `json:"domain"`
	Total    int             `json:"total"`
	Running  int             `json:"running"`
	Stopped  int             `json:"stopped"`
	Services []serviceStatus `json:"services"`
}

func runStatus(command *cobra.Command, _ []string) error {
	ctx := command.Context()
	verified, err := loadVerifiedProject(ctx)
	if err != nil {
		return err
	}

	containers, err := statusComposeFactory(verified.Project.Dir).PS(ctx)
	if err != nil {
		return fmt.Errorf("failed to get service status: %w", err)
	}
	report := buildStatusReport(verified, containers)

	if IsJSONOutput() {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("encode status report: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	// Header
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(tui.ColorPrimary).
		MarginBottom(1)

	fmt.Println(titleStyle.Render("SDBX STATUS // " + verified.Project.Config.Domain))
	fmt.Println()

	// Calculate column widths
	maxName := 20
	for _, service := range report.Services {
		if len(service.Name) > maxName {
			maxName = len(service.Name)
		}
	}

	// Header row
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(tui.ColorMuted)
	fmt.Printf("%s  %s  %s\n",
		headerStyle.Render(padRight("SERVICE", maxName)),
		headerStyle.Render(padRight("STATUS", 12)),
		headerStyle.Render("HEALTH"),
	)
	fmt.Println(strings.Repeat("─", maxName+30))

	// Service rows
	for _, service := range report.Services {
		var statusIcon, statusText string
		var statusStyle lipgloss.Style

		if service.Running {
			statusIcon = tui.IconRunning
			statusText = "running"
			statusStyle = tui.SuccessStyle
		} else if service.Present {
			statusIcon = tui.IconStopped
			statusText = service.Status
			statusStyle = tui.WarningStyle
		} else {
			statusIcon = tui.IconStopped
			statusText = "missing"
			statusStyle = tui.MutedStyle
		}

		var healthText string
		switch service.Health {
		case "healthy":
			healthText = tui.SuccessStyle.Render("✓ healthy")
		case "unhealthy":
			healthText = tui.ErrorStyle.Render("✗ unhealthy")
		case "starting":
			healthText = tui.WarningStyle.Render("◐ starting")
		default:
			healthText = tui.MutedStyle.Render("—")
		}

		fmt.Printf("%s  %s  %s\n",
			statusStyle.Render(statusIcon)+" "+padRight(service.Name, maxName-2),
			padRight(statusText, 12),
			healthText,
		)
	}

	fmt.Println()
	fmt.Println(tui.MutedStyle.Render(fmt.Sprintf(
		"Locked: %d services — %d running, %d stopped or missing",
		report.Total,
		report.Running,
		report.Stopped,
	)))

	return nil
}

func buildStatusReport(
	verified *verifiedProject,
	containers []docker.Service,
) statusReport {
	byService := make(map[string]docker.Service, len(containers))
	for _, container := range containers {
		name := container.Service
		if name == "" {
			name = matchContainerToGraph(container.Name, verified.Graph)
		}
		if name != "" {
			byService[name] = container
		}
	}
	report := statusReport{
		Domain:   verified.Project.Config.Domain,
		Total:    len(verified.Graph.Order),
		Services: make([]serviceStatus, 0, len(verified.Graph.Order)),
	}
	for _, name := range verified.Graph.Order {
		resolved := verified.Graph.Services[name]
		if resolved == nil || !resolved.Enabled || resolved.FinalDefinition == nil {
			continue
		}
		definition := resolved.FinalDefinition
		status := serviceStatus{
			Name:     name,
			Category: string(definition.Metadata.Category),
			Status:   "missing",
		}
		if definition.Routing.Enabled {
			status.Route = initServiceURL(verified.Project.Config, definition)
		}
		if container, present := byService[name]; present {
			status.ContainerName = container.Name
			status.Status = container.Status
			status.Health = container.Health
			status.Ports = container.Ports
			status.Image = container.Image
			status.Running = container.Running
			status.Present = true
			status.ExitCode = container.ExitCode
		}
		if status.Running {
			report.Running++
		} else {
			report.Stopped++
		}
		report.Services = append(report.Services, status)
	}
	report.Total = len(report.Services)
	return report
}

func matchContainerToGraph(
	containerName string,
	graph *registry.ResolutionGraph,
) string {
	for _, name := range graph.Order {
		if containerName == "sdbx-"+name ||
			strings.HasPrefix(containerName, "sdbx-"+name+"-") {
			return name
		}
	}
	return ""
}

// extractServiceName gets the service name from container name (removes project prefix)
func extractServiceName(containerName string) string {
	parts := strings.Split(containerName, "-")
	if len(parts) > 1 {
		return strings.Join(parts[1:], "-")
	}
	return containerName
}

// padRight pads a string to a minimum width
func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}
