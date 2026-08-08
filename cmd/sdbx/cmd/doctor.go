package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/doctor"
	"github.com/get-sdbx/sdbx/internal/generator"
	"github.com/get-sdbx/sdbx/internal/redact"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run diagnostic checks on your SDBX installation",
	Long: `Run a series of diagnostic checks to verify your SDBX installation.

Checks include:
  • Docker and Docker Compose versions
  • Disk space availability
  • File permissions
  • Port availability
  • Project file integrity
  • Secrets configuration
  • VPN connectivity (if services running)`,
	Args: cobra.NoArgs,
	RunE: runDoctor,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

type doctorJSONReport struct {
	Healthy bool              `json:"healthy"`
	Summary doctorJSONSummary `json:"summary"`
	Checks  []doctorJSONCheck `json:"checks"`
}

type doctorJSONSummary struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Warning int `json:"warning"`
	Failed  int `json:"failed"`
}

type doctorJSONCheck struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	DurationMS  int64  `json:"duration_ms"`
}

func runDoctor(command *cobra.Command, _ []string) error {
	ctx := command.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	verified, err := loadVerifiedProject(ctx)
	var doc *doctor.Doctor
	if err != nil && !config.IsProjectNotFoundError(err) {
		return err
	} else if err != nil {
		// Host-only diagnostics remain useful before init. Once a project is
		// present, the verified graph and lock are mandatory.
		doc = doctor.NewDoctor(".")
	} else {
		composeModel, composeErr := generator.NewComposeGeneratorWithLock(
			verified.Project.Config,
			verified.Project.Registry,
			verified.Lock,
		).Generate(verified.Graph)
		if composeErr != nil {
			return fmt.Errorf("build diagnostic Compose model: %w", composeErr)
		}
		doc = doctor.NewProjectDoctor(
			verified.Project.Dir,
			verified.Project.Config,
			verified.Graph,
			composeModel,
		)
	}

	// Header
	if !IsJSONOutput() {
		titleStyle := lipgloss.NewStyle().
			Bold(true).
			Foreground(tui.ColorPrimary)
		fmt.Println(titleStyle.Render("SDBX Doctor // trace the ghost"))
		fmt.Println()
		fmt.Println(tui.MutedStyle.Render("Running diagnostics..."))
		fmt.Println()
	}

	// Run checks
	checks := doc.RunAll(ctx)
	report := buildDoctorReport(checks)

	// JSON output
	if IsJSONOutput() {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("encode diagnostic report: %w", err)
		}
		fmt.Println(string(data))
		if !report.Healthy {
			return markCLIErrorReported(fmt.Errorf(
				"%d diagnostic check(s) failed; inspect checks[].remediation",
				report.Summary.Failed,
			))
		}
		return nil
	}

	// Display results
	for index, check := range checks {
		var icon string
		var style lipgloss.Style

		switch check.Status {
		case doctor.StatusPassed:
			icon = tui.IconSuccess
			style = tui.SuccessStyle
		case doctor.StatusWarning:
			icon = tui.IconWarning
			style = tui.WarningStyle
		case doctor.StatusFailed:
			icon = tui.IconError
			style = tui.ErrorStyle
		default:
			icon = "○"
			style = tui.MutedStyle
		}

		// Format: ✓ Check name          message (duration)
		nameWidth := 25
		name := check.Name
		if len(name) > nameWidth {
			name = name[:nameWidth-3] + "..."
		}
		for len(name) < nameWidth {
			name += " "
		}

		durationStr := ""
		if check.Duration > 0 {
			durationStr = fmt.Sprintf(" (%s)", check.Duration.Round(time.Millisecond))
		}

		fmt.Printf("  %s %s %s%s\n",
			style.Render(icon),
			name,
			report.Checks[index].Message,
			tui.MutedStyle.Render(durationStr),
		)
		if report.Checks[index].Remediation != "" {
			fmt.Printf("    %s %s\n", tui.IconArrow, report.Checks[index].Remediation)
		}
	}

	// Summary
	fmt.Println()
	if report.Healthy {
		fmt.Println(tui.SuccessStyle.Render(fmt.Sprintf("✓ All %d checks passed", report.Summary.Passed)))
	} else {
		fmt.Println(tui.ErrorStyle.Render(fmt.Sprintf(
			"✗ %d of %d checks failed",
			report.Summary.Failed,
			report.Summary.Total,
		)))
		fmt.Println()
		fmt.Println(tui.MutedStyle.Render("Fix the failed checks and run 'sdbx doctor' again."))
		return markCLIErrorReported(fmt.Errorf(
			"%d diagnostic check(s) failed",
			report.Summary.Failed,
		))
	}

	return nil
}

func buildDoctorReport(checks []doctor.Check) doctorJSONReport {
	report := doctorJSONReport{
		Healthy: true,
		Summary: doctorJSONSummary{Total: len(checks)},
		Checks:  make([]doctorJSONCheck, 0, len(checks)),
	}
	for _, check := range checks {
		status := doctorStatusName(check.Status)
		switch check.Status {
		case doctor.StatusPassed:
			report.Summary.Passed++
		case doctor.StatusWarning:
			report.Summary.Warning++
		case doctor.StatusFailed:
			report.Summary.Failed++
			report.Healthy = false
		default:
			report.Healthy = false
		}
		report.Checks = append(report.Checks, doctorJSONCheck{
			Name:        check.Name,
			Status:      status,
			Message:     redact.Text(check.Message),
			Remediation: redact.Text(doctorRemediation(check.Name, check.Status)),
			DurationMS:  check.Duration.Milliseconds(),
		})
	}
	return report
}

func doctorStatusName(status doctor.CheckStatus) string {
	switch status {
	case doctor.StatusPending:
		return "pending"
	case doctor.StatusRunning:
		return "running"
	case doctor.StatusPassed:
		return "passed"
	case doctor.StatusWarning:
		return "warning"
	case doctor.StatusFailed:
		return "failed"
	default:
		return "unknown"
	}
}

func doctorRemediation(name string, status doctor.CheckStatus) string {
	if status != doctor.StatusFailed {
		return ""
	}
	switch name {
	case "Docker version":
		return "Install or upgrade Docker Engine to version 24 or newer."
	case "Docker Compose version":
		return "Install or upgrade the Docker Compose plugin to version 2.20 or newer."
	case "Disk space":
		return "Free disk space on the project filesystem before deploying or updating."
	case "File permissions":
		return "Run SDBX as the project owner and repair ownership or modes reported above."
	case "Required ports":
		return "Stop the conflicting listener or choose a deployment profile that does not publish the port."
	case "Docker daemon":
		return "Start Docker and verify the current user can access the daemon."
	case "Service health":
		return "Run 'sdbx up', inspect 'sdbx status', and review logs for stopped or unhealthy services."
	case "Project files":
		return "Run 'sdbx generate' after reviewing .sdbx.yaml and .sdbx.lock."
	case "Configured paths":
		return "Create or correct the configured data, download, media, config, and secret paths."
	case "*arr auth consistency":
		return "Run 'sdbx generate' to repair SDBX-managed API authentication settings."
	case "Secrets configured":
		return "Run 'sdbx generate' and configure any provider-owned credentials still reported missing."
	case "Cloudflare routing":
		return "Run 'sdbx tunnel routes', reconcile every Published application route in Cloudflare, then retry."
	case "VPN connectivity":
		return "Run 'sdbx vpn status' and repair Gluetun before allowing download traffic."
	default:
		return "Resolve the reported condition and rerun 'sdbx doctor'."
	}
}
