package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/docker"
	"github.com/get-sdbx/sdbx/internal/redact"
	"github.com/spf13/cobra"
)

var (
	logsTail   int
	logsFollow bool
)

var logsCmd = &cobra.Command{
	Use:   "logs [service]",
	Short: "View logs from SDBX services",
	Long: `View logs from one or all SDBX services.

Common credential shapes are redacted from both bounded and followed output.
Use 'sdbx secrets show SERVICE --confirm reveal' for the narrow, explicit
credential-recovery workflow.

Examples:
  sdbx logs              # All services
  sdbx logs plex         # Specific service
  sdbx logs -f sonarr    # Follow logs
  sdbx logs -n 50 sonarr # Last 50 lines`,
	Args: cobra.MaximumNArgs(1),
	RunE: runLogs,
}

func init() {
	rootCmd.AddCommand(logsCmd)
	logsCmd.Flags().IntVarP(&logsTail, "tail", "n", 100, "Number of lines to show")
	logsCmd.Flags().BoolVarP(&logsFollow, "follow", "f", false, "Follow log output")
}

func runLogs(command *cobra.Command, args []string) error {
	// Find project directory
	projectDir, err := config.ProjectDir()
	if err != nil {
		return err
	}

	service := ""
	if len(args) > 0 {
		service = args[0]
	}

	// For follow mode, use exec directly for better UX
	if logsFollow {
		cmdArgs := []string{"compose", "-f", "compose.yaml", "-p", "sdbx", "logs", "-f"}
		if logsTail > 0 {
			cmdArgs = append(cmdArgs, "--tail", fmt.Sprintf("%d", logsTail))
		}
		if service != "" {
			cmdArgs = append(cmdArgs, service)
		}

		execCmd := exec.CommandContext(command.Context(), "docker", cmdArgs...)
		execCmd.Dir = projectDir
		stdout := redact.NewLineWriter(os.Stdout)
		stderr := redact.NewLineWriter(os.Stderr)
		execCmd.Stdout = stdout
		execCmd.Stderr = stderr
		runErr := execCmd.Run()
		closeErr := errors.Join(stdout.Close(), stderr.Close())
		return errors.Join(runErr, closeErr)
	}

	// Non-follow mode
	compose := docker.NewCompose(projectDir)

	output, err := compose.Logs(command.Context(), service, logsTail, false)
	if err != nil {
		return fmt.Errorf("failed to get logs: %w", err)
	}

	fmt.Print(redact.Text(output))
	return nil
}
