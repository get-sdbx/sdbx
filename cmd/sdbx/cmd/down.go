package cmd

import (
	"fmt"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/docker"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
)

var downCmd = &cobra.Command{
	Use:   "down",
	Short: "Stop all SDBX services",
	Long:  `Stop all running SDBX services while preserving application data.`,
	Args:  cobra.NoArgs,
	RunE:  runDown,
}

func init() {
	rootCmd.AddCommand(downCmd)
}

func runDown(command *cobra.Command, _ []string) error {
	// Find project directory
	projectDir, err := config.ProjectDir()
	if err != nil {
		return err
	}

	compose := docker.NewCompose(projectDir)

	fmt.Println(tui.InfoStyle.Render("Stopping SDBX services..."))

	if err := compose.Down(commandContext(command)); err != nil {
		return fmt.Errorf("failed to stop services: %w", err)
	}

	fmt.Println()
	fmt.Println(tui.SuccessStyle.Render("✓ All services stopped"))

	return nil
}
