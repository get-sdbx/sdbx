package cmd

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/docker"
	"github.com/get-sdbx/sdbx/internal/generator"
	"github.com/get-sdbx/sdbx/internal/registry"
	"github.com/get-sdbx/sdbx/internal/secrets"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
)

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "Start all SDBX services",
	Long: `Start all configured SDBX services using Docker Compose.

This command will:
  • Start only digest-pinned images from the verified lock
  • Start all enabled services
  • Remove containers for services no longer in the project`,
	Args: cobra.NoArgs,
	RunE: runUp,
}

func init() {
	rootCmd.AddCommand(upCmd)
}

func runUp(command *cobra.Command, _ []string) error {
	// Find project directory
	projectDir, err := config.ProjectDir()
	if err != nil {
		return err
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
	if err := registry.ValidateGeneratedFiles(
		project.Dir,
		project.Config.ConfigPath,
		lock,
	); err != nil {
		return fmt.Errorf("generated runtime verification failed: %w", err)
	}
	secretsDir := project.Config.SecretsPath
	if !filepath.IsAbs(secretsDir) {
		secretsDir = filepath.Join(project.Dir, secretsDir)
	}
	if err := secrets.RepairExistingPermissions(secretsDir); err != nil {
		return fmt.Errorf("prepare runtime secret permissions: %w", err)
	}
	runtimeGenerator := generator.NewGeneratorWithLock(
		project.Config,
		project.Dir,
		project.Registry,
		lock,
		Version,
	)
	if err := runtimeGenerator.PrepareRuntimePermissions(); err != nil {
		return fmt.Errorf("prepare runtime volume ownership: %w", err)
	}

	compose := docker.NewCompose(projectDir)

	fmt.Println(tui.InfoStyle.Render("Starting SDBX services..."))
	fmt.Println()

	// Start services
	start := time.Now()
	if err := compose.Up(ctx); err != nil {
		return fmt.Errorf("failed to start services: %w", err)
	}

	elapsed := time.Since(start)
	fmt.Println()
	fmt.Println(tui.SuccessStyle.Render(fmt.Sprintf("✓ Services started in %s", elapsed.Round(time.Millisecond))))
	fmt.Println()
	fmt.Println("Run 'sdbx status' to view service health")
	fmt.Println("Run 'sdbx doctor' to verify configuration")

	return nil
}
