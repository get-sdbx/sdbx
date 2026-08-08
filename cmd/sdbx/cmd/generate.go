package cmd

import (
	"fmt"

	"github.com/get-sdbx/sdbx/internal/generator"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Regenerate runtime files (compose.yaml, .env, integration configs)",
	Long: `Regenerate the project's runtime files from the current .sdbx.yaml and
service registry without re-running the init wizard.

Useful after manually editing .sdbx.yaml (for example, to repoint config_path,
data_path, or secrets_path during a path migration). SDBX-managed runtime
policy is refreshed, including compose.yaml, .env, .sdbx.yaml, Authelia access
rules, Traefik static and dynamic configuration, and enabled integration
configs. User-managed application databases and configuration are preserved.

This command also auto-surfaces supported active *arr API keys: if config.xml
is missing or has no <ApiKey>, a
fresh key is generated and persisted. Existing keys are never overwritten.`,
	Args: cobra.NoArgs,
	RunE: runGenerate,
}

func init() {
	rootCmd.AddCommand(generateCmd)
}

func runGenerate(command *cobra.Command, _ []string) error {
	project, err := newProjectContext()
	if err != nil {
		return err
	}
	lock, err := verifyProjectLock(commandContext(command), project)
	if err != nil {
		return err
	}

	if err := generator.GenerateProjectTransactional(
		project.Config,
		project.Dir,
		project.Registry,
		lock,
		Version,
		generator.ProjectTransactionOptions{RuntimeOnly: true},
	); err != nil {
		return fmt.Errorf("failed to commit runtime transaction: %w", err)
	}

	fmt.Println(tui.SuccessStyle.Render("✓ Runtime files regenerated"))
	return nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
