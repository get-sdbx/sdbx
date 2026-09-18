package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/get-sdbx/sdbx/internal/generator"
	"github.com/get-sdbx/sdbx/internal/registry"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
)

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Manage service version lock file",
	Long: `Manage the .sdbx.lock file that pins service versions and image digests.

Lock files ensure reproducible deployments by recording:
- Source commit hashes
- Service definition versions
- Container image digests

Examples:
  sdbx lock                    # Generate/update lock file
  sdbx lock verify             # Verify lock file integrity
  sdbx lock diff               # Show differences from lock

Use 'sdbx update' to preview and safely apply upstream image refreshes.`,
	Args: cobra.NoArgs,
	RunE: runLockGenerate,
}

var lockVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify lock file integrity",
	Long: `Verify that the lock file matches current sources and services.

Returns exit code 0 if everything is in sync, 1 if there are differences.`,
	Args: cobra.NoArgs,
	RunE: runLockVerify,
}

var lockDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Show differences from lock file",
	Long: `Show what would change if the lock file was regenerated.

Useful to see if source updates introduce new versions.`,
	Args: cobra.NoArgs,
	RunE: runLockDiff,
}

var lockAllowLocalSources bool
var imageDigestResolverFactory = func() registry.ImageDigestResolver {
	return registry.NewOfficialImageDigestResolver(
		registry.NewDockerImageDigestResolver(),
	)
}
var imageRefreshResolverFactory = func() registry.ImageDigestResolver {
	return registry.NewDockerImageDigestResolver()
}

func init() {
	rootCmd.AddCommand(lockCmd)
	lockCmd.AddCommand(lockVerifyCmd)
	lockCmd.AddCommand(lockDiffCmd)
	lockCmd.PersistentFlags().BoolVar(
		&lockAllowLocalSources,
		"allow-local-sources",
		false,
		"Development only: permit non-reproducible local catalog sources",
	)
}

func runLockGenerate(command *cobra.Command, _ []string) error {
	return generateProjectLock(
		commandContext(command),
		imageDigestResolverFactory(),
		true,
	)
}

func generateProjectLock(
	ctx context.Context,
	imageResolver registry.ImageDigestResolver,
	preserveExistingPins bool,
) error {
	project, err := newProjectContext()
	if err != nil {
		return err
	}
	if preserveExistingPins {
		existing, loadErr := registry.NewLoader().LoadLockFile(
			filepath.Join(project.Dir, ".sdbx.lock"),
		)
		switch {
		case loadErr == nil:
			imageResolver, err = registry.NewUpdatingImageResolver(
				existing,
				imageResolver,
			)
			if err != nil {
				return fmt.Errorf(
					"failed to preserve existing image pins: %w",
					err,
				)
			}
		case !errors.Is(loadErr, os.ErrNotExist):
			return fmt.Errorf("failed to load existing lock file: %w", loadErr)
		}
	}

	// Generate lock file
	lockFile, warnings, err := project.Registry.GenerateLockFileWithOptions(
		ctx,
		project.Config,
		registry.LockOptions{
			CLIVersion:        Version,
			AllowLocalSources: lockAllowLocalSources,
			ImageResolver:     imageResolver,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to generate lock file: %w", err)
	}
	if err := generator.GenerateProjectTransactional(
		project.Config,
		project.Dir,
		project.Registry,
		lockFile,
		Version,
		generator.ProjectTransactionOptions{RuntimeOnly: true},
	); err != nil {
		return fmt.Errorf("failed to commit lock and runtime transaction: %w", err)
	}

	// JSON output
	if IsJSONOutput() {
		data, _ := json.MarshalIndent(lockFile, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	fmt.Println(tui.SuccessStyle.Render("✓ Generated .sdbx.lock"))
	fmt.Println()
	fmt.Printf("Locked %d sources, %d services\n",
		len(lockFile.Sources),
		len(lockFile.Services),
	)
	if len(warnings) > 0 {
		fmt.Println()
		fmt.Print(tui.WarningStyle.Render("Validation warnings:"))
		fmt.Println()
		fmt.Print(formatResolutionWarnings(warnings))
	}

	return nil
}

func formatResolutionWarnings(warnings []registry.ResolutionWarning) string {
	var builder strings.Builder
	for _, warning := range warnings {
		builder.WriteString(fmt.Sprintf("  - %s %s: %s\n",
			tui.EscapeText(warning.Service),
			tui.EscapeText(warning.Field),
			tui.EscapeText(warning.Message),
		))
	}
	return builder.String()
}

func runLockVerify(command *cobra.Command, _ []string) error {
	ctx := commandContext(command)
	project, err := newProjectContext()
	if err != nil {
		return err
	}

	// Load existing lock file
	loader := registry.NewLoader()
	existing, err := loader.LoadLockFile(filepath.Join(project.Dir, ".sdbx.lock"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no .sdbx.lock found; run 'sdbx lock' to generate one")
		}
		return fmt.Errorf("failed to load lock file: %w", err)
	}

	// Generate current lock file
	resolver, err := registry.NewLockedImageResolver(existing)
	if err != nil {
		return fmt.Errorf("invalid existing lock file: %w", err)
	}
	current, _, err := project.Registry.GenerateLockFileWithOptions(
		ctx,
		project.Config,
		registry.LockOptions{
			CLIVersion:        Version,
			AllowLocalSources: lockAllowLocalSources,
			ImageResolver:     resolver,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to generate current state: %w", err)
	}

	// Compare
	diffs := project.Registry.DiffLockFiles(existing, current)
	generatedFilesErr := registry.ValidateGeneratedFiles(
		project.Dir,
		project.Config.ConfigPath,
		existing,
	)

	// JSON output
	if IsJSONOutput() {
		result := map[string]interface{}{
			"valid":       len(diffs) == 0 && generatedFilesErr == nil,
			"differences": diffs,
		}
		if generatedFilesErr != nil {
			result["generatedFilesError"] = redactCLIError(
				generatedFilesErr.Error(),
			)
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		if len(diffs) > 0 || generatedFilesErr != nil {
			return markCLIErrorReported(fmt.Errorf("lock file is stale"))
		}
		return nil
	}

	if len(diffs) == 0 && generatedFilesErr == nil {
		fmt.Println(tui.SuccessStyle.Render("✓ Lock file is valid and up-to-date"))
		return nil
	}

	fmt.Println(tui.WarningStyle.Render("Lock file has differences:"))
	fmt.Println()
	for _, diff := range diffs {
		fmt.Printf("  %s: %s\n", tui.InfoStyle.Render(diff.Type), tui.EscapeText(diff.Description))
	}
	if generatedFilesErr != nil {
		fmt.Printf(
			"  %s: %s\n",
			tui.InfoStyle.Render("changed"),
			tui.EscapeText(redactCLIError(generatedFilesErr.Error())),
		)
	}
	fmt.Println()
	fmt.Printf("Run '%s' to update the lock file\n", tui.CommandStyle.Render("sdbx lock"))

	return fmt.Errorf("lock file is stale")
}

func runLockDiff(command *cobra.Command, _ []string) error {
	ctx := commandContext(command)
	project, err := newProjectContext()
	if err != nil {
		return err
	}

	// Load existing lock file
	loader := registry.NewLoader()
	existing, err := loader.LoadLockFile(filepath.Join(project.Dir, ".sdbx.lock"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no .sdbx.lock found; run 'sdbx lock' to generate one")
		}
		return fmt.Errorf("failed to load lock file: %w", err)
	}

	// Generate current lock file
	resolver, err := registry.NewLockedImageResolver(existing)
	if err != nil {
		return fmt.Errorf("invalid existing lock file: %w", err)
	}
	current, _, err := project.Registry.GenerateLockFileWithOptions(
		ctx,
		project.Config,
		registry.LockOptions{
			CLIVersion:        Version,
			AllowLocalSources: lockAllowLocalSources,
			ImageResolver:     resolver,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to generate current state: %w", err)
	}

	// Compare
	diffs := project.Registry.DiffLockFiles(existing, current)

	// JSON output
	if IsJSONOutput() {
		data, _ := json.MarshalIndent(diffs, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	if len(diffs) == 0 {
		fmt.Println(tui.MutedStyle.Render("No differences found"))
		return nil
	}

	fmt.Println(tui.TitleStyle.Render("Lock File Differences"))
	fmt.Println()

	for _, diff := range diffs {
		var icon string
		switch diff.Type {
		case "added":
			icon = tui.SuccessStyle.Render("+")
		case "removed":
			icon = tui.ErrorStyle.Render("-")
		case "changed":
			icon = tui.WarningStyle.Render("~")
		default:
			icon = " "
		}
		fmt.Printf("  %s %s\n", icon, tui.EscapeText(diff.Description))
	}

	return nil
}
