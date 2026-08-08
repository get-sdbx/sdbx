package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/get-sdbx/sdbx/internal/docker"
	"github.com/get-sdbx/sdbx/internal/generator"
	"github.com/get-sdbx/sdbx/internal/registry"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
)

const (
	updateMinimumHealthTimeout = 90 * time.Second
	updateMaximumHealthTimeout = 15 * time.Minute
	updateHealthSettleWindow   = 30 * time.Second
)

type updateCompose interface {
	Pull(context.Context) error
	Up(context.Context) error
	Down(context.Context) error
	WaitHealthy(context.Context, string, time.Duration) error
}

var updateComposeFactory = func(projectDir string) updateCompose {
	return docker.NewCompose(projectDir)
}

var updateRuntimeWriter = writeLockedRuntime

var (
	updateApply   bool
	updateConfirm string
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Preview or apply locked service image updates",
	Long: `Resolve configured image tags to new immutable digests and show the
candidate lock changes without mutating the project.

Applying a candidate requires both --apply and the exact
--confirm apply-upstream-images acknowledgement. SDBX then regenerates the
locked runtime, pulls those exact images, and converges the active Compose
stack. It verifies services in dependency order and restores the previous
digest-pinned stack if pulling, deployment, or health verification fails.

Resolved upstream images have not passed the release catalog security review.
Review the displayed digest changes and upstream advisories before applying.`,
	Args: cobra.NoArgs,
	RunE: runUpdate,
}

func init() {
	updateCmd.Flags().BoolVar(
		&updateApply,
		"apply",
		false,
		"apply the previewed upstream image digest changes",
	)
	updateCmd.Flags().StringVar(
		&updateConfirm,
		"confirm",
		"",
		"required exact acknowledgement when applying: apply-upstream-images",
	)
	rootCmd.AddCommand(updateCmd)
}

type updateResult struct {
	Changed      bool                    `json:"changed"`
	Differences  []registry.LockFileDiff `json:"differences,omitempty"`
	ServiceOrder []string                `json:"serviceOrder,omitempty"`
	Applied      bool                    `json:"applied"`
	RolledBack   bool                    `json:"rolledBack"`
}

func runUpdate(command *cobra.Command, _ []string) error {
	ctx := command.Context()
	project, err := newProjectContext()
	if err != nil {
		return err
	}
	previous, err := verifyProjectLock(ctx, project)
	if err != nil {
		return fmt.Errorf("refusing update from an unverified baseline: %w", err)
	}

	allowLocalSources := lockContainsLocalSource(previous)
	next, warnings, err := project.Registry.GenerateLockFileWithOptions(
		ctx,
		project.Config,
		registry.LockOptions{
			CLIVersion:        Version,
			AllowLocalSources: allowLocalSources,
			ImageResolver:     imageRefreshResolverFactory(),
		},
	)
	if err != nil {
		return fmt.Errorf("resolve updated image locks: %w", err)
	}
	differences := project.Registry.DiffLockFiles(previous, next)
	result := updateResult{
		Changed:      len(differences) > 0,
		Differences:  differences,
		ServiceOrder: append([]string(nil), next.InstallOrder...),
	}
	if len(differences) == 0 {
		return printUpdateResult(result, warnings)
	}
	if !updateApply {
		return printUpdateResult(result, warnings)
	}
	if err := validateUpdateApplyConfirmation(updateConfirm); err != nil {
		return err
	}
	healthTimeouts, err := resolveUpdateHealthTimeouts(ctx, project)
	if err != nil {
		return fmt.Errorf("resolve service health policy: %w", err)
	}

	compose := updateComposeFactory(project.Dir)
	if !IsJSONOutput() {
		fmt.Println(tui.TitleStyle.Render("SDBX Update"))
		fmt.Println()
		fmt.Printf("  %d locked change(s) resolved\n", len(differences))
	}

	if err := updateRuntimeWriter(project, next); err != nil {
		rollbackErr := rollbackUpdate(
			ctx,
			project,
			compose,
			previous,
			healthTimeouts,
			false,
		)
		result.RolledBack = rollbackErr == nil
		return updateFailure("write updated locked runtime", err, rollbackErr)
	}
	if err := compose.Pull(ctx); err != nil {
		rollbackErr := rollbackUpdate(
			ctx,
			project,
			compose,
			previous,
			healthTimeouts,
			false,
		)
		result.RolledBack = rollbackErr == nil
		return updateFailure("pull updated digest-pinned images", err, rollbackErr)
	}
	if err := compose.Up(ctx); err != nil {
		rollbackErr := rollbackUpdate(
			ctx,
			project,
			compose,
			previous,
			healthTimeouts,
			true,
		)
		result.RolledBack = rollbackErr == nil
		return updateFailure("converge updated stack", err, rollbackErr)
	}
	if err := waitForUpdateHealth(
		ctx,
		compose,
		next.InstallOrder,
		healthTimeouts,
	); err != nil {
		rollbackErr := rollbackUpdate(
			ctx,
			project,
			compose,
			previous,
			healthTimeouts,
			true,
		)
		result.RolledBack = rollbackErr == nil
		return updateFailure("verify updated stack", err, rollbackErr)
	}

	result.Applied = true
	return printUpdateResult(result, warnings)
}

func validateUpdateApplyConfirmation(confirmation string) error {
	if confirmation == "apply-upstream-images" {
		return nil
	}
	return fmt.Errorf(
		"applying newly resolved upstream images crosses a fresh supply-chain boundary; inspect the preview, then pass --apply --confirm apply-upstream-images",
	)
}

func writeLockedRuntime(project *projectContext, lock *registry.LockFile) error {
	if err := generator.GenerateProjectTransactional(
		project.Config,
		project.Dir,
		project.Registry,
		lock,
		Version,
		generator.ProjectTransactionOptions{
			RuntimeOnly: true,
		},
	); err != nil {
		return fmt.Errorf("commit locked runtime transaction: %w", err)
	}
	return nil
}

func rollbackUpdate(
	ctx context.Context,
	project *projectContext,
	compose updateCompose,
	previous *registry.LockFile,
	healthTimeouts map[string]time.Duration,
	resetContainers bool,
) error {
	if err := updateRuntimeWriter(project, previous); err != nil {
		return fmt.Errorf("restore previous locked runtime: %w", err)
	}
	if resetContainers {
		if err := compose.Down(ctx); err != nil {
			return fmt.Errorf("stop failed updated stack: %w", err)
		}
	}
	if err := compose.Pull(ctx); err != nil {
		return fmt.Errorf("pull previous digest-pinned images: %w", err)
	}
	if err := compose.Up(ctx); err != nil {
		return fmt.Errorf("reconverge previous stack: %w", err)
	}
	if err := waitForUpdateHealth(
		ctx,
		compose,
		previous.InstallOrder,
		healthTimeouts,
	); err != nil {
		return fmt.Errorf("verify previous stack after rollback: %w", err)
	}
	return nil
}

func waitForUpdateHealth(
	ctx context.Context,
	compose updateCompose,
	serviceOrder []string,
	healthTimeouts map[string]time.Duration,
) error {
	if len(serviceOrder) == 0 {
		return fmt.Errorf("active lock contains no service order")
	}
	for _, service := range serviceOrder {
		if err := ctx.Err(); err != nil {
			return err
		}
		timeout := healthTimeouts[service]
		if timeout == 0 {
			timeout = updateMinimumHealthTimeout
		}
		if err := compose.WaitHealthy(ctx, service, timeout); err != nil {
			return fmt.Errorf("%s did not become healthy: %w", service, err)
		}
	}
	return nil
}

func resolveUpdateHealthTimeouts(
	ctx context.Context,
	project *projectContext,
) (map[string]time.Duration, error) {
	if project == nil || project.Registry == nil || project.Config == nil {
		return nil, fmt.Errorf("loaded project registry and configuration are required")
	}
	graph, err := project.Registry.Resolve(ctx, project.Config)
	if err != nil {
		return nil, fmt.Errorf("resolve active service graph: %w", err)
	}
	if len(graph.Errors) > 0 {
		return nil, fmt.Errorf("active service graph is invalid: %w", graph.Errors[0])
	}
	timeouts := make(map[string]time.Duration, len(graph.Order))
	for _, service := range graph.Order {
		resolved := graph.Services[service]
		if resolved == nil || !resolved.Enabled || resolved.FinalDefinition == nil {
			return nil, fmt.Errorf("active service %s has no resolved definition", service)
		}
		timeout, err := updateHealthTimeout(
			resolved.FinalDefinition.Spec.HealthCheck,
		)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", service, err)
		}
		timeouts[service] = timeout
	}
	return timeouts, nil
}

func updateHealthTimeout(health *registry.HealthCheck) (time.Duration, error) {
	if health == nil {
		return updateMinimumHealthTimeout, nil
	}
	parse := func(field, value string, fallback time.Duration) (time.Duration, error) {
		if value == "" {
			return fallback, nil
		}
		duration, err := time.ParseDuration(value)
		if err != nil || duration <= 0 {
			return 0, fmt.Errorf(
				"healthcheck %s %q is not a positive duration",
				field,
				value,
			)
		}
		return duration, nil
	}
	startPeriod, err := parse("start_period", health.StartPeriod, 0)
	if err != nil {
		return 0, err
	}
	interval, err := parse("interval", health.Interval, 30*time.Second)
	if err != nil {
		return 0, err
	}
	checkTimeout, err := parse("timeout", health.Timeout, 30*time.Second)
	if err != nil {
		return 0, err
	}
	retries := health.Retries
	if retries == 0 {
		retries = 3
	}
	if retries < 0 || retries > 20 {
		return 0, fmt.Errorf("healthcheck retries must be between 1 and 20")
	}
	timeout := startPeriod +
		time.Duration(retries)*(interval+checkTimeout) +
		updateHealthSettleWindow
	if timeout < updateMinimumHealthTimeout {
		timeout = updateMinimumHealthTimeout
	}
	if timeout > updateMaximumHealthTimeout {
		return 0, fmt.Errorf(
			"derived health deadline %s exceeds the %s safety bound",
			timeout,
			updateMaximumHealthTimeout,
		)
	}
	return timeout, nil
}

func updateFailure(stage string, cause, rollbackErr error) error {
	if rollbackErr != nil {
		return fmt.Errorf(
			"%s failed: %w; automatic rollback also failed: %v",
			stage,
			cause,
			rollbackErr,
		)
	}
	return fmt.Errorf("%s failed: %w; previous locked stack restored", stage, cause)
}

func lockContainsLocalSource(lock *registry.LockFile) bool {
	if lock == nil {
		return false
	}
	for _, source := range lock.Sources {
		if source.Type == "local" {
			return true
		}
	}
	return false
}

func printUpdateResult(
	result updateResult,
	warnings []registry.ResolutionWarning,
) error {
	if IsJSONOutput() {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}
	if !result.Changed {
		fmt.Println(tui.SuccessStyle.Render("✓ Locked service images are already current"))
		return nil
	}
	if !result.Applied {
		fmt.Println(tui.TitleStyle.Render("SDBX Update Preview"))
		fmt.Println()
		fmt.Printf(
			"  %d locked change(s) resolved; no project files or containers changed\n",
			len(result.Differences),
		)
		fmt.Println()
		fmt.Println(tui.WarningStyle.Render(
			"  Candidate images have not passed the SDBX release catalog security review.",
		))
		fmt.Println("  Review upstream releases and exact digest changes, then apply with:")
		fmt.Println("  sdbx update --apply --confirm apply-upstream-images")
		if len(warnings) > 0 {
			fmt.Println()
			fmt.Print(tui.WarningStyle.Render("Validation warnings:"))
			fmt.Println()
			fmt.Print(formatResolutionWarnings(warnings))
		}
		return nil
	}
	fmt.Println()
	fmt.Println(tui.SuccessStyle.Render("✓ Updated locked stack is healthy"))
	fmt.Printf("  Verified %d service(s) in dependency order\n", len(result.ServiceOrder))
	if len(warnings) > 0 {
		fmt.Println()
		fmt.Print(tui.WarningStyle.Render("Validation warnings:"))
		fmt.Println()
		fmt.Print(formatResolutionWarnings(warnings))
	}
	return nil
}
