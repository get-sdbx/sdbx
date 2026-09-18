// Package cmd contains all CLI commands for sdbx.
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/generator"
	"github.com/get-sdbx/sdbx/internal/redact"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	noTUI   bool
	jsonOut bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:           "sdbx",
	Short:         "Build and operate a self-hosted seedbox under your root",
	SilenceErrors: true,
	SilenceUsage:  true,
	Long: `SDBX is a CLI tool for bootstrapping, deploying, and managing
a reproducible self-hosted seedbox with authentication, VPN-enforced downloads,
immutable service locks, encrypted recovery, and guided terminal workflows.

Your server. Your bandwidth. Your business.

Features:
  • Policy-derived authentication with Authelia
  • VPN-enforced downloads with kill-switch
  • Embedded, validated service catalog
  • Digest-pinned, reproducible deployments
  • Authenticated encrypted backups
  • Authelia-protected remote management console

Get started:
  sdbx init     Bootstrap a new project
  sdbx up       Start all services
  sdbx status   Inspect the live stack
  sdbx serve    Run the brokered web console
  sdbx doctor   Run diagnostic checks`,
	PersistentPreRunE: prepareCommand,
}

type cliErrorEnvelope struct {
	Error cliErrorBody `json:"error"`
}

type cliErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// reportedCLIError preserves a nonzero exit while telling Execute that the
// command already emitted its complete human or JSON failure report.
type reportedCLIError struct {
	cause error
}

func (e *reportedCLIError) Error() string {
	return e.cause.Error()
}

func (e *reportedCLIError) Unwrap() error {
	return e.cause
}

func markCLIErrorReported(err error) error {
	if err == nil {
		return nil
	}
	return &reportedCLIError{cause: err}
}

func shouldRenderCLIError(err error) bool {
	var reported *reportedCLIError
	return !errors.As(err, &reported)
}

// Execute runs the CLI and emits exactly one machine-readable error object when
// --json is requested. Cobra's usage text is reserved for explicit help.
func Execute() error {
	return ExecuteContext(context.Background())
}

// ExecuteContext runs the CLI with cancellation propagated to long-running
// operations and servers.
func ExecuteContext(ctx context.Context) error {
	err := rootCmd.ExecuteContext(ctx)
	if err == nil {
		return nil
	}
	if shouldRenderCLIError(err) {
		writeCLIError(os.Stderr, err, jsonRequested(os.Args[1:]))
	}
	return err
}

func commandContext(command *cobra.Command) context.Context {
	if command == nil || command.Context() == nil {
		return context.Background()
	}
	return command.Context()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is .sdbx.yaml)")
	rootCmd.PersistentFlags().BoolVar(&noTUI, "no-tui", false, "disable TUI, use plain text output")
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "emit machine-readable JSON (supported commands only)")

	// Bind flags to viper (panic on error as this indicates a programming bug)
	if err := viper.BindPFlag("no-tui", rootCmd.PersistentFlags().Lookup("no-tui")); err != nil {
		panic(fmt.Sprintf("failed to bind no-tui flag: %v", err))
	}
	if err := viper.BindPFlag("json", rootCmd.PersistentFlags().Lookup("json")); err != nil {
		panic(fmt.Sprintf("failed to bind json flag: %v", err))
	}
}

// initConfig selects one explicit project configuration. Runtime environment
// variables must not silently override reproducibility-relevant project intent.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// Search for config in current directory
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".sdbx")
	}

	// Read config file if it exists (errors are silently ignored)
	_ = viper.ReadInConfig()
}

// IsTUIEnabled returns true if TUI mode is enabled
func IsTUIEnabled() bool {
	// TUI is enabled by default in interactive terminals
	if noTUI || jsonOut {
		return false
	}
	// Check if stdout is a terminal
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

// IsJSONOutput returns true if JSON output is requested
func IsJSONOutput() bool {
	return jsonOut
}

func validateOutputMode(command *cobra.Command, _ []string) error {
	if !IsJSONOutput() {
		return nil
	}
	if supportsJSON(command) {
		return nil
	}
	return fmt.Errorf("--json is not supported by %q", command.CommandPath())
}

func prepareCommand(command *cobra.Command, args []string) error {
	if err := validateOutputMode(command, args); err != nil {
		return err
	}
	// Initialization has its own dry-run-aware recovery gate. All other
	// commands recover a journal before their RunE can load project intent.
	if command == initCmd {
		return nil
	}
	projectDir, err := config.ProjectDir()
	if err != nil {
		var notFound *config.ProjectNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return fmt.Errorf("locate project for transaction recovery: %w", err)
	}
	if err := generator.RecoverProjectTransaction(projectDir); err != nil {
		return fmt.Errorf("recover interrupted project transaction: %w", err)
	}
	return nil
}

func supportsJSON(command *cobra.Command) bool {
	switch command {
	case addonListCmd, addonSearchCmd, addonInfoCmd,
		backupCmd, backupListCmd, backupRestoreCmd, backupDeleteCmd,
		configGetCmd,
		doctorCmd,
		integrateCmd,
		lockCmd, lockVerifyCmd, lockDiffCmd,
		presetListCmd, presetShowCmd, presetApplyCmd,
		secretsListCmd,
		sourceListCmd,
		statusCmd,
		tunnelRoutesCmd,
		updateCmd,
		versionCmd,
		vpnStatusCmd:
		return true
	default:
		return false
	}
}

func jsonRequested(args []string) bool {
	if jsonOut {
		return true
	}
	for _, arg := range args {
		if arg == "--json" || strings.HasPrefix(arg, "--json=") && arg != "--json=false" {
			return true
		}
	}
	return false
}

func writeCLIError(writer io.Writer, err error, asJSON bool) {
	message := redactCLIError(err.Error())
	if asJSON {
		_ = json.NewEncoder(writer).Encode(cliErrorEnvelope{
			Error: cliErrorBody{
				Code:    "command_failed",
				Message: message,
			},
		})
		return
	}
	_, _ = fmt.Fprintf(writer, "Error: %s\n", tui.EscapeText(message))
}

func redactCLIError(message string) string {
	return redact.Text(message)
}
