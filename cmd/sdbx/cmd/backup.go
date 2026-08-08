package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/get-sdbx/sdbx/internal/backup"
	"github.com/get-sdbx/sdbx/internal/config"
	verifiedproject "github.com/get-sdbx/sdbx/internal/project"
	"github.com/get-sdbx/sdbx/internal/recovery"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Backup and restore SDBX configuration",
	Long: `Backup and restore your SDBX configuration, secrets, and service configs.

Backups include:
  - Configuration (.sdbx.yaml, .sdbx.lock, .env)
  - Docker Compose file and generated service configuration
  - Secrets
  - Service configurations

Backups DO NOT include:
  - Media files
  - Downloads
  - Docker volumes/data

Backups are always authenticated age-encrypted. Choose either a public age
recipient (recommended for automation) or a passphrase. SDBX never creates a
plaintext backup archive.

Examples:
  sdbx backup --recipient age1...              # Create for a public recipient
  sdbx backup --passphrase-file /secure/input  # Create with a passphrase
  sdbx backup                                  # Interactive passphrase
  sdbx backup list             # List all backups
  sdbx backup restore <name> --identity-file /secure/age-key.txt --confirm restore
  sdbx backup delete <name> --confirm delete`,
	Args: cobra.NoArgs,
	RunE: runBackupCreate,
}

var backupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all backups",
	Args:  cobra.NoArgs,
	RunE:  runBackupList,
}

var backupRestoreCmd = &cobra.Command{
	Use:   "restore <backup-name>",
	Short: "Restore from backup",
	Long: `Restore an authenticated encrypted backup as one journaled transaction.

Every restore keeps the target's already verified project intent, lock,
Compose, .env, and generated policy. It restores only compatible application
configuration and secrets. Archived intent and the locked service graph must
match the target exactly.

For a reviewed cross-host move, --relocate-managed-roots additionally permits
the archived config_path and secrets_path to differ. State is still restored
only into the target's current managed roots.`,
	Args: cobra.ExactArgs(1),
	RunE: runBackupRestore,
}

var backupDeleteCmd = &cobra.Command{
	Use:   "delete <backup-name>",
	Short: "Delete a backup",
	Args:  cobra.ExactArgs(1),
	RunE:  runBackupDelete,
}

var (
	backupRecipient            string
	backupPassphraseFile       string
	backupIdentityFile         string
	restorePassphraseFile      string
	backupRestoreConfirm       string
	backupDeleteConfirm        string
	backupRelocateManagedRoots bool
)

func init() {
	rootCmd.AddCommand(backupCmd)
	backupCmd.AddCommand(backupListCmd)
	backupCmd.AddCommand(backupRestoreCmd)
	backupCmd.AddCommand(backupDeleteCmd)

	backupCmd.Flags().StringVar(
		&backupRecipient,
		"recipient",
		"",
		"age public recipient (age1... or age1pq1...); private identity is not stored",
	)
	backupCmd.Flags().StringVar(
		&backupPassphraseFile,
		"passphrase-file",
		"",
		"read backup passphrase from a private regular file",
	)
	backupRestoreCmd.Flags().StringVar(
		&backupIdentityFile,
		"identity-file",
		"",
		"private age identity file used only for this restore",
	)
	backupRestoreCmd.Flags().StringVar(
		&restorePassphraseFile,
		"passphrase-file",
		"",
		"read restore passphrase from a private regular file",
	)
	backupRestoreCmd.Flags().StringVar(
		&backupRestoreConfirm,
		"confirm",
		"",
		"required exact destructive-action confirmation: restore",
	)
	backupRestoreCmd.Flags().BoolVar(
		&backupRelocateManagedRoots,
		"relocate-managed-roots",
		false,
		"permit archived config/secrets roots to differ while preserving the verified target control plane",
	)
	backupDeleteCmd.Flags().StringVar(
		&backupDeleteConfirm,
		"confirm",
		"",
		"required exact destructive-action confirmation: delete",
	)
}

func runBackupCreate(command *cobra.Command, _ []string) error {
	// Get project directory
	projectDir, err := config.ProjectDir()
	if err != nil {
		return fmt.Errorf("not in an SDBX project directory")
	}

	// Change to project directory
	if err := os.Chdir(projectDir); err != nil {
		return fmt.Errorf("failed to change directory: %w", err)
	}

	ctx := command.Context()
	reg, err := getRegistry()
	if err != nil {
		return err
	}
	cfg, err := config.LoadFile(filepath.Join(projectDir, ".sdbx.yaml"))
	if err != nil {
		return fmt.Errorf("failed to load project configuration: %w", err)
	}
	if _, err := verifiedproject.VerifyGeneratedRuntime(
		ctx,
		projectDir,
		cfg,
		reg,
		Version,
	); err != nil {
		return fmt.Errorf(
			"backup source verification failed; regenerate and review the project before backup: %w",
			err,
		)
	}

	manager := backup.NewManager(projectDir)

	if !IsJSONOutput() {
		fmt.Println(tui.TitleStyle.Render("Creating Backup"))
		fmt.Println()
	}

	options, err := backupCreateOptions()
	if err != nil {
		return err
	}
	defer zeroBytes(options.Passphrase)

	// Create backup
	b, err := manager.CreateWithRoots(ctx, options, backup.ManagedRoots{
		ConfigPath:  cfg.ConfigPath,
		SecretsPath: cfg.SecretsPath,
	})
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// Get backup size
	size, _ := b.GetSize()

	// JSON output
	if IsJSONOutput() {
		result := map[string]interface{}{
			"name":      b.Name,
			"path":      b.Path,
			"size":      size,
			"timestamp": b.Metadata.Timestamp,
			"omissions": b.Metadata.Omissions,
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	// Human-readable output
	fmt.Println(tui.SuccessStyle.Render("✓ Backup created successfully"))
	fmt.Println()
	fmt.Printf("%s  %s\n", tui.MutedStyle.Render("Name:"), tui.EscapeText(b.Name))
	fmt.Printf("%s  %s\n", tui.MutedStyle.Render("Path:"), tui.EscapeText(b.Path))
	fmt.Printf("%s  %s\n", tui.MutedStyle.Render("Size:"), formatBytes(size))
	fmt.Printf("%s  %s\n", tui.MutedStyle.Render("Time:"), b.Metadata.Timestamp.Format("2006-01-02 15:04:05"))
	if len(b.Metadata.Omissions) > 0 {
		fmt.Println()
		fmt.Println(tui.MutedStyle.Render(
			"Omitted reproducible or ephemeral filesystem entries:",
		))
		for _, omission := range b.Metadata.Omissions {
			fmt.Printf(
				"  - %s (%s)\n",
				tui.EscapeText(omission.Path),
				tui.EscapeText(omission.Reason),
			)
		}
	}
	fmt.Println()

	return nil
}

func runBackupList(command *cobra.Command, _ []string) error {
	// Get project directory
	projectDir, err := config.ProjectDir()
	if err != nil {
		return fmt.Errorf("not in an SDBX project directory")
	}

	// Create backup manager
	manager := backup.NewManager(projectDir)

	ctx := command.Context()

	// List backups
	backups, err := manager.List(ctx)
	if err != nil {
		return fmt.Errorf("failed to list backups: %w", err)
	}

	// JSON output
	if IsJSONOutput() {
		result := make([]map[string]interface{}, 0, len(backups))
		for _, b := range backups {
			size, _ := b.GetSize()
			result = append(result, map[string]interface{}{
				"name":               b.Name,
				"path":               b.Path,
				"size":               size,
				"timestamp":          b.Metadata.Timestamp,
				"metadata_encrypted": true,
			})
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	// Human-readable output
	if len(backups) == 0 {
		fmt.Println(tui.MutedStyle.Render("No backups found"))
		return nil
	}

	fmt.Println(tui.TitleStyle.Render("Available Backups"))
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, tui.TableHeaderStyle.Render("NAME")+"\t"+tui.TableHeaderStyle.Render("DATE")+"\t"+tui.TableHeaderStyle.Render("SIZE")+"\t"+tui.TableHeaderStyle.Render("HOSTNAME"))

	for _, b := range backups {
		size, _ := b.GetSize()
		age := formatAge(b.Metadata.Timestamp)

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			tui.EscapeText(b.Name),
			age,
			formatBytes(size),
			encryptedMetadataLabel(b.Metadata.Hostname),
		)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("render backup list: %w", err)
	}

	return nil
}

func runBackupRestore(command *cobra.Command, args []string) error {
	backupName := args[0]
	if backupRestoreConfirm != "restore" {
		return fmt.Errorf(
			"restoring overwrites compatible application state and secrets; pass --confirm restore after verifying the target and recovery credential",
		)
	}
	if err := backup.ValidateBackupName(backupName); err != nil {
		return err
	}

	// Get project directory
	projectDir, err := config.ProjectDir()
	if err != nil {
		return fmt.Errorf("not in an SDBX project directory")
	}

	// Change to project directory
	if err := os.Chdir(projectDir); err != nil {
		return fmt.Errorf("failed to change directory: %w", err)
	}

	// Create backup manager
	manager := backup.NewManager(projectDir)

	ctx := command.Context()

	if !IsJSONOutput() {
		fmt.Println(tui.TitleStyle.Render("Restoring Backup"))
		fmt.Println()
		fmt.Printf("%s  %s\n", tui.MutedStyle.Render("Backup:"), tui.EscapeText(backupName))
		fmt.Println()
	}

	options, err := backupRestoreOptions()
	if err != nil {
		return err
	}
	defer zeroBytes(options.Passphrase)

	reg, err := getRegistry()
	if err != nil {
		return err
	}
	restoreHooks, err := recovery.RestoreHooks(
		ctx,
		projectDir,
		reg,
		Version,
		backupRelocateManagedRoots,
	)
	if err != nil {
		return err
	}

	// Keep the transaction open until the restored lock and generated runtime
	// state have been verified against the embedded catalog.
	if err := manager.RestoreWithHooks(
		ctx,
		backupName,
		options,
		restoreHooks,
	); err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	// JSON output
	if IsJSONOutput() {
		result := map[string]interface{}{
			"success": true,
			"backup":  backupName,
			"mode": func() string {
				if backupRelocateManagedRoots {
					return "state-relocation"
				}
				return "state"
			}(),
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	// Human-readable output
	fmt.Println(tui.SuccessStyle.Render("✓ Backup restored successfully"))
	fmt.Println()
	fmt.Println(tui.MutedStyle.Render("Run 'sdbx up' to apply the restored configuration"))

	return nil
}

func backupCreateOptions() (backup.EncryptOptions, error) {
	if backupRecipient != "" && backupPassphraseFile != "" {
		return backup.EncryptOptions{}, fmt.Errorf(
			"--recipient and --passphrase-file are mutually exclusive",
		)
	}
	if backupRecipient != "" {
		return backup.EncryptOptions{Recipient: backupRecipient}, nil
	}
	if backupPassphraseFile != "" {
		passphrase, err := readPrivatePassphraseFile(backupPassphraseFile)
		if err != nil {
			return backup.EncryptOptions{}, err
		}
		return backup.EncryptOptions{Passphrase: passphrase}, nil
	}
	passphrase, err := readInteractiveBackupPassphrase(true)
	if err != nil {
		return backup.EncryptOptions{}, err
	}
	return backup.EncryptOptions{Passphrase: passphrase}, nil
}

func backupRestoreOptions() (backup.DecryptOptions, error) {
	if backupIdentityFile != "" && restorePassphraseFile != "" {
		return backup.DecryptOptions{}, fmt.Errorf(
			"--identity-file and --passphrase-file are mutually exclusive",
		)
	}
	if backupIdentityFile != "" {
		return backup.DecryptOptions{IdentityFile: backupIdentityFile}, nil
	}
	if restorePassphraseFile != "" {
		passphrase, err := readPrivatePassphraseFile(restorePassphraseFile)
		if err != nil {
			return backup.DecryptOptions{}, err
		}
		return backup.DecryptOptions{Passphrase: passphrase}, nil
	}
	passphrase, err := readInteractiveBackupPassphrase(false)
	if err != nil {
		return backup.DecryptOptions{}, err
	}
	return backup.DecryptOptions{Passphrase: passphrase}, nil
}

func readPrivatePassphraseFile(filePath string) ([]byte, error) {
	return readPrivateCredentialFile(filePath, "passphrase")
}

func readInteractiveBackupPassphrase(confirm bool) ([]byte, error) {
	if IsJSONOutput() || !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf(
			"non-interactive backup encryption requires --recipient, --identity-file, or --passphrase-file as appropriate",
		)
	}
	fmt.Fprint(os.Stderr, "Backup passphrase: ")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read backup passphrase: %w", err)
	}
	if len(first) == 0 {
		return nil, fmt.Errorf("backup passphrase cannot be empty")
	}
	if !confirm {
		return first, nil
	}
	fmt.Fprint(os.Stderr, "Confirm backup passphrase: ")
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		zeroBytes(first)
		return nil, fmt.Errorf("confirm backup passphrase: %w", err)
	}
	defer zeroBytes(second)
	if !bytes.Equal(first, second) {
		zeroBytes(first)
		return nil, fmt.Errorf("backup passphrases do not match")
	}
	return first, nil
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func encryptedMetadataLabel(hostname string) string {
	if strings.TrimSpace(hostname) == "" {
		return "encrypted"
	}
	return hostname
}

func runBackupDelete(command *cobra.Command, args []string) error {
	backupName := args[0]
	if backupDeleteConfirm != "delete" {
		return fmt.Errorf(
			"deleting a backup is irreversible; pass --confirm delete after verifying another recovery copy exists",
		)
	}

	// Get project directory
	projectDir, err := config.ProjectDir()
	if err != nil {
		return fmt.Errorf("not in an SDBX project directory")
	}

	// Create backup manager
	manager := backup.NewManager(projectDir)

	ctx := command.Context()

	// Delete backup
	if err := manager.Delete(ctx, backupName); err != nil {
		return fmt.Errorf("failed to delete backup: %w", err)
	}

	// JSON output
	if IsJSONOutput() {
		result := map[string]interface{}{
			"success": true,
			"deleted": backupName,
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	// Human-readable output
	fmt.Println(tui.SuccessStyle.Render("✓ Backup deleted successfully"))

	return nil
}

// formatBytes formats bytes to human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// formatAge formats a timestamp as a relative time
func formatAge(t time.Time) string {
	duration := time.Since(t)

	if duration < time.Minute {
		return "just now"
	}
	if duration < time.Hour {
		mins := int(duration.Minutes())
		if mins == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", mins)
	}
	if duration < 24*time.Hour {
		hours := int(duration.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	}
	days := int(duration.Hours() / 24)
	if days == 1 {
		return "1 day ago"
	}
	if days < 30 {
		return fmt.Sprintf("%d days ago", days)
	}

	// For older backups, show full date
	return t.Format("2006-01-02 15:04")
}
