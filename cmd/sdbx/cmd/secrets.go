package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/get-sdbx/sdbx/internal/commandexec"
	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/integrate"
	"github.com/get-sdbx/sdbx/internal/secrets"
	"github.com/get-sdbx/sdbx/internal/securefs"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
)

var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Manage SDBX secrets",
	Long: `Generate, inspect, and recover secrets used by SDBX services.

Secrets are stored in the secrets/ directory and include:
  • Authelia JWT, session, and storage encryption keys
  • VPN credentials (user-provided)
  • Cloudflare tunnel token (user-provided)

Managed native service credentials are rotated transactionally by
sdbx integrate --rotate-managed-credentials --confirm rotate-managed-credentials.
Authelia, tunnel, VPN, Plex, Seerr, and encryption credentials are deliberately
excluded because changing one file can invalidate sessions or encrypted state.`,
}

var secretsGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate missing secrets",
	Long: `Generate any missing secret files.

This command will create new random secrets for Authelia and other services.
Existing secrets are preserved.`,
	Args: cobra.NoArgs,
	RunE: runSecretsGenerate,
}

var secretsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all secrets and their status",
	Long:  `Display all managed secrets and whether they are configured.`,
	Args:  cobra.NoArgs,
	RunE:  runSecretsList,
}

var secretsShowCmd = &cobra.Command{
	Use:   "show <service>",
	Short: "Show recovery credentials for a service",
	Long: `Surface the credentials needed to log into a service when you've
lost track of them. For services that generate ephemeral credentials at runtime
(e.g. qBittorrent's temporary admin password, logged to stdout on every start),
this command extracts and displays them — clearly marked as TEMP.

This deliberately writes plaintext credentials to the terminal. It never
supports --json. Pass the exact '--confirm reveal' acknowledgement to proceed,
and do not paste the output into logs, issues, or shell transcripts.

Currently supported:
  qbittorrent   Show the SDBX-managed permanent password, or recover the most
                recent temporary password from logs before integration.
  filebrowser   Show the SDBX-managed password, or recover the first-launch
                password from logs when it is still available.
  sonarr        Show the SDBX-managed native admin credential.
  prowlarr      Show the SDBX-managed native admin credential.
  radarr        Show the SDBX-managed native admin credential.
  lidarr        Show the SDBX-managed native admin credential.
  whisparr      Show the SDBX-managed native admin credential.
  qui           Show the SDBX-managed native admin credential.
  wizarr        Show the SDBX-managed native admin credential.
  cobalt       Show the generated API key used by cobalt.tools clients.

Examples:
  sdbx secrets show qbittorrent --confirm reveal
  sdbx secrets show filebrowser --confirm reveal
  sdbx secrets show sonarr --confirm reveal
  sdbx secrets show prowlarr --confirm reveal
  sdbx secrets show radarr --confirm reveal
  sdbx secrets show lidarr --confirm reveal
  sdbx secrets show whisparr --confirm reveal
  sdbx secrets show qui --confirm reveal
  sdbx secrets show wizarr --confirm reveal
  sdbx secrets show cobalt --confirm reveal`,
	Args: cobra.ExactArgs(1),
	RunE: runSecretsShow,
}

var secretsRevealConfirm string

func init() {
	rootCmd.AddCommand(secretsCmd)
	secretsCmd.AddCommand(secretsGenerateCmd)
	secretsCmd.AddCommand(secretsListCmd)
	secretsCmd.AddCommand(secretsShowCmd)
	secretsShowCmd.Flags().StringVar(
		&secretsRevealConfirm,
		"confirm",
		"",
		"required exact plaintext-credential confirmation: reveal",
	)
}

func runSecretsGenerate(_ *cobra.Command, args []string) error {
	secretsDir, err := configuredSecretsDir()
	if err != nil {
		return err
	}

	fmt.Println(tui.InfoStyle.Render("Generating secrets..."))
	fmt.Println()

	if err := secrets.GenerateSecrets(secretsDir); err != nil {
		return fmt.Errorf("failed to generate secrets: %w", err)
	}

	// List what was created
	status, _ := secrets.ListSecrets(secretsDir)
	for name, configured := range status {
		if configured {
			fmt.Printf("  %s %s\n", tui.SuccessStyle.Render(tui.IconSuccess), name)
		} else {
			fmt.Printf("  %s %s %s\n", tui.WarningStyle.Render(tui.IconWarning), name, tui.MutedStyle.Render("(needs manual config)"))
		}
	}

	fmt.Println()
	fmt.Println(tui.SuccessStyle.Render("✓ Secrets generated"))

	return nil
}

func runSecretsList(_ *cobra.Command, args []string) error {
	secretsDir, err := configuredSecretsDir()
	if err != nil {
		return err
	}

	status, err := secrets.ListSecrets(secretsDir)
	if err != nil {
		return err
	}

	// JSON output
	if IsJSONOutput() {
		data, _ := json.MarshalIndent(status, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	fmt.Println(tui.TitleStyle.Render("SDBX Secrets"))
	fmt.Println()

	configured := 0
	missing := 0

	for name, isConfigured := range status {
		if isConfigured {
			fmt.Printf("  %s %s\n", tui.SuccessStyle.Render(tui.IconSuccess), name)
			configured++
		} else {
			fmt.Printf("  %s %s %s\n", tui.ErrorStyle.Render(tui.IconError), name, tui.MutedStyle.Render("(empty)"))
			missing++
		}
	}

	fmt.Println()
	if missing > 0 {
		fmt.Println(tui.WarningStyle.Render(fmt.Sprintf("%d of %d secrets need configuration", missing, configured+missing)))
	} else {
		fmt.Println(tui.SuccessStyle.Render(fmt.Sprintf("✓ All %d secrets configured", configured)))
	}

	return nil
}

func configuredSecretsDir() (string, error) {
	projectDir, err := config.ProjectDir()
	if err != nil {
		return "", err
	}
	cfg, err := config.LoadFile(filepath.Join(projectDir, ".sdbx.yaml"))
	if err != nil {
		return "", fmt.Errorf("load project configuration: %w", err)
	}
	root := cfg.SecretsPath
	if root == "" {
		root = "secrets"
	}
	if !filepath.IsAbs(root) {
		root = filepath.Join(projectDir, root)
	}
	root = filepath.Clean(root)
	relative, relativeErr := filepath.Rel(projectDir, root)
	if relativeErr == nil &&
		relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator)) &&
		!filepath.IsAbs(relative) {
		if err := securefs.RejectSymlinkTraversal(projectDir, root); err != nil {
			return "", fmt.Errorf("unsafe secrets_path: %w", err)
		}
	}
	return root, nil
}

// qbtTempPasswordRE matches the temporary-password line qBittorrent emits on
// startup when no admin password is persisted in qBittorrent.conf.
//
//	"A temporary password is provided for this session: <password>"
var qbtTempPasswordRE = regexp.MustCompile(`temporary password is provided for this session:\s*(\S+)`)

// fbAdminPasswordRE matches filebrowser's first-launch admin-init line,
// emitted exactly once when filebrowser.db is created from scratch:
//
//	"User 'admin' initialized with randomly generated password: <password>"
var fbAdminPasswordRE = regexp.MustCompile(`User '([^']+)' initialized with randomly generated password:\s*(\S+)`)

func runSecretsShow(command *cobra.Command, args []string) error {
	if IsJSONOutput() {
		return fmt.Errorf(
			"--json is not supported by %q because it reveals plaintext credentials",
			command.CommandPath(),
		)
	}
	if secretsRevealConfirm != "reveal" {
		return fmt.Errorf(
			"revealing a plaintext recovery credential can expose it in terminal capture; pass --confirm reveal only in a private session",
		)
	}
	service := args[0]
	switch service {
	case "qbittorrent", "qbt":
		return showQBittorrentTempPassword(commandContext(command))
	case "filebrowser", "fb":
		return showFileBrowserAdminPassword(commandContext(command))
	case "sonarr", "prowlarr", "radarr", "lidarr", "whisparr", "qui", "wizarr":
		return showArrAdminPassword(service)
	case "cobalt":
		return showCobaltAPIKey()
	default:
		return fmt.Errorf(
			"no recovery handler for %q\n\nSupported: qbittorrent, filebrowser, sonarr, prowlarr, radarr, lidarr, whisparr, qui, wizarr, cobalt",
			service,
		)
	}
}

func showArrAdminPassword(service string) error {
	filename := service + "_admin_password.txt"
	password := readSDBXManagedPassword(filename)
	if password == "" {
		return fmt.Errorf(
			"%s managed credential is unavailable; run `sdbx generate`, start the service, then run `sdbx integrate`",
			service,
		)
	}
	fmt.Println(tui.SuccessStyle.Render("✓ Native admin password is configured (sdbx-managed)"))
	fmt.Println(tui.MutedStyle.Render("Reconciled by `sdbx integrate`. Persists across restarts."))
	fmt.Println()
	username := "sdbx-admin"
	if service == "qui" || service == "wizarr" {
		username = "admin"
	}
	fmt.Printf("  Username: %s\n", tui.InfoStyle.Render(username))
	fmt.Printf("  Password: %s\n", tui.InfoStyle.Render(password))
	fmt.Println()
	fmt.Println(tui.MutedStyle.Render("Authelia remains the outer admin-only boundary."))
	fmt.Println(tui.MutedStyle.Render("Rotate it transactionally with `sdbx integrate --rotate-managed-credentials --confirm rotate-managed-credentials`."))
	return nil
}

func showCobaltAPIKey() error {
	key := readSDBXManagedPassword("cobalt_keys.txt")
	if key == "" {
		return fmt.Errorf(
			"cobalt API key is unavailable; enable the addon and run `sdbx generate`",
		)
	}
	data := []byte(key)
	defer zeroBytes(data)
	first, err := integrate.ValidateCobaltKeys(data)
	if err != nil {
		return fmt.Errorf("read Cobalt API key map: %w", err)
	}
	fmt.Println(tui.SuccessStyle.Render("✓ Cobalt API authentication is configured (sdbx-managed)"))
	fmt.Println()
	fmt.Printf("  API key: %s\n", tui.InfoStyle.Render(first))
	fmt.Println()
	fmt.Println(tui.MutedStyle.Render("Paste this key into https://cobalt.tools/settings/instances"))
	fmt.Println(tui.MutedStyle.Render("after selecting your SDBX Cobalt API endpoint."))
	return nil
}

func showQBittorrentTempPassword(parent context.Context) error {
	// First, check if a permanent password is already persisted. If so,
	// any temp password line still in the docker log buffer is stale —
	// don't mislead the user.
	if persisted, username, passwordHash, _, err := qbtHasPersistedPassword(); err == nil && persisted {
		// If sdbx itself set the password (via `sdbx integrate` qBT
		// post-init), the plaintext lives in secrets/qbittorrent_password.txt.
		// Surface it directly — that's the whole point of sdbx managing it.
		if plaintext := readSDBXManagedQBTPassword(); plaintext != "" &&
			integrate.QBittorrentPasswordMatchesHash(plaintext, passwordHash) {
			if username == "" {
				username = "admin"
			}
			fmt.Println(tui.SuccessStyle.Render("✓ Permanent password is configured (sdbx-managed)"))
			fmt.Println(tui.MutedStyle.Render("Set by `sdbx integrate`. Persists across restarts."))
			fmt.Println()
			fmt.Printf("  Username: %s\n", tui.InfoStyle.Render(username))
			fmt.Printf("  Password: %s\n", tui.InfoStyle.Render(plaintext))
			fmt.Println()
			fmt.Println(tui.MutedStyle.Render("Do not change it outside SDBX; v1 does not automate safe rotation."))
			fmt.Println(tui.MutedStyle.Render("See docs/operations.md before any credential change."))
			return nil
		}

		// The current hash has no matching SDBX-managed plaintext. Never show a
		// stale recovery value as though it were authoritative.
		fmt.Println(tui.SuccessStyle.Render("✓ Permanent password is configured"))
		fmt.Println(tui.MutedStyle.Render("Stored as PBKDF2 hash in qBittorrent.conf. Survives container restarts."))
		fmt.Println()
		if username != "" {
			fmt.Printf("  Username: %s\n", tui.InfoStyle.Render(username))
		}
		fmt.Println(strings.TrimSpace(`
The current hash does not match an available SDBX-managed recovery credential.
Take an encrypted backup, then run sdbx integrate to reconcile qBittorrent
with a managed credential. SDBX does not print a password-bearing Docker
command because process arguments and shell history are not private channels.
`))
		return nil
	}

	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()

	out, err := commandexec.CombinedOutput(
		ctx,
		4<<20,
		nil,
		"docker",
		"logs",
		"--tail",
		"10000",
		"sdbx-qbittorrent",
	)
	if err != nil {
		return fmt.Errorf("failed to read sdbx-qbittorrent logs (is the container running?): %w", err)
	}
	defer zeroBytes(out)

	// Take the LAST match — qBittorrent logs a fresh temp password on every
	// start, and the most recent restart is the one that matters.
	matches := qbtTempPasswordRE.FindAllStringSubmatch(string(out), -1)
	if len(matches) == 0 {
		return fmt.Errorf("no temporary password found in qBittorrent logs — try restarting the qbittorrent container")
	}
	password := matches[len(matches)-1][1]

	fmt.Println(tui.WarningStyle.Render("⚠ TEMPORARY PASSWORD"))
	fmt.Println(tui.MutedStyle.Render("Rotates on every qBittorrent container restart."))
	fmt.Println()
	fmt.Printf("  Username: %s\n", tui.InfoStyle.Render("admin"))
	fmt.Printf("  Password: %s\n", tui.InfoStyle.Render(password))
	fmt.Println()
	fmt.Println(strings.TrimSpace(`
Run sdbx integrate to replace this temporary value with an SDBX-managed
permanent credential, then use sdbx secrets show qbittorrent --confirm reveal
from a private terminal when recovery is required.

Tip: while you're in Options, lower "Ban duration" to 60s so a fat-finger
doesn't lock you out for an hour.
`))
	return nil
}

// readSDBXManagedQBTPassword returns the plaintext qBT admin password sdbx
// generated and persisted to secrets/qbittorrent_password.txt. Empty string
// if the file is absent or empty — caller falls back to the "we know there's
// a hash, but we don't know the plaintext" branch.
func readSDBXManagedQBTPassword() string {
	return readSDBXManagedPassword("qbittorrent_password.txt")
}

// readSDBXManagedFBPassword returns the plaintext filebrowser admin password
// sdbx persisted to secrets/filebrowser_admin_password.txt during the
// `sdbx integrate` post-init phase. Empty string if absent.
func readSDBXManagedFBPassword() string {
	return readSDBXManagedPassword("filebrowser_admin_password.txt")
}

// readSDBXManagedPassword resolves the secrets path with cfg.SecretsPath
// honored and returns the trimmed contents of secrets/<filename>. Returns
// empty string on any error. The secret reader rejects symlink swaps, special
// files, and oversized values before returning credential material.
func readSDBXManagedPassword(filename string) string {
	projectDir, err := config.ProjectDir()
	if err != nil {
		return ""
	}
	cfg, err := config.LoadFile(filepath.Join(projectDir, ".sdbx.yaml"))
	if err != nil {
		return ""
	}
	root := cfg.SecretsPath
	if root == "" {
		root = "./secrets"
	}
	if !filepath.IsAbs(root) {
		root = filepath.Join(projectDir, root)
	}
	value, err := secrets.ReadSecret(root, filename)
	if err != nil {
		return ""
	}
	return value
}

// qbtHasPersistedPassword reports whether qBittorrent.conf already contains a
// PBKDF2 password hash, the configured username (if any), and the absolute
// path to the conf file. Returns (false, "", "", err) if the file isn't
// readable — callers should treat that as "unknown" and fall back to log
// scanning.
func qbtHasPersistedPassword() (bool, string, string, string, error) {
	projectDir, err := config.ProjectDir()
	if err != nil {
		return false, "", "", "", err
	}

	cfg, err := config.LoadFile(filepath.Join(projectDir, ".sdbx.yaml"))
	if err != nil {
		return false, "", "", "", err
	}

	configRoot := cfg.ConfigPath
	if !filepath.IsAbs(configRoot) {
		configRoot = filepath.Join(projectDir, configRoot)
	}
	confPath := filepath.Join(configRoot, "qbittorrent", "qBittorrent", "qBittorrent.conf")

	data, err := securefs.ReadRegularFile(confPath, 4<<20)
	if err != nil {
		return false, "", "", confPath, err
	}
	body := string(data)

	var username, passwordHash string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, `WebUI\Username=`) {
			username = strings.TrimPrefix(line, `WebUI\Username=`)
			username = strings.Trim(username, "\r\" ")
		}
		if strings.HasPrefix(line, `WebUI\Password_PBKDF2=`) {
			passwordHash = strings.TrimPrefix(line, `WebUI\Password_PBKDF2=`)
			passwordHash = strings.TrimSpace(passwordHash)
		}
	}
	return passwordHash != "", username, passwordHash, confPath, nil
}

func showFileBrowserAdminPassword(parent context.Context) error {
	// Prefer the sdbx-managed plaintext if `sdbx integrate` set it. Same
	// recovery UX as qBittorrent: the secret file is the source of truth.
	if plaintext := readSDBXManagedFBPassword(); plaintext != "" {
		fmt.Println(tui.SuccessStyle.Render("✓ Permanent password is configured (sdbx-managed)"))
		fmt.Println(tui.MutedStyle.Render("Set by `sdbx integrate`. Persists across restarts."))
		fmt.Println()
		fmt.Printf("  Username: %s\n", tui.InfoStyle.Render("admin"))
		fmt.Printf("  Password: %s\n", tui.InfoStyle.Render(plaintext))
		fmt.Println()
		fmt.Println(tui.MutedStyle.Render("Do not change it outside SDBX; v1 does not automate safe rotation."))
		fmt.Println(tui.MutedStyle.Render("See docs/operations.md before any credential change."))
		return nil
	}

	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()

	out, err := commandexec.CombinedOutput(
		ctx,
		4<<20,
		nil,
		"docker",
		"logs",
		"--tail",
		"10000",
		"sdbx-filebrowser",
	)
	if err != nil {
		return fmt.Errorf("failed to read sdbx-filebrowser logs (is the container running?): %w", err)
	}
	defer zeroBytes(out)

	// First-launch line is logged exactly once per fresh filebrowser.db. If
	// it's still in the docker log buffer, it's the password unless the user
	// has changed it since (we can't tell from logs alone — flag that risk).
	matches := fbAdminPasswordRE.FindAllStringSubmatch(string(out), -1)
	if len(matches) == 0 {
		fmt.Println(tui.MutedStyle.Render("No first-launch password line in current log buffer."))
		fmt.Println()
		fmt.Println("Either filebrowser was started before the current log retention window,")
		fmt.Println("or the database was already initialized when this container booted.")
		fmt.Println()
		fmt.Println(tui.InfoStyle.Render("Recovery"))
		fmt.Println("Take an encrypted backup, then follow the reviewed File Browser")
		fmt.Println("recovery procedure in docs/operations.md. Do not put a password in")
		fmt.Println("Docker arguments or shell history.")
		return nil
	}
	username := matches[len(matches)-1][1]
	password := matches[len(matches)-1][2]

	fmt.Println(tui.WarningStyle.Render("⚠ FIRST-LAUNCH PASSWORD"))
	fmt.Println(tui.MutedStyle.Render("Auto-generated on filebrowser.db init. Persists across restarts — but if you've"))
	fmt.Println(tui.MutedStyle.Render("changed it via the WebUI since first launch, this value will no longer work."))
	fmt.Println()
	fmt.Printf("  Username: %s\n", tui.InfoStyle.Render(username))
	fmt.Printf("  Password: %s\n", tui.InfoStyle.Render(password))
	fmt.Println()
	fmt.Println(strings.TrimSpace(`
Run sdbx integrate to replace this first-launch value with an SDBX-managed
credential. If this value is stale, use the recovery procedure in
docs/operations.md; do not pass a password in Docker arguments.
`))
	return nil
}
