package integrate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/get-sdbx/sdbx/internal/commandexec"
	"github.com/get-sdbx/sdbx/internal/config"
	sdbxsecrets "github.com/get-sdbx/sdbx/internal/secrets"
)

// FBInitResult records what the filebrowser post-init step did.
type FBInitResult struct {
	Action      string // "stamped", "rotated", "skipped-already-init", "skipped-not-enabled", "skipped-not-running"
	PasswordSet bool
	Reason      string
	Err         error
}

const (
	fbInitStampFilename = ".sdbx-init-stamp"
	// fbInitStampVersion bumps trigger a one-time re-run on every host.
	fbInitStampVersion            = "1"
	filebrowserCommandOutputLimit = 1 << 20
)

// EnsureFilebrowserInitialised provisions filebrowser's admin user with an
// sdbx-managed password. The plaintext is generated/persisted to
// <SecretsPath>/filebrowser_admin_password.txt so `sdbx secrets show
// filebrowser` can surface it on demand — same UX as qBittorrent.
//
// Implementation: we stop the container, run `filebrowser users update admin
// --password <pw>` (or `users add` if the user doesn't yet exist) in a
// one-shot run --rm, then restart. BoltDB is single-writer, so editing the
// DB requires the main filebrowser process to be down.
//
// Idempotent: stamps <ConfigPath>/filebrowser/.sdbx-init-stamp and skips on
// subsequent calls. Wipe the stamp + the secret file to force a rotation.
func EnsureFilebrowserInitialised(ctx context.Context, cfg *config.Config) (*FBInitResult, error) {
	return ensureFilebrowserInitialised(ctx, cfg, false)
}

// RotateFilebrowserCredential updates File Browser's BoltDB while its main
// process is stopped, then atomically replaces the private recovery secret.
func RotateFilebrowserCredential(
	ctx context.Context,
	cfg *config.Config,
) (*FBInitResult, error) {
	return ensureFilebrowserInitialised(ctx, cfg, true)
}

func ensureFilebrowserInitialised(
	ctx context.Context,
	cfg *config.Config,
	rotate bool,
) (*FBInitResult, error) {
	res := &FBInitResult{}
	if !IsServiceEnabled(cfg, "filebrowser") {
		res.Action = "skipped-not-enabled"
		return res, nil
	}

	stampPath := filepath.Join(cfg.ConfigPath, "filebrowser", fbInitStampFilename)
	if !rotate && matchesStamp(stampPath, fbInitStampVersion) {
		if managedCredentialAvailable(cfg, "filebrowser_admin_password.txt") {
			res.Action = "skipped-already-init"
			return res, nil
		}
		if err := writeStamp(
			stampPath,
			fbInitStampVersion+"-credential-recovery-pending",
			cfg.PUID,
			cfg.PGID,
		); err != nil {
			res.Err = fmt.Errorf("mark filebrowser credential recovery pending: %w", err)
			return res, res.Err
		}
	}

	// Filebrowser must have written its initial DB before we can update the
	// admin user. Bail with a hint if the DB isn't there yet — the next
	// `sdbx integrate` will retry.
	dbPath := filepath.Join(cfg.ConfigPath, "filebrowser", "filebrowser.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		res.Action = "skipped-not-running"
		res.Reason = fmt.Sprintf("filebrowser.db not present at %s — run `sdbx up`, wait for filebrowser to settle, then re-run `sdbx integrate`", dbPath)
		return res, nil
	}

	credentialPath := secretsFilePath(cfg, "filebrowser_admin_password.txt")
	previousPassword := ""
	password := ""
	var err error
	if rotate {
		previousPassword, err = sdbxsecrets.ReadSecret(
			filepath.Dir(credentialPath),
			filepath.Base(credentialPath),
		)
		if err == nil {
			password, err = sdbxsecrets.GenerateRandomString(24)
		}
	} else {
		password, err = readOrCreateSecret(
			credentialPath,
			24,
			cfg.PUID,
			cfg.PGID,
		)
	}
	if err != nil {
		res.Err = fmt.Errorf("provision filebrowser password: %w", err)
		return res, res.Err
	}

	if err := dockerComposeStop(ctx, "filebrowser"); err != nil {
		res.Err = fmt.Errorf("stop filebrowser: %w", err)
		return res, res.Err
	}

	if err := setFilebrowserAdminPassword(ctx, password); err != nil {
		_ = dockerComposeStart(ctx, "filebrowser") // best-effort restart
		res.Err = fmt.Errorf("set filebrowser admin password: %w", err)
		return res, res.Err
	}
	if rotate {
		credentialBytes := []byte(password)
		writeErr := writeFileChown(
			credentialPath,
			credentialBytes,
			0o600,
			cfg.PUID,
			cfg.PGID,
		)
		wipeCredentialBytes(credentialBytes)
		if writeErr != nil {
			rollbackErr := setFilebrowserAdminPassword(ctx, previousPassword)
			_ = dockerComposeStart(ctx, "filebrowser")
			res.Err = errors.Join(
				fmt.Errorf("persist rotated filebrowser credential: %w", writeErr),
				rollbackErr,
			)
			return res, res.Err
		}
	}
	res.PasswordSet = true

	if err := dockerComposeStart(ctx, "filebrowser"); err != nil {
		if rotate {
			_ = setFilebrowserAdminPassword(ctx, previousPassword)
			previousBytes := []byte(previousPassword)
			_ = writeFileChown(
				credentialPath,
				previousBytes,
				0o600,
				cfg.PUID,
				cfg.PGID,
			)
			wipeCredentialBytes(previousBytes)
			_ = dockerComposeStart(ctx, "filebrowser")
		}
		res.Err = fmt.Errorf("start filebrowser: %w", err)
		return res, res.Err
	}

	if err := writeStamp(stampPath, fbInitStampVersion, cfg.PUID, cfg.PGID); err != nil {
		res.Err = fmt.Errorf("write stamp: %w", err)
		return res, res.Err
	}

	res.Action = "stamped"
	if rotate {
		res.Action = "rotated"
	}
	return res, nil
}

// setFilebrowserAdminPassword runs File Browser's native user command in a
// one-shot container that mounts the same /database volume as the main
// service. The password is supplied over stdin to a fixed BusyBox wrapper so
// it never appears in Docker's host-side process arguments. Falls back to
// `users add` if the admin user doesn't yet exist.
func setFilebrowserAdminPassword(ctx context.Context, password string) error {
	input := append([]byte(password), '\n')
	defer wipeCredentialBytes(input)
	out, err := commandexec.CombinedOutput(
		ctx,
		filebrowserCommandOutputLimit,
		bytes.NewReader(input),
		"docker",
		filebrowserPasswordCommandArgs("update")...,
	)
	defer wipeCredentialBytes(out)
	if err == nil {
		return nil
	}
	// Distinguish "user not found" from other failures so we know when to
	// fall back to `users add`. Filebrowser's CLI prints "the resource does
	// not exist" or similar when admin is missing.
	combined := strings.ToLower(string(out))
	if !(strings.Contains(combined, "does not exist") ||
		strings.Contains(combined, "not found") ||
		strings.Contains(combined, "no such") ||
		strings.Contains(combined, "user not found")) {
		return fmt.Errorf("users update admin: %w", err)
	}

	addOutput, err := commandexec.CombinedOutput(
		ctx,
		filebrowserCommandOutputLimit,
		bytes.NewReader(input),
		"docker",
		filebrowserPasswordCommandArgs("add")...,
	)
	wipeCredentialBytes(addOutput)
	if err != nil {
		return fmt.Errorf("users add admin: %w", err)
	}
	return nil
}

func filebrowserPasswordCommandArgs(action string) []string {
	script := `IFS= read -r sdbx_password
exec filebrowser users update admin --password "$sdbx_password" --database /database/filebrowser.db`
	if action == "add" {
		script = `IFS= read -r sdbx_password
exec filebrowser users add admin "$sdbx_password" --perm.admin --database /database/filebrowser.db`
	}

	return []string{
		"compose", "run", "--rm", "--no-deps", "--entrypoint", "/bin/sh",
		"filebrowser",
		"-eu", "-c",
		script,
	}
}
