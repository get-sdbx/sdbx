package integrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/get-sdbx/sdbx/internal/commandexec"
	"github.com/get-sdbx/sdbx/internal/redact"
	sdbxsecrets "github.com/get-sdbx/sdbx/internal/secrets"
)

const wizarrReconcileScript = `
import json, os, sys
from app import create_app
from app.extensions import db
from app.models import AdminAccount, MediaServer

payload = json.load(sys.stdin)
app = create_app()
with app.app_context():
    admins = AdminAccount.query.filter_by(auth_source="local").all()
    if len(admins) != 1:
        raise RuntimeError("expected exactly one local Wizarr administrator")
    admin = admins[0]
    servers = MediaServer.query.filter_by(server_type="plex").all()
    if len(servers) != 1:
        raise RuntimeError("expected exactly one Wizarr Plex server")
    server = servers[0]
    if payload["apply"]:
        admin.set_password(payload["password"])
        server.url = "http://sdbx-plex:32400"
        server.api_key = payload["plex_token"]
        server.verified = True
        db.session.flush()
    if not admin.check_password(payload["password"]):
        raise RuntimeError("managed Wizarr credential verification failed")
    if server.url.rstrip("/") != "http://sdbx-plex:32400" or server.api_key != payload["plex_token"] or not server.verified:
        raise RuntimeError("managed Wizarr Plex connection verification failed")
    if payload["apply"]:
        db.session.commit()
print("ok", flush=True)
os._exit(0)
`

const wizarrReconcileTimeout = 60 * time.Second

func wizarrReconcileCommandArgs() []string {
	return []string{
		"exec",
		"-i",
		"sdbx-wizarr",
		"/app/.venv/bin/python",
		"-c",
		wizarrReconcileScript,
	}
}

func verifyPlexConnection(
	ctx context.Context,
	client *HTTPClient,
	service *ServiceConfig,
) error {
	service = serviceControlConfig(service)
	body, err := client.Get(
		ctx,
		strings.TrimRight(service.URL, "/")+"/identity",
		map[string]string{"X-Plex-Token": service.APIKey},
	)
	wipeCredentialBytes(body)
	if err != nil {
		return fmt.Errorf("verify Plex application token: %w", err)
	}
	return nil
}

func reconcileWizarrState(
	ctx context.Context,
	password string,
	plexToken string,
	apply bool,
) error {
	payload, err := json.Marshal(map[string]any{
		"password":   password,
		"plex_token": plexToken,
		"apply":      apply,
	})
	if err != nil {
		return fmt.Errorf("encode Wizarr reconciliation input: %w", err)
	}
	defer wipeCredentialBytes(payload)
	input := append(payload, '\n')
	defer wipeCredentialBytes(input)
	commandContext, cancel := context.WithTimeout(ctx, wizarrReconcileTimeout)
	defer cancel()
	output, err := commandexec.CombinedOutput(
		commandContext,
		1<<20,
		bytes.NewReader(input),
		"docker",
		wizarrReconcileCommandArgs()...,
	)
	defer wipeCredentialBytes(output)
	if err != nil {
		return fmt.Errorf(
			"run bounded Wizarr reconciliation: %w (%s)",
			err,
			redact.Text(strings.TrimSpace(string(output))),
		)
	}
	if !wizarrReconcileOutputOK(output) {
		return fmt.Errorf("Wizarr reconciliation returned an unexpected result")
	}
	return nil
}

func wizarrReconcileOutputOK(output []byte) bool {
	lines := strings.Split(string(output), "\n")
	for index := len(lines) - 1; index >= 0; index-- {
		line := strings.TrimSpace(lines[index])
		if line == "" {
			continue
		}
		return line == "ok"
	}
	return false
}

func (i *Integrator) integrateWizarr(ctx context.Context) *IntegrationResult {
	result := &IntegrationResult{Service: "wizarr native authentication and plex"}
	plex := i.services["plex"]
	if plex == nil || !plex.Enabled {
		result.Message, result.Error = "Plex integration is unavailable", fmt.Errorf("Plex service configuration is unavailable")
		return result
	}
	if err := verifyPlexConnection(ctx, i.httpClient, plex); err != nil {
		result.Message, result.Error = "Plex preflight failed", err
		return result
	}
	credentialPath := secretsFilePath(i.config.ProjectConfig, "wizarr_admin_password.txt")
	previous := ""
	previousExists := false
	if value, err := sdbxsecrets.ReadSecret(
		filepath.Dir(credentialPath),
		filepath.Base(credentialPath),
	); err == nil {
		previous, previousExists = value, true
	}
	if !i.config.RotateCredentials {
		if !previousExists {
			result.Message = "Managed recovery credential is unavailable"
			result.Error = fmt.Errorf("run with explicit managed credential rotation")
			return result
		}
		if i.wizarrReconcile == nil {
			result.Message, result.Error = "Wizarr reconciliation handler is unavailable", fmt.Errorf("Wizarr reconciliation handler is unavailable")
			return result
		}
		if err := i.wizarrReconcile(ctx, previous, plex.APIKey, false); err != nil {
			result.Message, result.Error = "Managed credential or Plex connection failed verification", err
			return result
		}
		result.Success, result.Message = true, "Managed credential and Plex connection verified"
		return result
	}
	if i.config.DryRun {
		result.Success, result.Message = true, "[DRY RUN] Would rotate the managed credential and repair Plex"
		return result
	}
	next, err := sdbxsecrets.GenerateRandomString(24)
	if err != nil {
		result.Message, result.Error = "Failed to generate managed credential", err
		return result
	}
	nextBytes := []byte(next)
	if err := writeFileChown(
		credentialPath,
		nextBytes,
		0o600,
		i.config.ProjectConfig.PUID,
		i.config.ProjectConfig.PGID,
	); err != nil {
		wipeCredentialBytes(nextBytes)
		result.Message, result.Error = "Failed to persist managed credential", err
		return result
	}
	wipeCredentialBytes(nextBytes)
	if i.wizarrReconcile == nil {
		result.Message, result.Error = "Wizarr reconciliation handler is unavailable", fmt.Errorf("Wizarr reconciliation handler is unavailable")
		return result
	}
	if err := i.wizarrReconcile(ctx, next, plex.APIKey, true); err != nil {
		// A container exec can lose its output after the database transaction
		// committed. Verify the desired state before rolling anything back.
		if verifyErr := i.wizarrReconcile(ctx, next, plex.APIKey, false); verifyErr == nil {
			result.Success = true
			result.Message = "Credential rotated and Plex connection repaired and verified"
			return result
		}

		var rollbackErr error
		if previousExists {
			applicationRollbackErr := i.wizarrReconcile(
				ctx,
				previous,
				plex.APIKey,
				true,
			)
			previousBytes := []byte(previous)
			secretRollbackErr := writeFileChown(
				credentialPath,
				previousBytes,
				0o600,
				i.config.ProjectConfig.PUID,
				i.config.ProjectConfig.PGID,
			)
			wipeCredentialBytes(previousBytes)
			rollbackErr = errors.Join(applicationRollbackErr, secretRollbackErr)
		} else {
			rollbackErr = os.Remove(credentialPath)
			if errors.Is(rollbackErr, os.ErrNotExist) {
				rollbackErr = nil
			}
		}
		result.Message = "Wizarr reconciliation failed; recovery secret rollback attempted"
		result.Error = errors.Join(err, rollbackErr)
		return result
	}
	if err := i.wizarrReconcile(ctx, next, plex.APIKey, false); err != nil {
		var rollbackErr error
		if previousExists {
			applicationRollbackErr := i.wizarrReconcile(
				ctx,
				previous,
				plex.APIKey,
				true,
			)
			previousBytes := []byte(previous)
			secretRollbackErr := writeFileChown(
				credentialPath,
				previousBytes,
				0o600,
				i.config.ProjectConfig.PUID,
				i.config.ProjectConfig.PGID,
			)
			wipeCredentialBytes(previousBytes)
			rollbackErr = errors.Join(applicationRollbackErr, secretRollbackErr)
		}
		result.Message = "Rotated state failed verification; rollback attempted"
		result.Error = errors.Join(err, rollbackErr)
		return result
	}
	result.Success, result.Message = true, "Credential rotated and Plex connection repaired and verified"
	return result
}
