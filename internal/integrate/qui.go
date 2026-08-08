package integrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	sdbxsecrets "github.com/get-sdbx/sdbx/internal/secrets"
)

type quiClient struct {
	client *HTTPClient
	config *ServiceConfig
}

type quiSetupState struct {
	SetupRequired bool `json:"setupRequired"`
}

type quiInstance struct {
	ID                       int    `json:"id"`
	Name                     string `json:"name"`
	Host                     string `json:"host"`
	Username                 string `json:"username"`
	Active                   bool   `json:"isActive"`
	Connected                bool   `json:"connected"`
	TLSSkipVerify            bool   `json:"tlsSkipVerify"`
	HasLocalFilesystemAccess bool   `json:"hasLocalFilesystemAccess"`
	UseHardlinks             bool   `json:"useHardlinks"`
	HardlinkBaseDir          string `json:"hardlinkBaseDir"`
	HardlinkDirPreset        string `json:"hardlinkDirPreset"`
	UseReflinks              bool   `json:"useReflinks"`
	FallbackToRegularMode    bool   `json:"fallbackToRegularMode"`
}

func newQuiClient(client *HTTPClient, cfg *ServiceConfig) *quiClient {
	return &quiClient{client: client, config: cfg}
}

func (q *quiClient) endpoint(path string) string {
	return strings.TrimRight(q.config.URL, "/") + path
}

func (q *quiClient) setupState(ctx context.Context) (*quiSetupState, error) {
	body, err := q.client.Get(ctx, q.endpoint("/api/auth/check-setup"), nil)
	if err != nil {
		return nil, err
	}
	defer wipeCredentialBytes(body)
	var state quiSetupState
	if err := json.Unmarshal(body, &state); err != nil {
		return nil, fmt.Errorf("decode Qui setup state: %w", err)
	}
	return &state, nil
}

func (q *quiClient) login(ctx context.Context, password string) error {
	_, err := q.client.Post(ctx, q.endpoint("/api/auth/login"), nil, map[string]string{
		"username": "admin",
		"password": password,
	})
	if err != nil {
		return fmt.Errorf("authenticate Qui managed administrator: %w", err)
	}
	return nil
}

func (q *quiClient) setup(ctx context.Context, password string) error {
	_, err := q.client.Post(ctx, q.endpoint("/api/auth/setup"), nil, map[string]string{
		"username": "admin",
		"password": password,
	})
	if err != nil {
		return fmt.Errorf("initialize Qui managed administrator: %w", err)
	}
	return nil
}

func (q *quiClient) changePassword(ctx context.Context, current, next string) error {
	_, err := q.client.Put(
		ctx,
		q.endpoint("/api/auth/change-password"),
		nil,
		map[string]string{
			"currentPassword": current,
			"newPassword":     next,
		},
	)
	if err != nil {
		return fmt.Errorf("rotate Qui managed administrator: %w", err)
	}
	return nil
}

func (q *quiClient) instances(ctx context.Context) ([]quiInstance, error) {
	body, err := q.client.Get(ctx, q.endpoint("/api/instances"), nil)
	if err != nil {
		return nil, err
	}
	defer wipeCredentialBytes(body)
	var instances []quiInstance
	if err := json.Unmarshal(body, &instances); err != nil {
		return nil, fmt.Errorf("decode Qui instances: %w", err)
	}
	return instances, nil
}

func (q *quiClient) saveInstance(
	ctx context.Context,
	current *quiInstance,
	qbt *ServiceConfig,
) error {
	payload := map[string]any{
		"name":          "sdbx-qbittorrent",
		"host":          qbt.URL,
		"username":      "admin",
		"password":      qbt.APIKey,
		"tlsSkipVerify": false,
	}
	var body []byte
	var err error
	if current == nil {
		payload["hasLocalFilesystemAccess"] = false
		payload["useHardlinks"] = false
		payload["useReflinks"] = false
		payload["fallbackToRegularMode"] = false
		body, err = q.client.Post(ctx, q.endpoint("/api/instances"), nil, payload)
	} else {
		payload["hasLocalFilesystemAccess"] = current.HasLocalFilesystemAccess
		payload["useHardlinks"] = current.UseHardlinks
		payload["hardlinkBaseDir"] = current.HardlinkBaseDir
		payload["hardlinkDirPreset"] = current.HardlinkDirPreset
		payload["useReflinks"] = current.UseReflinks
		payload["fallbackToRegularMode"] = current.FallbackToRegularMode
		body, err = q.client.Put(
			ctx,
			q.endpoint("/api/instances/"+strconv.Itoa(current.ID)),
			nil,
			payload,
		)
	}
	if err != nil {
		return err
	}
	wipeCredentialBytes(body)
	return nil
}

func (q *quiClient) testInstance(ctx context.Context, id int) error {
	body, err := q.client.Post(
		ctx,
		q.endpoint("/api/instances/"+strconv.Itoa(id)+"/test"),
		nil,
		nil,
	)
	wipeCredentialBytes(body)
	return err
}

func (i *Integrator) integrateQui(ctx context.Context) []*IntegrationResult {
	credentialResult := &IntegrationResult{Service: "qui native authentication"}
	instanceResult := &IntegrationResult{Service: "qui → qbittorrent"}
	client := newQuiClient(i.httpClient, serviceControlConfig(i.services["qui"]))
	state, err := client.setupState(ctx)
	if err != nil {
		credentialResult.Message, credentialResult.Error = "Failed to inspect setup state", err
		return []*IntegrationResult{credentialResult}
	}
	credentialPath := secretsFilePath(i.config.ProjectConfig, "qui_admin_password.txt")
	if state.SetupRequired {
		if i.config.DryRun {
			credentialResult.Success = true
			credentialResult.Message = "[DRY RUN] Would initialize a unique managed administrator credential"
			return []*IntegrationResult{credentialResult}
		}
		password, generateErr := sdbxsecrets.GenerateRandomString(24)
		if generateErr != nil {
			credentialResult.Message, credentialResult.Error = "Failed to generate managed credential", generateErr
			return []*IntegrationResult{credentialResult}
		}
		credentialBytes := []byte(password)
		writeErr := writeFileChown(
			credentialPath,
			credentialBytes,
			0o600,
			i.config.ProjectConfig.PUID,
			i.config.ProjectConfig.PGID,
		)
		wipeCredentialBytes(credentialBytes)
		if writeErr != nil {
			credentialResult.Message, credentialResult.Error = "Failed to persist managed credential", writeErr
			return []*IntegrationResult{credentialResult}
		}
		if setupErr := client.setup(ctx, password); setupErr != nil {
			_ = os.Remove(credentialPath)
			credentialResult.Message, credentialResult.Error = "Failed to initialize managed administrator", setupErr
			return []*IntegrationResult{credentialResult}
		}
		if loginErr := client.login(ctx, password); loginErr != nil {
			credentialResult.Message, credentialResult.Error = "Initialized credential failed verification", loginErr
			return []*IntegrationResult{credentialResult}
		}
		credentialResult.Success, credentialResult.Message = true, "Initialized and verified"
	} else {
		password, readErr := sdbxsecrets.ReadSecret(
			filepath.Dir(credentialPath),
			filepath.Base(credentialPath),
		)
		if readErr != nil {
			credentialResult.Message, credentialResult.Error = "Managed recovery credential is unavailable", readErr
			return []*IntegrationResult{credentialResult}
		}
		if loginErr := client.login(ctx, password); loginErr != nil {
			credentialResult.Message, credentialResult.Error = "Managed recovery credential does not authenticate", loginErr
			return []*IntegrationResult{credentialResult}
		}
		if i.config.RotateCredentials {
			if i.config.DryRun {
				credentialResult.Success = true
				credentialResult.Message = "[DRY RUN] Would rotate and verify the managed credential"
			} else {
				next, generateErr := sdbxsecrets.GenerateRandomString(24)
				if generateErr != nil {
					credentialResult.Message, credentialResult.Error = "Failed to generate rotated credential", generateErr
					return []*IntegrationResult{credentialResult}
				}
				if changeErr := client.changePassword(ctx, password, next); changeErr != nil {
					credentialResult.Message, credentialResult.Error = "Failed to rotate managed credential", changeErr
					return []*IntegrationResult{credentialResult}
				}
				credentialBytes := []byte(next)
				writeErr := writeFileChown(
					credentialPath,
					credentialBytes,
					0o600,
					i.config.ProjectConfig.PUID,
					i.config.ProjectConfig.PGID,
				)
				wipeCredentialBytes(credentialBytes)
				if writeErr != nil {
					rollbackErr := client.changePassword(ctx, next, password)
					credentialResult.Message = "Failed to persist rotated credential; application rollback attempted"
					credentialResult.Error = fmt.Errorf("persist Qui credential: %w; rollback: %v", writeErr, rollbackErr)
					return []*IntegrationResult{credentialResult}
				}
				if loginErr := client.login(ctx, next); loginErr != nil {
					applicationRollbackErr := client.changePassword(ctx, next, password)
					previousBytes := []byte(password)
					secretRollbackErr := writeFileChown(
						credentialPath,
						previousBytes,
						0o600,
						i.config.ProjectConfig.PUID,
						i.config.ProjectConfig.PGID,
					)
					wipeCredentialBytes(previousBytes)
					credentialResult.Message = "Rotated credential failed verification; rollback attempted"
					credentialResult.Error = errors.Join(
						loginErr,
						applicationRollbackErr,
						secretRollbackErr,
					)
					return []*IntegrationResult{credentialResult}
				}
				credentialResult.Success, credentialResult.Message = true, "Rotated and verified"
			}
		} else {
			credentialResult.Success, credentialResult.Message = true, "Managed credential verified"
		}
	}

	qbt := i.services["qbittorrent"]
	if qbt == nil || !qbt.Enabled {
		instanceResult.Success, instanceResult.Message = true, "Not applicable"
		return []*IntegrationResult{credentialResult, instanceResult}
	}
	instances, err := client.instances(ctx)
	if err != nil {
		instanceResult.Message, instanceResult.Error = "Failed to inspect qBittorrent instances", err
		return []*IntegrationResult{credentialResult, instanceResult}
	}
	var managed *quiInstance
	for index := range instances {
		if strings.EqualFold(instances[index].Name, "sdbx-qbittorrent") {
			managed = &instances[index]
			break
		}
	}
	if managed != nil && managed.Host == qbt.URL && managed.Username == "admin" && !managed.TLSSkipVerify {
		if err := client.testInstance(ctx, managed.ID); err == nil && !i.config.RotateCredentials {
			instanceResult.Success, instanceResult.Message = true, "Already configured and verified"
			return []*IntegrationResult{credentialResult, instanceResult}
		}
	}
	if i.config.DryRun {
		instanceResult.Success, instanceResult.Message = true, "[DRY RUN] Would repair and verify managed instance"
		return []*IntegrationResult{credentialResult, instanceResult}
	}
	if err := client.saveInstance(ctx, managed, qbt); err != nil {
		instanceResult.Message, instanceResult.Error = "Failed to repair managed instance", err
		return []*IntegrationResult{credentialResult, instanceResult}
	}
	instances, err = client.instances(ctx)
	if err != nil {
		instanceResult.Message, instanceResult.Error = "Failed to read repaired instance", err
		return []*IntegrationResult{credentialResult, instanceResult}
	}
	managed = nil
	for index := range instances {
		if strings.EqualFold(instances[index].Name, "sdbx-qbittorrent") {
			managed = &instances[index]
			break
		}
	}
	if managed == nil || managed.Host != qbt.URL || managed.Username != "admin" || managed.TLSSkipVerify {
		instanceResult.Message = "Repaired instance failed read-back verification"
		instanceResult.Error = fmt.Errorf("Qui managed instance mismatch")
		return []*IntegrationResult{credentialResult, instanceResult}
	}
	if err := client.testInstance(ctx, managed.ID); err != nil {
		instanceResult.Message, instanceResult.Error = "Repaired instance failed connection test", err
		return []*IntegrationResult{credentialResult, instanceResult}
	}
	instanceResult.Success, instanceResult.Message = true, "Repaired and verified"
	return []*IntegrationResult{credentialResult, instanceResult}
}
