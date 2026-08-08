package integrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	sdbxsecrets "github.com/get-sdbx/sdbx/internal/secrets"
)

const arrManagedAdminUsername = "sdbx-admin"

type arrManagedAuthSpec struct {
	name       string
	apiVersion string
	secretFile string
}

var arrManagedAuthSpecs = []arrManagedAuthSpec{
	{
		name:       "lidarr",
		apiVersion: "v1",
		// #nosec G101 -- this is a public filename, not credential material.
		secretFile: "lidarr_admin_password.txt",
	},
	{
		name:       "prowlarr",
		apiVersion: "v1",
		// #nosec G101 -- this is a public filename, not credential material.
		secretFile: "prowlarr_admin_password.txt",
	},
	{
		name:       "radarr",
		apiVersion: "v3",
		// #nosec G101 -- this is a public filename, not credential material.
		secretFile: "radarr_admin_password.txt",
	},
	{
		name:       "sonarr",
		apiVersion: "v3",
		// #nosec G101 -- this is a public filename, not credential material.
		secretFile: "sonarr_admin_password.txt",
	},
	{
		name:       "whisparr",
		apiVersion: "v3",
		// #nosec G101 -- this is a public filename, not credential material.
		secretFile: "whisparr_admin_password.txt",
	},
}

// reconcileArrAuthentication authoritatively enables native Forms
// authentication for the official *arr services. Authelia remains in front of
// their public routes; this second boundary blocks lateral access from
// compromised Docker-network peers.
func (i *Integrator) reconcileArrAuthentication(
	ctx context.Context,
) []*IntegrationResult {
	results := make([]*IntegrationResult, 0, len(arrManagedAuthSpecs))
	for _, spec := range arrManagedAuthSpecs {
		service, ok := i.services[spec.name]
		if !ok || service == nil || !service.Enabled {
			continue
		}

		if i.config.DryRun {
			action := "verify Forms authentication and reconcile"
			if i.config.RotateCredentials {
				action = "rotate"
			}
			results = append(results, &IntegrationResult{
				Service: spec.name + " native authentication",
				Success: true,
				Message: "[DRY RUN] Would " + action + " the SDBX-managed admin credential",
			})
			continue
		}

		action, err := i.ensureArrNativeAuthentication(ctx, spec, service)
		if err != nil {
			results = append(results, &IntegrationResult{
				Service: spec.name + " native authentication",
				Success: false,
				Message: "Failed to reconcile native authentication",
				Error:   err,
			})
			continue
		}
		message := "SDBX-managed Forms authentication already verified"
		if action == "reconciled" {
			message = "Enabled Forms authentication and reconciled the SDBX-managed admin credential"
		} else if action == "rotated" {
			message = "Rotated and verified the SDBX-managed Forms credential"
		}
		results = append(results, &IntegrationResult{
			Service: spec.name + " native authentication",
			Success: true,
			Message: message,
		})
	}
	return results
}

func (i *Integrator) ensureArrNativeAuthentication(
	ctx context.Context,
	spec arrManagedAuthSpec,
	service *ServiceConfig,
) (string, error) {
	if i.config.ProjectConfig == nil {
		return "", fmt.Errorf("verified project configuration is required")
	}
	if service == nil || service.APIKey == "" {
		return "", fmt.Errorf("%s API key is unavailable", spec.name)
	}

	credentialPath := secretsFilePath(i.config.ProjectConfig, spec.secretFile)
	password := ""
	previousPassword := ""
	var err error
	if i.config.RotateCredentials {
		previousPassword, err = sdbxsecrets.ReadSecret(
			filepath.Dir(credentialPath),
			filepath.Base(credentialPath),
		)
		if err != nil {
			return "", fmt.Errorf("read previous %s admin credential: %w", spec.name, err)
		}
		password, err = sdbxsecrets.GenerateRandomString(24)
	} else {
		password, err = readOrCreateSecret(
			credentialPath,
			24,
			i.config.ProjectConfig.PUID,
			i.config.ProjectConfig.PGID,
		)
	}
	if err != nil {
		return "", fmt.Errorf("provision %s admin credential: %w", spec.name, err)
	}

	control := serviceControlConfig(service)
	if control == nil || strings.TrimSpace(control.URL) == "" {
		return "", fmt.Errorf("%s control endpoint is unavailable", spec.name)
	}
	hostConfigURL := strings.TrimRight(control.URL, "/") +
		"/api/" + spec.apiVersion + "/config/host"
	headers := map[string]string{"X-Api-Key": service.APIKey}
	body, err := i.httpClient.Get(ctx, hostConfigURL, headers)
	if err != nil {
		return "", fmt.Errorf("read %s host configuration: %w", spec.name, err)
	}
	defer wipeCredentialBytes(body)

	var hostConfig map[string]any
	if err := json.Unmarshal(body, &hostConfig); err != nil {
		return "", fmt.Errorf("decode %s host configuration: %w", spec.name, err)
	}
	if len(hostConfig) == 0 {
		return "", fmt.Errorf("%s returned an empty host configuration", spec.name)
	}

	method, _ := hostConfig["authenticationMethod"].(string)
	required, _ := hostConfig["authenticationRequired"].(string)
	username, _ := hostConfig["username"].(string)
	if !i.config.RotateCredentials &&
		strings.EqualFold(method, "forms") &&
		strings.EqualFold(required, "enabled") &&
		username == arrManagedAdminUsername {
		valid, err := verifyArrFormsCredential(
			ctx,
			control.URL,
			arrManagedAdminUsername,
			password,
			i.config.Timeout,
		)
		if err != nil {
			return "", fmt.Errorf("verify %s managed credential: %w", spec.name, err)
		}
		if valid {
			return "kept", nil
		}
	}

	hostConfig["authenticationMethod"] = "forms"
	hostConfig["authenticationRequired"] = "enabled"
	hostConfig["username"] = arrManagedAdminUsername
	hostConfig["password"] = password
	hostConfig["passwordConfirmation"] = password
	if _, err := i.httpClient.Put(ctx, hostConfigURL, headers, hostConfig); err != nil {
		return "", fmt.Errorf("update %s host authentication: %w", spec.name, err)
	}

	valid, err := verifyArrFormsCredential(
		ctx,
		control.URL,
		arrManagedAdminUsername,
		password,
		i.config.Timeout,
	)
	if err != nil {
		return "", fmt.Errorf("verify reconciled %s credential: %w", spec.name, err)
	}
	if !valid {
		return "", fmt.Errorf("%s rejected the reconciled managed credential", spec.name)
	}
	if i.config.RotateCredentials {
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
			hostConfig["password"] = previousPassword
			hostConfig["passwordConfirmation"] = previousPassword
			_, rollbackErr := i.httpClient.Put(
				ctx,
				hostConfigURL,
				headers,
				hostConfig,
			)
			if rollbackErr != nil {
				return "", errors.Join(
					fmt.Errorf("persist rotated %s credential: %w", spec.name, writeErr),
					fmt.Errorf("rollback %s credential: %w", spec.name, rollbackErr),
				)
			}
			return "", fmt.Errorf(
				"persist rotated %s credential; previous credential restored: %w",
				spec.name,
				writeErr,
			)
		}
		return "rotated", nil
	}
	return "reconciled", nil
}

// verifyArrFormsCredential performs the same bounded login flow a browser
// uses. Redirects may stay only on the verified service origin; a successful
// final response must not land back on /login.
func verifyArrFormsCredential(
	ctx context.Context,
	baseURL, username, password string,
	timeout time.Duration,
) (bool, error) {
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return false, fmt.Errorf("parse control URL: %w", err)
	}
	if parsedBase.Scheme != "http" || parsedBase.Host == "" {
		return false, fmt.Errorf("control URL must be an internal HTTP origin")
	}
	loginURL := strings.TrimRight(baseURL, "/") + "/login"
	jar, err := cookiejar.New(nil)
	if err != nil {
		return false, fmt.Errorf("create login cookie jar: %w", err)
	}
	client := &http.Client{
		Timeout: timeout,
		Jar:     jar,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many login redirects")
			}
			if request.URL.Scheme != parsedBase.Scheme ||
				request.URL.Host != parsedBase.Host {
				return fmt.Errorf("login redirected outside the verified service origin")
			}
			return nil
		},
	}
	form := url.Values{
		"username":   {username},
		"password":   {password},
		"rememberMe": {"true"},
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		loginURL,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return false, fmt.Errorf("create login request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10)); err != nil {
		return false, fmt.Errorf("drain login response: %w", err)
	}
	if response.StatusCode < http.StatusOK ||
		response.StatusCode >= http.StatusBadRequest {
		return false, nil
	}
	return !strings.HasSuffix(
		strings.TrimRight(response.Request.URL.Path, "/"),
		"/login",
	), nil
}
