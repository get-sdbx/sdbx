package integrate

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/securefs"
)

const plexPreferencesMaxSize = 1 << 20

type maintainerrClient struct {
	client *HTTPClient
	config *ServiceConfig
}

type maintainerrResult struct {
	Status  string `json:"status"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var errMaintainerrPortScopedQBTCookie = errors.New(
	"Maintainerr does not support qBittorrent port-scoped session cookies",
)

type maintainerrArrSetting struct {
	ID         int    `json:"id,omitempty"`
	ServerName string `json:"serverName"`
	URL        string `json:"url"`
	APIKey     string `json:"apiKey"`
}

type maintainerrDownloadSetting struct {
	URL           string  `json:"download_client_url"`
	Username      string  `json:"download_client_username"`
	Password      string  `json:"download_client_password"`
	DeleteData    bool    `json:"download_client_delete_data"`
	FallbackRatio float64 `json:"download_client_fallback_ratio"`
}

type maintainerrSeerrSetting struct {
	URL    string `json:"url"`
	APIKey string `json:"api_key"`
}

type maintainerrPublicSettings struct {
	MediaServerType string `json:"media_server_type"`
	PlexName        string `json:"plex_name"`
	PlexHostname    string `json:"plex_hostname"`
	PlexPort        int    `json:"plex_port"`
	PlexSSL         int    `json:"plex_ssl"`
}

func newMaintainerrClient(client *HTTPClient, cfg *ServiceConfig) *maintainerrClient {
	return &maintainerrClient{client: client, config: cfg}
}

func (m *maintainerrClient) endpoint(path string) string {
	return strings.TrimRight(m.config.URL, "/") + "/api/settings" + path
}

func (m *maintainerrClient) check(ctx context.Context) error {
	_, err := m.client.Get(ctx, m.endpoint("/version"), nil)
	return err
}

func (m *maintainerrClient) getJSON(ctx context.Context, path string, target any) error {
	body, err := m.client.Get(ctx, m.endpoint(path), nil)
	if err != nil {
		return err
	}
	defer wipeCredentialBytes(body)
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode Maintainerr response: %w", err)
	}
	return nil
}

func (m *maintainerrClient) resultOK(body []byte) error {
	defer wipeCredentialBytes(body)
	var result maintainerrResult
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("decode Maintainerr result: %w", err)
	}
	if !strings.EqualFold(result.Status, "OK") || result.Code != 1 {
		if strings.Contains(result.Message, "accepted the login but returned 403 Forbidden") &&
			strings.Contains(result.Message, "Bypass authentication") {
			return errMaintainerrPortScopedQBTCookie
		}
		return fmt.Errorf("Maintainerr rejected integration settings")
	}
	return nil
}

func (m *maintainerrClient) test(ctx context.Context, path string, settings any) error {
	body, err := m.client.Post(ctx, m.endpoint("/test/"+path), nil, settings)
	if err != nil {
		return err
	}
	return m.resultOK(body)
}

func (m *maintainerrClient) save(ctx context.Context, path string, id int, settings any) error {
	var body []byte
	var err error
	if id > 0 {
		body, err = m.client.Put(
			ctx,
			m.endpoint("/"+path+"/"+strconv.Itoa(id)),
			nil,
			settings,
		)
	} else {
		body, err = m.client.Post(ctx, m.endpoint("/"+path), nil, settings)
	}
	if err != nil {
		return err
	}
	return m.resultOK(body)
}

func (m *maintainerrClient) patch(ctx context.Context, settings any) error {
	body, err := m.client.Patch(ctx, m.endpoint(""), nil, settings)
	if err != nil {
		return err
	}
	return m.resultOK(body)
}

func ReadPlexToken(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("project config is required")
	}
	path := filepath.Join(
		cfg.ConfigPath,
		"plex",
		"Library",
		"Application Support",
		"Plex Media Server",
		"Preferences.xml",
	)
	body, err := securefs.ReadRegularFile(path, plexPreferencesMaxSize)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read Plex preferences: %w", err)
	}
	defer wipeCredentialBytes(body)
	decoder := xml.NewDecoder(bytes.NewReader(body))
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", fmt.Errorf("decode Plex preferences: %w", err)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		for _, attribute := range start.Attr {
			if attribute.Name.Local == "PlexOnlineToken" {
				return strings.TrimSpace(attribute.Value), nil
			}
		}
		return "", nil
	}
}

func maintainerrArrMatches(current, desired maintainerrArrSetting) bool {
	return strings.EqualFold(current.ServerName, desired.ServerName) &&
		strings.TrimRight(current.URL, "/") == strings.TrimRight(desired.URL, "/") &&
		current.APIKey == desired.APIKey
}

func (i *Integrator) integrateMaintainerr(ctx context.Context) []*IntegrationResult {
	client := newMaintainerrClient(
		i.httpClient,
		serviceControlConfig(i.services["maintainerr"]),
	)
	results := make([]*IntegrationResult, 0, 5)
	for _, kind := range []string{"radarr", "sonarr"} {
		service := i.services[kind]
		if service == nil || !service.Enabled {
			continue
		}
		result := &IntegrationResult{Service: "maintainerr → " + kind}
		desired := maintainerrArrSetting{
			ServerName: strings.ToUpper(kind[:1]) + kind[1:],
			URL:        service.URL,
			APIKey:     service.APIKey,
		}
		var current []maintainerrArrSetting
		if err := client.getJSON(ctx, "/"+kind, &current); err != nil {
			result.Message, result.Error = "Failed to read Arr connection", err
			results = append(results, result)
			continue
		}
		var managed *maintainerrArrSetting
		for index := range current {
			if strings.EqualFold(current[index].ServerName, desired.ServerName) {
				managed = &current[index]
				break
			}
		}
		if err := client.test(ctx, kind, desired); err != nil {
			result.Message, result.Error = "Managed connection failed preflight", err
			results = append(results, result)
			continue
		}
		if managed != nil && maintainerrArrMatches(*managed, desired) {
			result.Success, result.Message = true, "Already configured and verified"
			results = append(results, result)
			continue
		}
		if i.config.DryRun {
			result.Success, result.Message = true, "[DRY RUN] Would repair managed connection"
			results = append(results, result)
			continue
		}
		id := 0
		if managed != nil {
			id = managed.ID
		}
		if err := client.save(ctx, kind, id, desired); err != nil {
			result.Message, result.Error = "Failed to repair managed connection", err
			results = append(results, result)
			continue
		}
		if err := client.test(ctx, kind, desired); err != nil {
			result.Message, result.Error = "Repaired connection failed verification", err
			results = append(results, result)
			continue
		}
		result.Success, result.Message = true, "Repaired and verified"
		results = append(results, result)
	}

	results = append(results, i.integrateMaintainerrSeerr(ctx, client))
	results = append(results, i.integrateMaintainerrDownloadClient(ctx, client))
	results = append(results, i.integrateMaintainerrPlex(ctx, client))
	return results
}

func (i *Integrator) integrateMaintainerrSeerr(ctx context.Context, client *maintainerrClient) *IntegrationResult {
	result := &IntegrationResult{Service: "maintainerr → seerr"}
	service := i.services["seerr"]
	if service == nil || !service.Enabled {
		result.Success, result.Message = true, "Not applicable"
		return result
	}
	desired := maintainerrSeerrSetting{URL: service.URL, APIKey: service.APIKey}
	var current maintainerrSeerrSetting
	if err := client.getJSON(ctx, "/seerr", &current); err != nil {
		result.Message, result.Error = "Failed to read Seerr connection", err
		return result
	}
	if err := client.test(ctx, "seerr", desired); err != nil {
		result.Message, result.Error = "Managed connection failed preflight", err
		return result
	}
	if strings.TrimRight(current.URL, "/") == strings.TrimRight(desired.URL, "/") && current.APIKey == desired.APIKey {
		result.Success, result.Message = true, "Already configured and verified"
		return result
	}
	if i.config.DryRun {
		result.Success, result.Message = true, "[DRY RUN] Would repair managed connection"
		return result
	}
	if err := client.save(ctx, "seerr", 0, desired); err != nil {
		result.Message, result.Error = "Failed to repair managed connection", err
		return result
	}
	if err := client.test(ctx, "seerr", desired); err != nil {
		result.Message, result.Error = "Repaired connection failed verification", err
		return result
	}
	result.Success, result.Message = true, "Repaired and verified"
	return result
}

func (i *Integrator) integrateMaintainerrDownloadClient(ctx context.Context, client *maintainerrClient) *IntegrationResult {
	result := &IntegrationResult{Service: "maintainerr → qbittorrent"}
	service := i.services["qbittorrent"]
	if service == nil || !service.Enabled {
		result.Success, result.Message = true, "Not applicable"
		return result
	}
	var current maintainerrDownloadSetting
	if err := client.getJSON(ctx, "/download-client", &current); err != nil {
		result.Message, result.Error = "Failed to read download client", err
		return result
	}
	ratio := current.FallbackRatio
	if ratio < 0.5 {
		ratio = 0.5
	}
	desired := maintainerrDownloadSetting{
		URL:           service.URL,
		Username:      "admin",
		Password:      service.APIKey,
		DeleteData:    false,
		FallbackRatio: ratio,
	}
	if err := client.test(ctx, "download-client", desired); err != nil {
		if !errors.Is(err, errMaintainerrPortScopedQBTCookie) {
			result.Message, result.Error = "Managed connection failed preflight", err
			return result
		}
		const limitation = "qBittorrent cleanup unavailable because Maintainerr does not yet support port-scoped session cookies; data deletion remains disabled"
		if current == desired {
			result.Success, result.Message = true, limitation
			return result
		}
		if i.config.DryRun {
			result.Success = true
			result.Message = "[DRY RUN] Would store non-destructive settings; " + limitation
			return result
		}
		if err := client.save(ctx, "download-client", 0, desired); err != nil {
			result.Message, result.Error = "Failed to persist non-destructive download settings", err
			return result
		}
		result.Success, result.Message = true, "Stored non-destructive settings; "+limitation
		return result
	}
	if current == desired {
		result.Success, result.Message = true, "Already configured, verified, and data deletion disabled"
		return result
	}
	if i.config.DryRun {
		result.Success, result.Message = true, "[DRY RUN] Would repair connection and disable data deletion"
		return result
	}
	if err := client.save(ctx, "download-client", 0, desired); err != nil {
		result.Message, result.Error = "Failed to repair download client", err
		return result
	}
	if err := client.test(ctx, "download-client", desired); err != nil {
		result.Message, result.Error = "Repaired download client failed verification", err
		return result
	}
	result.Success, result.Message = true, "Repaired, verified, and data deletion disabled"
	return result
}

func (i *Integrator) integrateMaintainerrPlex(ctx context.Context, client *maintainerrClient) *IntegrationResult {
	result := &IntegrationResult{Service: "maintainerr → plex"}
	if !IsServiceEnabled(i.config.ProjectConfig, "plex") {
		result.Success, result.Message = true, "Not applicable"
		return result
	}
	token, err := ReadPlexToken(i.config.ProjectConfig)
	if err != nil || token == "" {
		result.Message = "Failed to read Plex application token"
		result.Error = err
		if err == nil {
			result.Error = fmt.Errorf("Plex application token is unavailable")
		}
		return result
	}
	var current maintainerrPublicSettings
	if err := client.getJSON(ctx, "", &current); err != nil {
		result.Message, result.Error = "Failed to read Plex connection", err
		return result
	}
	desired := map[string]any{
		"media_server_type": "plex",
		"plex_name":         "Plex",
		"plex_hostname":     "sdbx-plex",
		"plex_port":         32400,
		"plex_ssl":          0,
	}
	matches := current.MediaServerType == "plex" &&
		current.PlexHostname == "sdbx-plex" && current.PlexPort == 32400 &&
		current.PlexSSL == 0
	if matches {
		if err := client.getResult(ctx, "/test/plex"); err == nil {
			if err := client.getResult(ctx, "/test/plex/auth"); err == nil {
				result.Success, result.Message = true, "Already configured and verified"
				return result
			}
		}
	}
	if i.config.DryRun {
		result.Success, result.Message = true, "[DRY RUN] Would repair Plex connection"
		return result
	}
	body, err := client.client.Post(
		ctx,
		client.endpoint("/plex/token"),
		nil,
		map[string]string{"plex_auth_token": token},
	)
	if err != nil {
		result.Message, result.Error = "Failed to repair Plex token", err
		return result
	}
	if err := client.resultOK(body); err != nil {
		result.Message, result.Error = "Failed to repair Plex token", err
		return result
	}
	if err := client.patch(ctx, desired); err != nil {
		result.Message, result.Error = "Failed to repair Plex endpoint", err
		return result
	}
	if err := client.getResult(ctx, "/test/plex"); err != nil {
		result.Message, result.Error = "Repaired Plex connection failed verification", err
		return result
	}
	if err := client.getResult(ctx, "/test/plex/auth"); err != nil {
		result.Message, result.Error = "Repaired Plex token failed verification", err
		return result
	}
	result.Success, result.Message = true, "Repaired and verified"
	return result
}

func (m *maintainerrClient) getResult(ctx context.Context, path string) error {
	body, err := m.client.Get(ctx, m.endpoint(path), nil)
	if err != nil {
		return err
	}
	return m.resultOK(body)
}
