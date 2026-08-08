package integrate

import (
	"context"
	"encoding/json"
	"fmt"
)

// ArrClient handles supported *arr app API interactions.
type ArrClient struct {
	client *HTTPClient
	config *ServiceConfig
}

// NewArrClient creates a new *arr app API client
func NewArrClient(httpClient *HTTPClient, config *ServiceConfig) *ArrClient {
	return &ArrClient{
		client: httpClient,
		config: config,
	}
}

// arrAPIVersion returns the API version path segment for the given *arr.
// Sonarr/Radarr/Whisparr/Prowlarr/Bazarr use v3; Lidarr v1.x ships only
// /api/v1. Defaulting to v3 keeps the common callers unchanged while routing
// Lidarr to its actual endpoint.
func arrAPIVersion(name string) string {
	switch name {
	case "lidarr":
		return "v1"
	default:
		return "v3"
	}
}

func (a *ArrClient) version() string { return arrAPIVersion(a.config.Name) }

// CheckHealth verifies *arr app is accessible
func (a *ArrClient) CheckHealth(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/%s/system/status", a.config.URL, a.version())
	headers := map[string]string{
		"X-Api-Key": a.config.APIKey,
	}

	_, err := a.client.Get(ctx, url, headers)
	if err != nil {
		return fmt.Errorf("%s health check failed: %w", a.config.Name, err)
	}

	return nil
}

// GetDownloadClients retrieves all configured download clients
func (a *ArrClient) GetDownloadClients(ctx context.Context) ([]DownloadClient, error) {
	url := fmt.Sprintf("%s/api/%s/downloadclient", a.config.URL, a.version())
	headers := map[string]string{
		"X-Api-Key": a.config.APIKey,
	}

	body, err := a.client.Get(ctx, url, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to get download clients: %w", err)
	}

	var clients []DownloadClient
	if err := json.Unmarshal(body, &clients); err != nil {
		return nil, fmt.Errorf("failed to parse download clients: %w", err)
	}

	return clients, nil
}

// AddDownloadClient adds a new download client
func (a *ArrClient) AddDownloadClient(ctx context.Context, client *DownloadClient) (*DownloadClient, error) {
	url := fmt.Sprintf("%s/api/%s/downloadclient", a.config.URL, a.version())
	headers := map[string]string{
		"X-Api-Key": a.config.APIKey,
	}

	body, err := a.client.Post(ctx, url, headers, client)
	if err != nil {
		return nil, fmt.Errorf("failed to add download client: %w", err)
	}

	var result DownloadClient
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse download client response: %w", err)
	}

	return &result, nil
}

// UpdateDownloadClient updates an existing download client
func (a *ArrClient) UpdateDownloadClient(ctx context.Context, client *DownloadClient) error {
	url := fmt.Sprintf("%s/api/%s/downloadclient/%d", a.config.URL, a.version(), client.ID)
	headers := map[string]string{
		"X-Api-Key": a.config.APIKey,
	}

	_, err := a.client.Put(ctx, url, headers, client)
	if err != nil {
		return fmt.Errorf("failed to update download client: %w", err)
	}

	return nil
}

// TestDownloadClient validates a download-client configuration without
// persisting it. This catches masked-password drift that cannot be detected by
// comparing the GET response with the SDBX-managed secret.
func (a *ArrClient) TestDownloadClient(
	ctx context.Context,
	client *DownloadClient,
) error {
	url := fmt.Sprintf("%s/api/%s/downloadclient/test", a.config.URL, a.version())
	headers := map[string]string{
		"X-Api-Key": a.config.APIKey,
	}
	if _, err := a.client.Post(ctx, url, headers, client); err != nil {
		return fmt.Errorf("download client connection test failed: %w", err)
	}
	return nil
}

// CreateQBittorrentClient creates a qBittorrent download client config
func CreateQBittorrentClient(name, host string, port int, username, password string) *DownloadClient {
	return &DownloadClient{
		Name:                     name,
		Implementation:           "QBittorrent",
		ConfigContract:           "QBittorrentSettings",
		Protocol:                 "torrent",
		Priority:                 1,
		Enable:                   true,
		RemoveCompletedDownloads: true,
		RemoveFailedDownloads:    true,
		Tags:                     []int{},
		Fields: []DownloadClientField{
			{Name: "host", Value: host},
			{Name: "port", Value: port},
			{Name: "useSsl", Value: false},
			{Name: "urlBase", Value: ""},
			{Name: "username", Value: username},
			{Name: "password", Value: password},
			{Name: "recentTvPriority", Value: 0},
			{Name: "olderTvPriority", Value: 0},
			{Name: "initialState", Value: 0},
			{Name: "sequentialOrder", Value: false},
			{Name: "firstAndLast", Value: false},
		},
	}
}

// CreateSABnzbdClient creates a SABnzbd download client config
func CreateSABnzbdClient(name, host string, port int, apiKey string) *DownloadClient {
	return &DownloadClient{
		Name:           name,
		Implementation: "Sabnzbd",
		ConfigContract: "SabnzbdSettings",
		Protocol:       "usenet",
		Priority:       1,
		Enable:         true,
		Fields: []DownloadClientField{
			{Name: "host", Value: host},
			{Name: "port", Value: port},
			{Name: "apiKey", Value: apiKey},
			{Name: "category", Value: name},
			{Name: "recentTvPriority", Value: 0},
			{Name: "olderTvPriority", Value: 0},
		},
	}
}
