package integrate

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ProwlarrClient handles Prowlarr API interactions
type ProwlarrClient struct {
	client *HTTPClient
	config *ServiceConfig
}

// NewProwlarrClient creates a new Prowlarr API client
func NewProwlarrClient(httpClient *HTTPClient, config *ServiceConfig) *ProwlarrClient {
	return &ProwlarrClient{
		client: httpClient,
		config: config,
	}
}

// CheckHealth verifies Prowlarr is accessible
func (p *ProwlarrClient) CheckHealth(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/v1/system/status", p.config.URL)
	headers := map[string]string{
		"X-Api-Key": p.config.APIKey,
	}

	_, err := p.client.Get(ctx, url, headers)
	if err != nil {
		return fmt.Errorf("prowlarr health check failed: %w", err)
	}

	return nil
}

// GetApplications retrieves all configured applications
func (p *ProwlarrClient) GetApplications(ctx context.Context) ([]ProwlarrApplication, error) {
	url := fmt.Sprintf("%s/api/v1/applications", p.config.URL)
	headers := map[string]string{
		"X-Api-Key": p.config.APIKey,
	}

	body, err := p.client.Get(ctx, url, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to get applications: %w", err)
	}
	defer wipeCredentialBytes(body)

	var apps []ProwlarrApplication
	if err := json.Unmarshal(body, &apps); err != nil {
		return nil, fmt.Errorf("failed to parse applications: %w", err)
	}

	return apps, nil
}

// AddApplication adds a new *arr application to Prowlarr
func (p *ProwlarrClient) AddApplication(ctx context.Context, app *ProwlarrApplication) (*ProwlarrApplication, error) {
	url := fmt.Sprintf("%s/api/v1/applications", p.config.URL)
	headers := map[string]string{
		"X-Api-Key": p.config.APIKey,
	}

	body, err := p.client.Post(ctx, url, headers, app)
	if err != nil {
		return nil, fmt.Errorf("failed to add application: %w", err)
	}
	defer wipeCredentialBytes(body)

	var result ProwlarrApplication
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse application response: %w", err)
	}

	return &result, nil
}

func (p *ProwlarrClient) GetIndexerProxies(
	ctx context.Context,
) ([]map[string]any, error) {
	body, err := p.client.Get(
		ctx,
		strings.TrimRight(p.config.URL, "/")+"/api/v1/indexerProxy",
		map[string]string{"X-Api-Key": p.config.APIKey},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get indexer proxies: %w", err)
	}
	defer wipeCredentialBytes(body)
	var proxies []map[string]any
	if err := json.Unmarshal(body, &proxies); err != nil {
		return nil, fmt.Errorf("failed to parse indexer proxies: %w", err)
	}
	return proxies, nil
}

func (p *ProwlarrClient) TestIndexerProxy(
	ctx context.Context,
	proxy map[string]any,
) error {
	body, err := p.client.Post(
		ctx,
		strings.TrimRight(p.config.URL, "/")+"/api/v1/indexerProxy/test",
		map[string]string{"X-Api-Key": p.config.APIKey},
		proxy,
	)
	wipeCredentialBytes(body)
	if err != nil {
		return fmt.Errorf("indexer proxy connection test failed: %w", err)
	}
	return nil
}

func (p *ProwlarrClient) SaveIndexerProxy(
	ctx context.Context,
	id int,
	proxy map[string]any,
) error {
	endpoint := strings.TrimRight(p.config.URL, "/") + "/api/v1/indexerProxy"
	var body []byte
	var err error
	if id > 0 {
		body, err = p.client.Put(
			ctx,
			fmt.Sprintf("%s/%d", endpoint, id),
			map[string]string{"X-Api-Key": p.config.APIKey},
			proxy,
		)
	} else {
		body, err = p.client.Post(
			ctx,
			endpoint,
			map[string]string{"X-Api-Key": p.config.APIKey},
			proxy,
		)
	}
	wipeCredentialBytes(body)
	if err != nil {
		return fmt.Errorf("save indexer proxy: %w", err)
	}
	return nil
}

// UpdateApplication updates an existing *arr application
func (p *ProwlarrClient) UpdateApplication(ctx context.Context, app *ProwlarrApplication) error {
	url := fmt.Sprintf("%s/api/v1/applications/%d", p.config.URL, app.ID)
	headers := map[string]string{
		"X-Api-Key": p.config.APIKey,
	}

	_, err := p.client.Put(ctx, url, headers, app)
	if err != nil {
		return fmt.Errorf("failed to update application: %w", err)
	}

	return nil
}

// TestApplication asks Prowlarr to validate an application configuration
// without persisting it. A display-name match alone cannot prove that the
// target URL and API credential are still usable.
func (p *ProwlarrClient) TestApplication(
	ctx context.Context,
	app *ProwlarrApplication,
) error {
	url := fmt.Sprintf("%s/api/v1/applications/test", p.config.URL)
	headers := map[string]string{
		"X-Api-Key": p.config.APIKey,
	}
	if _, err := p.client.Post(ctx, url, headers, app); err != nil {
		return fmt.Errorf("application connection test failed: %w", err)
	}
	return nil
}

// CreateSonarrApplication creates a Sonarr application config
func CreateSonarrApplication(name, prowlarrURL, baseURL, apiKey string, syncLevel string) *ProwlarrApplication {
	return &ProwlarrApplication{
		Name:           name,
		Enable:         true,
		SyncLevel:      syncLevel,
		Implementation: "Sonarr",
		ConfigContract: "SonarrSettings",
		Tags:           []int{},
		Fields: []ProwlarrField{
			{Name: "prowlarrUrl", Value: prowlarrURL},
			{Name: "baseUrl", Value: baseURL},
			{Name: "apiKey", Value: apiKey},
			{Name: "syncCategories", Value: []int{5000, 5030, 5040}}, // TV categories
		},
	}
}

// CreateRadarrApplication creates a Radarr application config
func CreateRadarrApplication(name, prowlarrURL, baseURL, apiKey string, syncLevel string) *ProwlarrApplication {
	return &ProwlarrApplication{
		Name:           name,
		Enable:         true,
		SyncLevel:      syncLevel,
		Implementation: "Radarr",
		ConfigContract: "RadarrSettings",
		Tags:           []int{},
		Fields: []ProwlarrField{
			{Name: "prowlarrUrl", Value: prowlarrURL},
			{Name: "baseUrl", Value: baseURL},
			{Name: "apiKey", Value: apiKey},
			{Name: "syncCategories", Value: []int{2000, 2010, 2020, 2030, 2040, 2045, 2050, 2060}}, // Movie categories
		},
	}
}

// CreateLidarrApplication creates a Lidarr application config
func CreateLidarrApplication(name, prowlarrURL, baseURL, apiKey string, syncLevel string) *ProwlarrApplication {
	return &ProwlarrApplication{
		Name:           name,
		Enable:         true,
		SyncLevel:      syncLevel,
		Implementation: "Lidarr",
		ConfigContract: "LidarrSettings",
		Tags:           []int{},
		Fields: []ProwlarrField{
			{Name: "prowlarrUrl", Value: prowlarrURL},
			{Name: "baseUrl", Value: baseURL},
			{Name: "apiKey", Value: apiKey},
			{Name: "syncCategories", Value: []int{3000, 3010, 3020, 3030, 3040}}, // Music categories
		},
	}
}

// CreateWhisparrApplication creates a Whisparr v3 application config using
// Prowlarr's upstream Whisparr contract and adult Newznab categories.
func CreateWhisparrApplication(
	name, prowlarrURL, baseURL, apiKey, syncLevel string,
) *ProwlarrApplication {
	return &ProwlarrApplication{
		Name:           name,
		Enable:         true,
		SyncLevel:      syncLevel,
		Implementation: "Whisparr",
		ConfigContract: "WhisparrSettings",
		Tags:           []int{},
		Fields: []ProwlarrField{
			{Name: "prowlarrUrl", Value: prowlarrURL},
			{Name: "baseUrl", Value: baseURL},
			{Name: "apiKey", Value: apiKey},
			{
				Name: "syncCategories",
				Value: []int{
					6000,
					6010,
					6020,
					6030,
					6040,
					6045,
					6050,
					6070,
					6080,
					6090,
				},
			},
		},
	}
}
