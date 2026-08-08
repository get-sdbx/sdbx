package integrate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/securefs"
	"gopkg.in/yaml.v3"
)

const bazarrSettingsMaxSize = 1 << 20

func ReadBazarrAPIKey(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("project config is required")
	}
	path := filepath.Join(cfg.ConfigPath, "bazarr", "config", "config.yaml")
	body, err := securefs.ReadRegularFile(path, bazarrSettingsMaxSize)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read Bazarr settings: %w", err)
	}
	defer wipeCredentialBytes(body)
	var settings struct {
		Auth struct {
			APIKey string `yaml:"apikey"`
		} `yaml:"auth"`
	}
	if err := yaml.Unmarshal(body, &settings); err != nil {
		return "", fmt.Errorf("decode Bazarr settings: %w", err)
	}
	return strings.TrimSpace(settings.Auth.APIKey), nil
}

type BazarrClient struct {
	client *HTTPClient
	config *ServiceConfig
}

type bazarrArrSettings struct {
	APIKey  string `json:"apikey"`
	BaseURL string `json:"base_url"`
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	SSL     bool   `json:"ssl"`
}

type bazarrSettings struct {
	General struct {
		UseSonarr bool `json:"use_sonarr"`
		UseRadarr bool `json:"use_radarr"`
	} `json:"general"`
	Sonarr bazarrArrSettings `json:"sonarr"`
	Radarr bazarrArrSettings `json:"radarr"`
}

func NewBazarrClient(client *HTTPClient, cfg *ServiceConfig) *BazarrClient {
	return &BazarrClient{client: client, config: cfg}
}

func (b *BazarrClient) headers() map[string]string {
	return map[string]string{"X-Api-Key": b.config.APIKey}
}

func (b *BazarrClient) GetSettings(ctx context.Context) (*bazarrSettings, error) {
	body, err := b.client.Get(
		ctx,
		strings.TrimRight(b.config.URL, "/")+"/api/system/settings",
		b.headers(),
	)
	if err != nil {
		return nil, fmt.Errorf("get Bazarr settings: %w", err)
	}
	defer wipeCredentialBytes(body)
	var settings bazarrSettings
	if err := json.Unmarshal(body, &settings); err != nil {
		return nil, fmt.Errorf("decode Bazarr settings: %w", err)
	}
	return &settings, nil
}

func (b *BazarrClient) UpdateArrSettings(
	ctx context.Context,
	desired map[string]*ServiceConfig,
) error {
	values := make(url.Values)
	for _, kind := range []string{"sonarr", "radarr"} {
		service := desired[kind]
		if service == nil || !service.Enabled {
			continue
		}
		parsed, err := url.Parse(service.URL)
		if err != nil || parsed.Hostname() == "" {
			return fmt.Errorf("parse %s stable integration URL", kind)
		}
		port, err := strconv.Atoi(parsed.Port())
		if err != nil {
			return fmt.Errorf("parse %s stable integration port: %w", kind, err)
		}
		values.Set("settings-general-use_"+kind, "true")
		values.Set("settings-"+kind+"-ip", parsed.Hostname())
		values.Set("settings-"+kind+"-port", strconv.Itoa(port))
		values.Set("settings-"+kind+"-base_url", parsed.EscapedPath())
		values.Set("settings-"+kind+"-ssl", "false")
		values.Set("settings-"+kind+"-apikey", service.APIKey)
	}
	if _, err := b.client.PostForm(
		ctx,
		strings.TrimRight(b.config.URL, "/")+"/api/system/settings",
		b.headers(),
		values,
	); err != nil {
		return fmt.Errorf("update Bazarr Arr settings: %w", err)
	}
	return nil
}

func bazarrArrSettingsMatch(
	current *bazarrSettings,
	desired map[string]*ServiceConfig,
) bool {
	for _, kind := range []string{"sonarr", "radarr"} {
		service := desired[kind]
		if service == nil || !service.Enabled {
			continue
		}
		parsed, err := url.Parse(service.URL)
		if err != nil {
			return false
		}
		port, err := strconv.Atoi(parsed.Port())
		if err != nil {
			return false
		}
		var enabled bool
		var settings bazarrArrSettings
		if kind == "sonarr" {
			enabled, settings = current.General.UseSonarr, current.Sonarr
		} else {
			enabled, settings = current.General.UseRadarr, current.Radarr
		}
		if !enabled || settings.IP != parsed.Hostname() ||
			settings.Port != port || settings.SSL ||
			settings.BaseURL != parsed.EscapedPath() ||
			settings.APIKey != service.APIKey {
			return false
		}
	}
	return true
}

func (i *Integrator) integrateBazarr(ctx context.Context) *IntegrationResult {
	result := &IntegrationResult{Service: "bazarr → sonarr/radarr"}
	client := NewBazarrClient(i.httpClient, serviceControlConfig(i.services["bazarr"]))
	current, err := client.GetSettings(ctx)
	if err != nil {
		result.Message = "Failed to read Arr connections"
		result.Error = err
		return result
	}
	if bazarrArrSettingsMatch(current, i.services) {
		result.Success = true
		result.Message = "Already configured and verified"
		return result
	}
	if i.config.DryRun {
		result.Success = true
		result.Message = "[DRY RUN] Would repair Arr connections"
		return result
	}
	if err := client.UpdateArrSettings(ctx, i.services); err != nil {
		result.Message = "Failed to repair Arr connections"
		result.Error = err
		return result
	}
	current, err = client.GetSettings(ctx)
	if err != nil || !bazarrArrSettingsMatch(current, i.services) {
		result.Message = "Repaired Arr connections failed read-back verification"
		if err != nil {
			result.Error = err
		} else {
			result.Error = fmt.Errorf("Bazarr Arr settings read-back mismatch")
		}
		return result
	}
	result.Success = true
	result.Message = "Repaired and verified"
	return result
}
