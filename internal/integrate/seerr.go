package integrate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/securefs"
)

const seerrSettingsMaxSize = 1 << 20

// ReadSeerrAPIKey reads only Seerr's own API credential from its app-owned
// settings file. The rest of the secret-bearing document is never returned.
func ReadSeerrAPIKey(cfg *config.Config) (string, error) {
	path := filepath.Join(cfg.ConfigPath, "seerr", "settings.json")
	body, err := securefs.ReadRegularFile(path, seerrSettingsMaxSize)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read Seerr settings: %w", err)
	}
	defer wipeCredentialBytes(body)
	var settings struct {
		Main struct {
			APIKey string `json:"apiKey"`
		} `json:"main"`
	}
	if err := json.Unmarshal(body, &settings); err != nil {
		return "", fmt.Errorf("decode Seerr settings: %w", err)
	}
	return strings.TrimSpace(settings.Main.APIKey), nil
}

type SeerrClient struct {
	client *HTTPClient
	config *ServiceConfig
}

func NewSeerrClient(client *HTTPClient, cfg *ServiceConfig) *SeerrClient {
	return &SeerrClient{client: client, config: cfg}
}

func (s *SeerrClient) headers() map[string]string {
	return map[string]string{"X-Api-Key": s.config.APIKey}
}

func (s *SeerrClient) CheckHealth(ctx context.Context) error {
	if _, err := s.client.Get(
		ctx,
		strings.TrimRight(s.config.URL, "/")+"/api/v1/status",
		s.headers(),
	); err != nil {
		return fmt.Errorf("Seerr health check failed: %w", err)
	}
	return nil
}

func (s *SeerrClient) GetServices(
	ctx context.Context,
	kind string,
) ([]map[string]any, error) {
	if kind != "radarr" && kind != "sonarr" {
		return nil, fmt.Errorf("unsupported Seerr service %q", kind)
	}
	body, err := s.client.Get(
		ctx,
		strings.TrimRight(s.config.URL, "/")+"/api/v1/settings/"+kind,
		s.headers(),
	)
	if err != nil {
		return nil, fmt.Errorf("get Seerr %s settings: %w", kind, err)
	}
	defer wipeCredentialBytes(body)
	var settings []map[string]any
	if err := json.Unmarshal(body, &settings); err != nil {
		return nil, fmt.Errorf("decode Seerr %s settings: %w", kind, err)
	}
	return settings, nil
}

func (s *SeerrClient) TestService(
	ctx context.Context,
	kind string,
	settings map[string]any,
) (map[string]any, error) {
	body, err := s.client.Post(
		ctx,
		strings.TrimRight(s.config.URL, "/")+"/api/v1/settings/"+kind+"/test",
		s.headers(),
		settings,
	)
	if err != nil {
		return nil, fmt.Errorf("test Seerr %s settings: %w", kind, err)
	}
	defer wipeCredentialBytes(body)
	var result map[string]any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("decode Seerr %s test response: %w", kind, err)
		}
	}
	return result, nil
}

func (s *SeerrClient) UpdateService(
	ctx context.Context,
	kind string,
	id int,
	settings map[string]any,
) (map[string]any, error) {
	endpoint := fmt.Sprintf(
		"%s/api/v1/settings/%s/%d",
		strings.TrimRight(s.config.URL, "/"),
		kind,
		id,
	)
	body, err := s.client.Put(ctx, endpoint, s.headers(), settings)
	if err != nil {
		return nil, fmt.Errorf("update Seerr %s settings: %w", kind, err)
	}
	defer wipeCredentialBytes(body)
	var updated map[string]any
	if err := json.Unmarshal(body, &updated); err != nil {
		return nil, fmt.Errorf("decode updated Seerr %s settings: %w", kind, err)
	}
	return updated, nil
}

func (s *SeerrClient) AddService(
	ctx context.Context,
	kind string,
	settings map[string]any,
) error {
	endpoint := strings.TrimRight(s.config.URL, "/") + "/api/v1/settings/" + kind
	if _, err := s.client.Post(ctx, endpoint, s.headers(), settings); err != nil {
		return fmt.Errorf("add Seerr %s settings: %w", kind, err)
	}
	return nil
}

func (s *SeerrClient) DeleteService(
	ctx context.Context,
	kind string,
	id int,
) error {
	endpoint := fmt.Sprintf(
		"%s/api/v1/settings/%s/%d",
		strings.TrimRight(s.config.URL, "/"),
		kind,
		id,
	)
	if _, err := s.client.Delete(ctx, endpoint, s.headers()); err != nil {
		return fmt.Errorf("delete Seerr %s settings: %w", kind, err)
	}
	return nil
}

func (s *SeerrClient) GetPlexSettings(ctx context.Context) (map[string]any, error) {
	body, err := s.client.Get(
		ctx,
		strings.TrimRight(s.config.URL, "/")+"/api/v1/settings/plex",
		s.headers(),
	)
	if err != nil {
		return nil, fmt.Errorf("get Seerr Plex settings: %w", err)
	}
	defer wipeCredentialBytes(body)
	var settings map[string]any
	if err := json.Unmarshal(body, &settings); err != nil {
		return nil, fmt.Errorf("decode Seerr Plex settings: %w", err)
	}
	return settings, nil
}

func (s *SeerrClient) UpdatePlexSettings(
	ctx context.Context,
	settings map[string]any,
) (map[string]any, error) {
	body, err := s.client.Post(
		ctx,
		strings.TrimRight(s.config.URL, "/")+"/api/v1/settings/plex",
		s.headers(),
		settings,
	)
	if err != nil {
		return nil, fmt.Errorf("update Seerr Plex settings: %w", err)
	}
	defer wipeCredentialBytes(body)
	var updated map[string]any
	if err := json.Unmarshal(body, &updated); err != nil {
		return nil, fmt.Errorf("decode updated Seerr Plex settings: %w", err)
	}
	return updated, nil
}

func seerrDesiredConnection(
	kind string,
	service *ServiceConfig,
) (map[string]any, error) {
	parsed, err := url.Parse(service.URL)
	if err != nil || parsed.Hostname() == "" {
		return nil, fmt.Errorf("parse %s stable integration URL", kind)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		return nil, fmt.Errorf("parse %s stable integration port: %w", kind, err)
	}
	return map[string]any{
		"name":     strings.ToUpper(kind[:1]) + kind[1:],
		"hostname": parsed.Hostname(),
		"port":     port,
		"apiKey":   service.APIKey,
		"useSsl":   false,
		"baseUrl":  parsed.EscapedPath(),
	}, nil
}

func seerrConnectionMatches(existing, desired map[string]any) bool {
	for _, name := range []string{"hostname", "port", "useSsl", "baseUrl"} {
		if fmt.Sprint(existing[name]) != fmt.Sprint(desired[name]) {
			return false
		}
	}
	// Seerr returns the configured Arr API key in current releases. Compare it
	// whenever present so a healthy preflight using the desired key cannot mask
	// a stale credential still persisted in Seerr.
	if current := strings.TrimSpace(fmt.Sprint(existing["apiKey"])); current != "" && current != "<nil>" && current != fmt.Sprint(desired["apiKey"]) {
		return false
	}
	return true
}

func seerrDesiredPlexConnection(service *ServiceConfig) (map[string]any, error) {
	parsed, err := url.Parse(service.URL)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("parse Plex stable integration URL")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		return nil, fmt.Errorf("parse Plex stable integration port: %w", err)
	}
	return map[string]any{
		"ip":     parsed.Hostname(),
		"port":   port,
		"useSsl": false,
	}, nil
}

func seerrPlexConnectionMatches(existing, desired map[string]any) bool {
	for _, name := range []string{"ip", "port", "useSsl"} {
		if fmt.Sprint(existing[name]) != fmt.Sprint(desired[name]) {
			return false
		}
	}
	return true
}

func mergeSeerrSettings(existing, desired map[string]any) map[string]any {
	merged := make(map[string]any, len(existing)+len(desired))
	for name, value := range existing {
		merged[name] = value
	}
	for name, value := range desired {
		merged[name] = value
	}
	return merged
}

// seerrWritableServiceSettings removes response-only fields before a complete
// Arr instance replacement. Seerr's OpenAPI middleware rejects its read-only
// id property on PUT even though GET includes it in the returned object.
func seerrWritableServiceSettings(settings map[string]any) map[string]any {
	writable := mergeSeerrSettings(settings, nil)
	delete(writable, "id")
	return writable
}

func seerrPlexOperatorSettingsPreserved(before, after map[string]any) bool {
	for name, value := range before {
		switch name {
		case "ip", "port", "useSsl", "name", "machineId":
			continue
		}
		if !reflect.DeepEqual(after[name], value) {
			return false
		}
	}
	return true
}

func seerrSettingsID(settings map[string]any) int {
	switch value := settings["id"].(type) {
	case float64:
		return int(value)
	case int:
		return value
	default:
		return -1
	}
}

func seerrNewServiceSettings(
	kind string,
	desired map[string]any,
	discovery map[string]any,
) (map[string]any, error) {
	profile, err := firstSeerrObject(discovery, "profiles")
	if err != nil {
		return nil, fmt.Errorf("select %s quality profile: %w", kind, err)
	}
	profileID, ok := numericID(profile["id"])
	if !ok || strings.TrimSpace(fmt.Sprint(profile["name"])) == "" {
		return nil, fmt.Errorf("select %s quality profile: invalid profile response", kind)
	}
	wantedRoot := map[string]string{
		"radarr": "/movies",
		"sonarr": "/tv",
	}[kind]
	rootFolders, ok := discovery["rootFolders"].([]any)
	if !ok {
		return nil, fmt.Errorf("select %s root folder: invalid discovery response", kind)
	}
	rootFound := false
	for _, raw := range rootFolders {
		folder, ok := raw.(map[string]any)
		if ok && strings.TrimRight(fmt.Sprint(folder["path"]), "/") == wantedRoot {
			rootFound = true
			break
		}
	}
	if !rootFound {
		return nil, fmt.Errorf("select %s root folder: required %s root is unavailable", kind, wantedRoot)
	}

	settings := mergeSeerrSettings(nil, desired)
	settings["activeProfileId"] = profileID
	settings["activeProfileName"] = fmt.Sprint(profile["name"])
	settings["activeDirectory"] = wantedRoot
	settings["is4k"] = false
	settings["isDefault"] = true
	settings["syncEnabled"] = true
	settings["preventSearch"] = false
	switch kind {
	case "radarr":
		settings["minimumAvailability"] = "released"
	case "sonarr":
		settings["enableSeasonFolders"] = true
	default:
		return nil, fmt.Errorf("unsupported Seerr service %q", kind)
	}
	return settings, nil
}

func firstSeerrObject(document map[string]any, name string) (map[string]any, error) {
	values, ok := document[name].([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("%s list is empty", name)
	}
	value, ok := values[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s entry has an invalid shape", name)
	}
	return value, nil
}

func numericID(value any) (int, bool) {
	switch typed := value.(type) {
	case float64:
		return int(typed), typed == float64(int(typed))
	case int:
		return typed, true
	default:
		return 0, false
	}
}
