package integrate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// qbtBaseURL returns the qBittorrent WebUI base URL ("http://host:port"),
// tolerant of host strings that already include a port. The pre-existing
// QBittorrentConfig design separates Host + Port, but newer callers (and
// the auto-fork path) populate Host with a full URL. Without this helper
// we'd emit broken URLs like "http://sdbx-gluetun:8080:8080/...".
func qbtBaseURL(cfg *QBittorrentConfig) string {
	host := cfg.Host
	// Strip a trailing slash if any caller adds one.
	host = strings.TrimRight(host, "/")
	// Already has a port (host[host.LastIndex(":")+1:] is digits)?
	if hasExplicitPort(host) {
		return host
	}
	return fmt.Sprintf("%s:%d", host, cfg.Port)
}

// qbtDownloadClientEndpoint returns the host and port fields expected by
// Sonarr-compatible download-client APIs. Internal callers may provide Host
// as a complete URL, but the *arr schema requires the hostname and port in
// separate fields.
func qbtDownloadClientEndpoint(cfg *QBittorrentConfig) (string, int) {
	raw := strings.TrimSpace(cfg.Host)
	candidate := raw
	if !strings.Contains(candidate, "://") {
		candidate = "http://" + candidate
	}
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Hostname() == "" {
		return strings.TrimPrefix(strings.TrimPrefix(raw, "http://"), "https://"), cfg.Port
	}

	port := cfg.Port
	if explicit := parsed.Port(); explicit != "" {
		if parsedPort, parseErr := strconv.Atoi(explicit); parseErr == nil {
			port = parsedPort
		}
	}
	return parsed.Hostname(), port
}

// hasExplicitPort reports whether url ends with ":<digits>" (treating any
// "://" before the host as a scheme separator).
func hasExplicitPort(u string) bool {
	// Cut the scheme.
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	// Path or query starts → no port we care about (qBT's WebUI is rooted).
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	idx := strings.LastIndex(u, ":")
	if idx == -1 || idx == len(u)-1 {
		return false
	}
	for _, r := range u[idx+1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// QBittorrentClient handles qBittorrent API interactions
type QBittorrentClient struct {
	client        *HTTPClient
	config        *QBittorrentConfig
	sessionCookie string
}

// NewQBittorrentClient creates a new qBittorrent API client
func NewQBittorrentClient(httpClient *HTTPClient, config *QBittorrentConfig) *QBittorrentClient {
	// qBittorrent authentication is carried explicitly in the session cookie
	// returned by Login. Do not share the generic integration cookie jar: a
	// valid cookie left by an earlier health probe can cause /auth/login to
	// return success without issuing a new cookie, which would falsely verify
	// the supplied managed credential and leave this client unauthenticated.
	isolatedHTTPClient := *httpClient
	isolatedClient := *httpClient.client
	isolatedClient.Jar = nil
	isolatedHTTPClient.client = &isolatedClient
	return &QBittorrentClient{
		client: &isolatedHTTPClient,
		config: config,
	}
}

// Login authenticates with qBittorrent
func (q *QBittorrentClient) Login(ctx context.Context) error {
	loginURL := fmt.Sprintf("%s/api/v2/auth/login", qbtBaseURL(q.config))

	// Create form data
	form := url.Values{}
	form.Set("username", q.config.Username)
	form.Set("password", q.config.Password)
	encoded := []byte(form.Encode())
	form.Del("password")
	defer wipeCredentialBytes(encoded)

	req, err := http.NewRequestWithContext(ctx, "POST", loginURL, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := q.client.client.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("login failed with status %d", resp.StatusCode)
	}

	// qBittorrent 5.x uses a port-scoped QBT_SID_<port> cookie while older
	// releases use SID. Preserve the validated name because subsequent API
	// calls must send the exact cookie returned by the server.
	for _, cookie := range resp.Cookies() {
		if isQBittorrentSessionCookie(cookie.Name) {
			q.sessionCookie = cookie.Name + "=" + cookie.Value
			return nil
		}
	}

	return fmt.Errorf("no session cookie received")
}

func isQBittorrentSessionCookie(name string) bool {
	if name == "SID" {
		return true
	}
	const prefix = "QBT_SID_"
	port := strings.TrimPrefix(name, prefix)
	if port == name || port == "" {
		return false
	}
	for _, character := range port {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// CheckHealth verifies qBittorrent is accessible
func (q *QBittorrentClient) CheckHealth(ctx context.Context) error {
	apiURL := fmt.Sprintf("%s/api/v2/app/version", qbtBaseURL(q.config))
	headers := map[string]string{}

	if q.sessionCookie != "" {
		headers["Cookie"] = q.sessionCookie
	}

	_, err := q.client.Get(ctx, apiURL, headers)
	if err != nil {
		return fmt.Errorf("qbittorrent health check failed: %w", err)
	}

	return nil
}

// GetPreferences retrieves qBittorrent preferences
func (q *QBittorrentClient) GetPreferences(ctx context.Context) (map[string]interface{}, error) {
	apiURL := fmt.Sprintf("%s/api/v2/app/preferences", qbtBaseURL(q.config))
	headers := map[string]string{
		"Cookie": q.sessionCookie,
	}

	body, err := q.client.Get(ctx, apiURL, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to get preferences: %w", err)
	}
	defer wipeCredentialBytes(body)

	var prefs map[string]interface{}
	if err := json.Unmarshal(body, &prefs); err != nil {
		return nil, fmt.Errorf("failed to parse preferences: %w", err)
	}

	return prefs, nil
}

// SetPreferences sets qBittorrent preferences
func (q *QBittorrentClient) SetPreferences(ctx context.Context, prefs map[string]interface{}) error {
	apiURL := fmt.Sprintf("%s/api/v2/app/setPreferences", qbtBaseURL(q.config))

	// qBittorrent expects form data with json parameter
	jsonData, err := json.Marshal(prefs)
	if err != nil {
		return fmt.Errorf("failed to marshal preferences: %w", err)
	}
	defer wipeCredentialBytes(jsonData)

	form := url.Values{}
	form.Set("json", string(jsonData))
	encoded := []byte(form.Encode())
	form.Del("json")
	defer wipeCredentialBytes(encoded)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", q.sessionCookie)

	resp, err := q.client.client.Do(req)
	if err != nil {
		return fmt.Errorf("set preferences request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("set preferences failed with status %d", resp.StatusCode)
	}

	return nil
}

// CreateCategory creates a download category
func (q *QBittorrentClient) CreateCategory(ctx context.Context, category, savePath string) error {
	apiURL := fmt.Sprintf("%s/api/v2/torrents/createCategory", qbtBaseURL(q.config))

	form := url.Values{}
	form.Set("category", category)
	if savePath != "" {
		form.Set("savePath", savePath)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", q.sessionCookie)

	resp, err := q.client.client.Do(req)
	if err != nil {
		return fmt.Errorf("create category request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusConflict {
		return fmt.Errorf("create category failed with status %d", resp.StatusCode)
	}

	return nil
}

// EditCategory changes a category's save path. Callers must first prove that
// the category has no assigned torrents; qBittorrent may otherwise move data.
func (q *QBittorrentClient) EditCategory(
	ctx context.Context,
	category, savePath string,
) error {
	apiURL := fmt.Sprintf("%s/api/v2/torrents/editCategory", qbtBaseURL(q.config))
	form := url.Values{}
	form.Set("category", category)
	form.Set("savePath", savePath)
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		apiURL,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", q.sessionCookie)
	resp, err := q.client.client.Do(req)
	if err != nil {
		return fmt.Errorf("edit category request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("edit category failed with status %d", resp.StatusCode)
	}
	return nil
}

type QBittorrentCategory struct {
	Name     string `json:"name"`
	SavePath string `json:"savePath"`
}

// GetCategories retrieves all categories
func (q *QBittorrentClient) GetCategories(
	ctx context.Context,
) (map[string]QBittorrentCategory, error) {
	apiURL := fmt.Sprintf("%s/api/v2/torrents/categories", qbtBaseURL(q.config))
	headers := map[string]string{
		"Cookie": q.sessionCookie,
	}

	body, err := q.client.Get(ctx, apiURL, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to get categories: %w", err)
	}

	var categories map[string]QBittorrentCategory
	if err := json.Unmarshal(body, &categories); err != nil {
		return nil, fmt.Errorf("failed to parse categories: %w", err)
	}

	return categories, nil
}

// CountTorrentsInCategory returns only a count and wipes the response that may
// contain torrent names immediately after decoding.
func (q *QBittorrentClient) CountTorrentsInCategory(
	ctx context.Context,
	category string,
) (int, error) {
	endpoint, err := url.Parse(
		fmt.Sprintf("%s/api/v2/torrents/info", qbtBaseURL(q.config)),
	)
	if err != nil {
		return 0, fmt.Errorf("parse torrents endpoint: %w", err)
	}
	query := endpoint.Query()
	query.Set("category", category)
	endpoint.RawQuery = query.Encode()
	body, err := q.client.Get(ctx, endpoint.String(), map[string]string{
		"Cookie": q.sessionCookie,
	})
	if err != nil {
		return 0, fmt.Errorf("get category torrent usage: %w", err)
	}
	defer wipeCredentialBytes(body)
	var torrents []struct {
		Category string `json:"category"`
	}
	if err := json.Unmarshal(body, &torrents); err != nil {
		return 0, fmt.Errorf("decode category torrent usage: %w", err)
	}
	count := 0
	for _, torrent := range torrents {
		if torrent.Category == category {
			count++
		}
	}
	return count, nil
}
