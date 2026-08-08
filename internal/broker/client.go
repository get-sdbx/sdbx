package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/get-sdbx/sdbx/internal/addons"
	"github.com/get-sdbx/sdbx/internal/management"
	"github.com/get-sdbx/sdbx/internal/settings"
)

type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
}

func NewUnixClient(socketPath, token string) (*Client, error) {
	info, err := os.Lstat(socketPath)
	if err != nil {
		return nil, fmt.Errorf("inspect broker socket: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("broker socket must be a Unix socket, not a symlink")
	}
	transport := &http.Transport{
		DisableCompression: true,
		DisableKeepAlives:  false,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 5 * time.Second}
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return newClient(
		&http.Client{Transport: transport, Timeout: 5 * time.Minute},
		"http://sdbxd",
		token,
	)
}

func newClient(httpClient *http.Client, baseURL, token string) (*Client, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("HTTP client is required")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" {
		return nil, fmt.Errorf("broker base URL must be an HTTP origin")
	}
	if _, err := NewStaticTokenAuthorizer(token); err != nil {
		return nil, err
	}
	return &Client{
		httpClient: httpClient,
		baseURL:    strings.TrimRight(parsed.String(), "/"),
		token:      token,
	}, nil
}

func (c *Client) Preview(
	ctx context.Context,
	request management.ImpactRequest,
) (*management.Impact, error) {
	query := url.Values{}
	query.Set("operation", request.Operation)
	if request.Target != "" {
		query.Set("target", request.Target)
	}
	return requestValue[management.Impact](
		c,
		ctx,
		http.MethodGet,
		"/v1/impact?"+query.Encode(),
		nil,
	)
}

func (c *Client) Summary(ctx context.Context) (*management.Summary, error) {
	return requestValue[management.Summary](c, ctx, http.MethodGet, "/v1/summary", nil)
}

func (c *Client) Security(ctx context.Context) (*management.SecurityReport, error) {
	return requestValue[management.SecurityReport](
		c,
		ctx,
		http.MethodGet,
		"/v1/security",
		nil,
	)
}

func (c *Client) Diagnostics(
	ctx context.Context,
) (*management.DiagnosticsReport, error) {
	return requestValue[management.DiagnosticsReport](
		c,
		ctx,
		http.MethodGet,
		"/v1/diagnostics",
		nil,
	)
}

func (c *Client) Audit(
	ctx context.Context,
	limit int,
) ([]management.AuditEvent, error) {
	value, err := requestValue[[]management.AuditEvent](
		c,
		ctx,
		http.MethodGet,
		"/v1/audit?limit="+strconv.Itoa(limit),
		nil,
	)
	if err != nil {
		return nil, err
	}
	return *value, nil
}

func (c *Client) Services(ctx context.Context) ([]management.Service, error) {
	value, err := requestValue[[]management.Service](
		c,
		ctx,
		http.MethodGet,
		"/v1/services",
		nil,
	)
	if err != nil {
		return nil, err
	}
	return *value, nil
}

func (c *Client) Logs(
	ctx context.Context,
	request management.LogsRequest,
) (*management.LogsResult, error) {
	query := url.Values{}
	query.Set("tail", strconv.Itoa(request.Tail))
	if request.Service != "" {
		query.Set("service", request.Service)
	}
	return requestValue[management.LogsResult](
		c,
		ctx,
		http.MethodGet,
		"/v1/logs?"+query.Encode(),
		nil,
	)
}

func (c *Client) Addons(ctx context.Context) ([]management.Addon, error) {
	value, err := requestValue[[]management.Addon](
		c,
		ctx,
		http.MethodGet,
		"/v1/addons",
		nil,
	)
	if err != nil {
		return nil, err
	}
	return *value, nil
}

func (c *Client) SetAddon(
	ctx context.Context,
	request management.AddonRequest,
) (*addons.Result, error) {
	return requestValue[addons.Result](c, ctx, http.MethodPost, "/v1/addons", request)
}

func (c *Client) Settings(ctx context.Context) (*management.Settings, error) {
	return requestValue[management.Settings](c, ctx, http.MethodGet, "/v1/settings", nil)
}

func (c *Client) SetSetting(
	ctx context.Context,
	request management.SettingRequest,
) (*settings.Result, error) {
	return requestValue[settings.Result](c, ctx, http.MethodPost, "/v1/settings", request)
}

func (c *Client) Backups(ctx context.Context) ([]management.Backup, error) {
	value, err := requestValue[[]management.Backup](
		c,
		ctx,
		http.MethodGet,
		"/v1/backups",
		nil,
	)
	if err != nil {
		return nil, err
	}
	return *value, nil
}

func (c *Client) CreateBackup(
	ctx context.Context,
	request management.CreateBackupRequest,
) (*management.Backup, error) {
	wire := createBackupWireRequest{
		Recipient:  request.Recipient,
		Passphrase: append([]byte(nil), request.Passphrase...),
	}
	defer zeroBytes(request.Passphrase)
	defer zeroBytes(wire.Passphrase)
	return requestValue[management.Backup](c, ctx, http.MethodPost, "/v1/backups", wire)
}

func (c *Client) RestoreBackup(
	ctx context.Context,
	request management.RestoreBackupRequest,
) error {
	wire := restoreBackupWireRequest{
		Name:                 request.Name,
		Passphrase:           append([]byte(nil), request.Passphrase...),
		Confirm:              request.Confirm,
		RelocateManagedRoots: request.RelocateManagedRoots,
	}
	defer zeroBytes(request.Passphrase)
	defer zeroBytes(wire.Passphrase)
	_, err := requestValue[map[string]bool](
		c,
		ctx,
		http.MethodPost,
		"/v1/backups/restore",
		wire,
	)
	return err
}

func (c *Client) DeleteBackup(
	ctx context.Context,
	request management.DeleteBackupRequest,
) error {
	_, err := requestValue[map[string]bool](
		c,
		ctx,
		http.MethodPost,
		"/v1/backups/delete",
		request,
	)
	return err
}

func (c *Client) Stack(ctx context.Context, request management.StackRequest) error {
	_, err := requestValue[map[string]bool](
		c,
		ctx,
		http.MethodPost,
		"/v1/stack",
		request,
	)
	return err
}

func requestValue[T any](
	client *Client,
	ctx context.Context,
	method, path string,
	payload any,
) (*T, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("encode broker request: %w", err)
		}
		defer zeroBytes(data)
		if len(data) > maxRequestBytes {
			return nil, fmt.Errorf("broker request exceeds %d-byte limit", maxRequestBytes)
		}
		body = bytes.NewReader(data)
	}
	// #nosec G704 -- the only production constructor pins this origin to
	// http://sdbxd and replaces TCP dialing with the verified Unix socket.
	request, err := http.NewRequestWithContext(
		ctx,
		method,
		client.baseURL+path,
		body,
	)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	// #nosec G704 -- see the fixed-origin, Unix-transport boundary above.
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("broker request failed: %w", err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read broker response: %w", err)
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("broker response exceeds %d-byte limit", maxResponseBytes)
	}
	var result envelope
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decode broker response: %w", err)
	}
	if result.APIVersion != APIVersion {
		return nil, fmt.Errorf("unsupported broker API version %q", result.APIVersion)
	}
	if result.Error != nil {
		result.Error.Status = response.StatusCode
		return nil, result.Error
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("broker returned HTTP %d without an error body", response.StatusCode)
	}
	var value T
	if err := json.Unmarshal(result.Data, &value); err != nil {
		return nil, fmt.Errorf("decode broker data: %w", err)
	}
	return &value, nil
}
