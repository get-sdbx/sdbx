package integrate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

const (
	maxIntegrationResponseBody = 1 << 20
	maxIntegrationRedirects    = 10
)

// HTTPClient wraps http.Client with retry logic
type HTTPClient struct {
	client        *http.Client
	retryAttempts int
	retryDelay    time.Duration
}

// HTTPStatusError preserves a bounded response status without retaining or
// reflecting a potentially secret-bearing upstream response body.
type HTTPStatusError struct {
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("client error %d", e.StatusCode)
}

// NewHTTPClient creates a new HTTP client with retry support
func NewHTTPClient(timeout time.Duration, retryAttempts int, retryDelay time.Duration) *HTTPClient {
	jar, _ := cookiejar.New(nil)
	return &HTTPClient{
		client: &http.Client{
			Timeout:       timeout,
			CheckRedirect: checkIntegrationRedirect,
			Jar:           jar,
		},
		retryAttempts: retryAttempts,
		retryDelay:    retryDelay,
	}
}

func checkIntegrationRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	if len(via) >= maxIntegrationRedirects {
		return fmt.Errorf("stopped after %d redirects", maxIntegrationRedirects)
	}
	if !sameHTTPOrigin(via[0].URL, req.URL) {
		return fmt.Errorf("refusing cross-origin integration redirect")
	}
	return nil
}

func sameHTTPOrigin(left, right *url.URL) bool {
	if left == nil || right == nil {
		return false
	}
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(canonicalURLHost(left), canonicalURLHost(right))
}

func canonicalURLHost(value *url.URL) string {
	host := value.Hostname()
	port := value.Port()
	if port == "" {
		switch strings.ToLower(value.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return host + ":" + port
}

// Get performs HTTP GET with retry logic
func (c *HTTPClient) Get(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return c.doWithRetry(req)
}

// Post performs HTTP POST with retry logic
func (c *HTTPClient) Post(ctx context.Context, url string, headers map[string]string, body interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		defer wipeCredentialBytes(jsonData)
		bodyReader = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return c.doWithRetry(req)
}

// PostForm performs an application/x-www-form-urlencoded POST. The encoded
// credential-bearing buffer is wiped when the request completes.
func (c *HTTPClient) PostForm(ctx context.Context, endpoint string, headers map[string]string, values url.Values) ([]byte, error) {
	encoded := []byte(values.Encode())
	defer wipeCredentialBytes(encoded)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.doWithRetry(req)
}

// Put performs HTTP PUT with retry logic
func (c *HTTPClient) Put(ctx context.Context, url string, headers map[string]string, body interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		defer wipeCredentialBytes(jsonData)
		bodyReader = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return c.doWithRetry(req)
}

// Patch performs an HTTP PATCH with a bounded JSON body. It is kept separate
// from Put because several upstream applications use merge-style settings
// updates where sending a reconstructed full document would clobber fields
// owned by the operator.
func (c *HTTPClient) Patch(ctx context.Context, url string, headers map[string]string, body interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		defer wipeCredentialBytes(jsonData)
		bodyReader = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, "PATCH", url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.doWithRetry(req)
}

// Delete performs HTTP DELETE with retry logic.
func (c *HTTPClient) Delete(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.doWithRetry(req)
}

// doWithRetry executes HTTP request with retry logic
func (c *HTTPClient) doWithRetry(req *http.Request) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt <= c.retryAttempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(c.retryDelay)
			select {
			case <-req.Context().Done():
				timer.Stop()
				return nil, req.Context().Err()
			case <-timer.C:
			}
		}

		attemptReq := req.Clone(req.Context())
		if req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("recreate request body: %w", err)
			}
			attemptReq.Body = body
		}

		resp, err := c.client.Do(attemptReq)
		if err != nil {
			lastErr = err
			continue
		}

		body, readErr := readBoundedResponse(resp.Body)
		closeErr := resp.Body.Close()

		if readErr != nil {
			lastErr = fmt.Errorf("failed to read response body: %w", readErr)
			continue
		}
		if closeErr != nil {
			wipeCredentialBytes(body)
			lastErr = fmt.Errorf("failed to close response body: %w", closeErr)
			continue
		}

		// Success
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return body, nil
		}

		// Client error - don't retry
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			wipeCredentialBytes(body)
			return nil, &HTTPStatusError{StatusCode: resp.StatusCode}
		}

		// Server error - retry
		wipeCredentialBytes(body)
		lastErr = fmt.Errorf("server error %d", resp.StatusCode)
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", c.retryAttempts+1, lastErr)
}

func readBoundedResponse(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxIntegrationResponseBody+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxIntegrationResponseBody {
		wipeCredentialBytes(data)
		return nil, fmt.Errorf("response exceeds %d bytes", maxIntegrationResponseBody)
	}
	return data, nil
}

func wipeCredentialBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
