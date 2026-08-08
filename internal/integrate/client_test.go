package integrate

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPClientRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", maxIntegrationResponseBody+1))
	}))
	defer server.Close()

	client := NewHTTPClient(time.Second, 0, 0)
	_, err := client.Get(context.Background(), server.URL, nil)
	if err == nil {
		t.Fatal("oversized response was accepted")
	}
	if !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("error = %q, want response size failure", err)
	}
}

func TestHTTPClientDoesNotEchoErrorResponseBody(t *testing.T) {
	const canary = "SDBX_RESPONSE_SECRET_CANARY"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"password":"`+canary+`"}`, http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewHTTPClient(time.Second, 0, 0)
	_, err := client.Get(context.Background(), server.URL, nil)
	if err == nil {
		t.Fatal("client error was accepted")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("response secret leaked into error: %q", err)
	}
	if !strings.Contains(err.Error(), "client error 401") {
		t.Fatalf("error = %q, want status-only diagnostic", err)
	}
}

func TestHTTPClientReplaysPostBodyOnRetry(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if string(body) != `{"value":"expected"}` {
			t.Errorf("attempt body = %q", body)
		}
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	client := NewHTTPClient(time.Second, 1, time.Millisecond)
	body, err := client.Post(
		context.Background(),
		server.URL,
		nil,
		map[string]string{"value": "expected"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
}

func TestHTTPClientAllowsSameOriginRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/finish", http.StatusTemporaryRedirect)
		case "/finish":
			if got := r.Header.Get("X-Api-Key"); got != "expected" {
				t.Fatalf("X-Api-Key = %q, want expected", got)
			}
			_, _ = io.WriteString(w, "ok")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewHTTPClient(time.Second, 0, 0)
	body, err := client.Get(
		context.Background(),
		server.URL+"/start",
		map[string]string{"X-Api-Key": "expected"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
}

func TestHTTPClientRejectsCrossOriginRedirectWithoutCredentialLeak(t *testing.T) {
	var attackerRequests atomic.Int32
	attacker := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		attackerRequests.Add(1)
		if value := r.Header.Get("X-Api-Key"); value != "" {
			t.Errorf("attacker received X-Api-Key %q", value)
		}
	}))
	defer attacker.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	client := NewHTTPClient(time.Second, 0, 0)
	_, err := client.Get(
		context.Background(),
		origin.URL,
		map[string]string{"X-Api-Key": "credential-canary"},
	)
	if err == nil {
		t.Fatal("cross-origin redirect was accepted")
	}
	if !strings.Contains(err.Error(), "cross-origin integration redirect") {
		t.Fatalf("error = %q, want cross-origin redirect refusal", err)
	}
	if got := attackerRequests.Load(); got != 0 {
		t.Fatalf("attacker requests = %d, want 0", got)
	}
}

func TestHTTPClientDoesNotForwardWriteAcrossOrigin(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			var attackerRequests atomic.Int32
			attacker := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				attackerRequests.Add(1)
			}))
			defer attacker.Close()

			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, attacker.URL, http.StatusTemporaryRedirect)
			}))
			defer origin.Close()

			client := NewHTTPClient(time.Second, 0, 0)
			var err error
			switch method {
			case http.MethodPost:
				_, err = client.Post(
					context.Background(),
					origin.URL,
					map[string]string{"X-Api-Key": "credential-canary"},
					map[string]string{"value": "sensitive"},
				)
			case http.MethodPut:
				_, err = client.Put(
					context.Background(),
					origin.URL,
					map[string]string{"X-Api-Key": "credential-canary"},
					map[string]string{"value": "sensitive"},
				)
			}
			if err == nil {
				t.Fatal("cross-origin write redirect was accepted")
			}
			if got := attackerRequests.Load(); got != 0 {
				t.Fatalf("attacker requests = %d, want 0", got)
			}
		})
	}
}

func TestSameHTTPOriginNormalizesDefaultPorts(t *testing.T) {
	left, err := url.Parse("https://EXAMPLE.com/path")
	if err != nil {
		t.Fatal(err)
	}
	right, err := url.Parse("https://example.com:443/other")
	if err != nil {
		t.Fatal(err)
	}
	if !sameHTTPOrigin(left, right) {
		t.Fatal("default HTTPS port and host case should identify the same origin")
	}
}

func TestWipeCredentialBytesClearsBuffer(t *testing.T) {
	value := []byte("credential-canary")
	wipeCredentialBytes(value)
	for index, item := range value {
		if item != 0 {
			t.Fatalf("credential byte %d was not cleared", index)
		}
	}
}
