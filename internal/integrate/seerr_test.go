package integrate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/get-sdbx/sdbx/internal/config"
)

func TestReadSeerrAPIKeyReturnsOnlyMainCredential(t *testing.T) {
	root := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ConfigPath = root
	path := filepath.Join(root, "seerr", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		path,
		[]byte(`{"main":{"apiKey":"synthetic-seerr-key"},"sessionSecret":"must-not-return"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	key, err := ReadSeerrAPIKey(cfg)
	if err != nil || key != "synthetic-seerr-key" {
		t.Fatalf("key=%q err=%v", key, err)
	}
}

func TestIntegrateSeerrRepairsAndVerifiesStaleArrCredential(t *testing.T) {
	const seerrKey = "synthetic-seerr-key"
	putCount := 0
	storedKey := "stale"
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.Header.Get("X-Api-Key") != seerrKey {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/settings/radarr":
			_ = json.NewEncoder(writer).Encode([]map[string]any{{
				"id": 0, "name": "Radarr", "hostname": "sdbx-radarr",
				"port": 7878, "apiKey": storedKey, "useSsl": false,
				"baseUrl": "/radarr", "activeProfileId": 1,
				"activeDirectory": "/movies", "isDefault": true,
			}})
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/settings/radarr/test":
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["apiKey"] != "current-radarr-key" || body["baseUrl"] != "/radarr" {
				http.Error(writer, "bad managed connection", http.StatusBadRequest)
				return
			}
			_, _ = writer.Write([]byte(`{"profiles":[]}`))
		case request.Method == http.MethodPut && request.URL.Path == "/api/v1/settings/radarr/0":
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if _, hasReadOnlyID := body["id"]; hasReadOnlyID {
				http.Error(writer, "read-only id", http.StatusBadRequest)
				return
			}
			putCount++
			storedKey = "current-radarr-key"
			body["id"] = float64(0)
			body["apiKey"] = storedKey
			_ = json.NewEncoder(writer).Encode(body)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	cfg.RetryAttempts = 0
	cfg.Services = map[string]*ServiceConfig{
		"seerr": {
			Name:       "seerr",
			URL:        "http://sdbx-seerr:5055",
			ControlURL: server.URL,
			APIKey:     seerrKey,
			Enabled:    true,
		},
		"radarr": {
			Name:    "radarr",
			URL:     "http://sdbx-radarr:7878/radarr",
			APIKey:  "current-radarr-key",
			Enabled: true,
		},
	}
	results := NewIntegrator(cfg).integrateSeerr(context.Background())
	if len(results) != 1 || !results[0].Success || putCount != 1 {
		t.Fatalf("results=%#v putCount=%d", results, putCount)
	}
	results = NewIntegrator(cfg).integrateSeerr(context.Background())
	if len(results) != 1 || !results[0].Success || putCount != 1 {
		t.Fatalf("second results=%#v putCount=%d", results, putCount)
	}
}

func TestIntegrateSeerrCreatesFreshInstanceWithBoundedDefaults(t *testing.T) {
	const seerrKey = "synthetic-seerr-key"
	created := false
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.Header.Get("X-Api-Key") != seerrKey {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/settings/sonarr":
			if !created {
				_, _ = writer.Write([]byte(`[]`))
				return
			}
			_, _ = writer.Write([]byte(`[{"id":7,"name":"Sonarr","hostname":"sdbx-sonarr","port":8989,"useSsl":false,"baseUrl":"/sonarr"}]`))
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/settings/sonarr/test":
			_, _ = writer.Write([]byte(`{"profiles":[{"id":3,"name":"Synthetic HD"}],"rootFolders":[{"id":1,"path":"/tv"}]}`))
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/settings/sonarr":
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["activeProfileId"] != float64(3) ||
				body["activeDirectory"] != "/tv" ||
				body["enableSeasonFolders"] != true ||
				body["isDefault"] != true || body["is4k"] != false {
				t.Fatalf("unsafe fresh settings: %#v", body)
			}
			created = true
			writer.WriteHeader(http.StatusCreated)
			_, _ = writer.Write([]byte(`{"id":7}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	cfg.RetryAttempts = 0
	cfg.Services = map[string]*ServiceConfig{
		"seerr": {
			Name:       "seerr",
			URL:        "http://sdbx-seerr:5055",
			ControlURL: server.URL,
			APIKey:     seerrKey,
			Enabled:    true,
		},
		"sonarr": {
			Name:    "sonarr",
			URL:     "http://sdbx-sonarr:8989/sonarr",
			APIKey:  "current-sonarr-key",
			Enabled: true,
		},
	}
	results := NewIntegrator(cfg).integrateSeerr(context.Background())
	if len(results) != 1 || !results[0].Success || !created {
		t.Fatalf("results=%#v created=%t", results, created)
	}
}

func TestIntegrateSeerrRepairsPlexToStableServiceAddressOnce(t *testing.T) {
	const seerrKey = "synthetic-seerr-key"
	postCount := 0
	stored := map[string]any{
		"name":      "Synthetic Plex",
		"machineId": "synthetic-machine",
		"ip":        "172.18.0.13",
		"port":      float64(32400),
		"useSsl":    false,
		"webAppUrl": "https://plex.example.test",
		"libraries": []any{map[string]any{"id": "1", "name": "Movies"}},
	}
	plex := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path != "/identity" || request.Header.Get("X-Plex-Token") != "synthetic-plex-token" {
			http.Error(writer, "bad Plex preflight", http.StatusBadRequest)
			return
		}
		_, _ = writer.Write([]byte(`<MediaContainer machineIdentifier="synthetic"/>`))
	}))
	defer plex.Close()
	seerr := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.Header.Get("X-Api-Key") != seerrKey {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/settings/plex":
			_ = json.NewEncoder(writer).Encode(stored)
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/settings/plex":
			postCount++
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["ip"] != "sdbx-plex" || body["port"] != float64(32400) || body["useSsl"] != false {
				t.Fatalf("unstable Plex connection: %#v", body)
			}
			for _, readOnly := range []string{"name", "machineId", "libraries"} {
				if _, exists := body[readOnly]; exists {
					http.Error(writer, "read-only field", http.StatusBadRequest)
					return
				}
			}
			for name, value := range body {
				stored[name] = value
			}
			_ = json.NewEncoder(writer).Encode(stored)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer seerr.Close()
	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	cfg.RetryAttempts = 0
	cfg.Services = map[string]*ServiceConfig{
		"seerr": {
			Name:       "seerr",
			URL:        "http://sdbx-seerr:5055",
			ControlURL: seerr.URL,
			APIKey:     seerrKey,
			Enabled:    true,
		},
		"plex": {
			Name:       "plex",
			URL:        "http://sdbx-plex:32400",
			ControlURL: plex.URL,
			APIKey:     "synthetic-plex-token",
			Enabled:    true,
		},
	}
	results := NewIntegrator(cfg).integrateSeerr(context.Background())
	if len(results) != 1 || !results[0].Success || postCount != 1 {
		t.Fatalf("results=%#v postCount=%d", results, postCount)
	}
	results = NewIntegrator(cfg).integrateSeerr(context.Background())
	if len(results) != 1 || !results[0].Success || postCount != 1 {
		t.Fatalf("second results=%#v postCount=%d", results, postCount)
	}
}
