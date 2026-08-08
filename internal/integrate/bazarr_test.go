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

func TestReadBazarrAPIKeyReturnsOnlyAuthenticationCredential(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigPath = t.TempDir()
	path := filepath.Join(cfg.ConfigPath, "bazarr", "config", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		path,
		[]byte("auth:\n  apikey: synthetic-bazarr-key\n  password: must-not-return\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	key, err := ReadBazarrAPIKey(cfg)
	if err != nil || key != "synthetic-bazarr-key" {
		t.Fatalf("key=%q err=%v", key, err)
	}
}

func TestIntegrateBazarrRepairsBothArrConnectionsAndVerifies(t *testing.T) {
	const bazarrKey = "synthetic-bazarr-key"
	updated := false
	updateCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.Header.Get("X-Api-Key") != bazarrKey {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		if request.URL.Path != "/bazarr/api/system/settings" {
			http.NotFound(writer, request)
			return
		}
		if request.Method == http.MethodPost {
			if err := request.ParseForm(); err != nil {
				t.Fatal(err)
			}
			for name, want := range map[string]string{
				"settings-general-use_sonarr": "true",
				"settings-sonarr-ip":          "sdbx-sonarr",
				"settings-sonarr-base_url":    "/sonarr",
				"settings-sonarr-apikey":      "current-sonarr-key",
				"settings-general-use_radarr": "true",
				"settings-radarr-ip":          "sdbx-radarr",
				"settings-radarr-base_url":    "/radarr",
				"settings-radarr-apikey":      "current-radarr-key",
			} {
				if got := request.Form.Get(name); got != want {
					t.Fatalf("%s=%q want %q", name, got, want)
				}
			}
			updated = true
			updateCount++
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		response := map[string]any{
			"general": map[string]any{"use_sonarr": updated, "use_radarr": updated},
			"sonarr":  map[string]any{"ip": "legacy", "port": 8989, "base_url": "", "apikey": "stale", "ssl": false},
			"radarr":  map[string]any{"ip": "legacy", "port": 7878, "base_url": "", "apikey": "stale", "ssl": false},
		}
		if updated {
			response["sonarr"] = map[string]any{"ip": "sdbx-sonarr", "port": 8989, "base_url": "/sonarr", "apikey": "current-sonarr-key", "ssl": false}
			response["radarr"] = map[string]any{"ip": "sdbx-radarr", "port": 7878, "base_url": "/radarr", "apikey": "current-radarr-key", "ssl": false}
		}
		_ = json.NewEncoder(writer).Encode(response)
	}))
	defer server.Close()
	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	cfg.RetryAttempts = 0
	cfg.Services = map[string]*ServiceConfig{
		"bazarr": {
			Name:       "bazarr",
			URL:        "http://sdbx-bazarr:6767/bazarr",
			ControlURL: server.URL + "/bazarr",
			APIKey:     bazarrKey,
			Enabled:    true,
		},
		"sonarr": {
			Name: "sonarr", URL: "http://sdbx-sonarr:8989/sonarr",
			APIKey: "current-sonarr-key", Enabled: true,
		},
		"radarr": {
			Name: "radarr", URL: "http://sdbx-radarr:7878/radarr",
			APIKey: "current-radarr-key", Enabled: true,
		},
	}
	result := NewIntegrator(cfg).integrateBazarr(context.Background())
	if !result.Success || !updated {
		t.Fatalf("result=%#v updated=%t", result, updated)
	}
	result = NewIntegrator(cfg).integrateBazarr(context.Background())
	if !result.Success || updateCount != 1 {
		t.Fatalf("second result=%#v updateCount=%d", result, updateCount)
	}
}
