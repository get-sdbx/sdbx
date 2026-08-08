package integrate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func syntheticPlexNotification(name, host, token string) map[string]any {
	return map[string]any{
		"id":             float64(1),
		"name":           name,
		"implementation": "PlexServer",
		"configContract": "PlexServerSettings",
		"onDownload":     true,
		"onUpgrade":      true,
		"onRename":       false,
		"fields": []any{
			map[string]any{"name": "server", "value": "http://" + host + ":32400"},
			map[string]any{"name": "host", "value": host},
			map[string]any{"name": "port", "value": float64(32400)},
			map[string]any{"name": "useSsl", "value": false},
			map[string]any{"name": "urlBase", "value": nil},
			map[string]any{"name": "authToken", "value": token},
			map[string]any{"name": "signIn", "value": "startOAuth"},
			map[string]any{"name": "updateLibrary", "value": true},
		},
	}
}

func cloneNotification(t *testing.T, notification map[string]any) map[string]any {
	t.Helper()
	body, err := json.Marshal(notification)
	if err != nil {
		t.Fatal(err)
	}
	var cloned map[string]any
	if err := json.Unmarshal(body, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func TestArrPlexNotificationRepairsStaleEndpointAndTokenOnce(t *testing.T) {
	const token = "synthetic-plex-token"
	stored := syntheticPlexNotification("Plex Media Server", "172.19.0.10", "stale-token")
	writes := 0
	tests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v3/notification":
			response := cloneNotification(t, stored)
			setNotificationField(response, "authToken", "********")
			_ = json.NewEncoder(writer).Encode([]map[string]any{response})
		case request.Method == http.MethodPost && request.URL.Path == "/api/v3/notification/test":
			var notification map[string]any
			_ = json.NewDecoder(request.Body).Decode(&notification)
			supplied, _ := notificationField(notification, "authToken")
			if supplied == "********" {
				supplied, _ = notificationField(stored, "authToken")
			}
			host, _ := notificationField(notification, "host")
			if host != "sdbx-plex" || supplied != token {
				http.Error(writer, "unavailable", http.StatusBadRequest)
				return
			}
			tests++
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodPut && request.URL.Path == "/api/v3/notification/1":
			var notification map[string]any
			_ = json.NewDecoder(request.Body).Decode(&notification)
			stored = notification
			writes++
			_ = json.NewEncoder(writer).Encode(notification)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	cfg.RetryAttempts = 0
	cfg.Services = map[string]*ServiceConfig{
		"radarr": {Name: "radarr", URL: server.URL, APIKey: "synthetic-arr-key", Enabled: true},
		"plex":   {Name: "plex", URL: "http://sdbx-plex:32400", APIKey: token, Enabled: true},
	}
	integrator := NewIntegrator(cfg)
	results := integrator.integrateArrPlexNotifications(context.Background())
	if len(results) != 1 || !results[0].Success || writes != 1 || tests != 2 {
		t.Fatalf("first results=%#v writes=%d tests=%d", results, writes, tests)
	}
	results = integrator.integrateArrPlexNotifications(context.Background())
	if len(results) != 1 || !results[0].Success || writes != 1 || tests != 3 {
		t.Fatalf("second results=%#v writes=%d tests=%d", results, writes, tests)
	}
}

func TestConfigureManagedPlexNotificationUsesLidarrImportEvent(t *testing.T) {
	notification := syntheticPlexNotification("", "", "")
	notification["onReleaseImport"] = false
	if err := configureManagedPlexNotification(notification, "lidarr", "synthetic-token"); err != nil {
		t.Fatal(err)
	}
	if notification["onReleaseImport"] != true || notification["onDownload"] != true {
		t.Fatalf("events = %#v", notification)
	}
	if !managedPlexNotificationMatches(notification, "lidarr") {
		t.Fatal("configured Lidarr notification did not match")
	}
}
