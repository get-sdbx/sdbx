package integrate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestArrAPIVersionMatchesSupportedApplications(t *testing.T) {
	for _, test := range []struct {
		name    string
		version string
	}{
		{name: "sonarr", version: "v3"},
		{name: "radarr", version: "v3"},
		{name: "prowlarr", version: "v3"},
		{name: "whisparr", version: "v3"},
		{name: "lidarr", version: "v1"},
		{name: "unknown", version: "v3"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if actual := arrAPIVersion(test.name); actual != test.version {
				t.Fatalf("version = %q, want %q", actual, test.version)
			}
		})
	}
}

func TestArrClientUsesVersionedAuthenticatedAPIContract(t *testing.T) {
	const apiKey = "synthetic-arr-api-key"
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Api-Key") != apiKey {
			t.Errorf("API key header = %q", request.Header.Get("X-Api-Key"))
		}
		requests = append(requests, request.Method+" "+request.URL.Path)
		switch {
		case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/system/status"):
			_, _ = writer.Write([]byte(`{"version":"test"}`))
		case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/downloadclient"):
			_, _ = writer.Write([]byte(`[{"id":7,"name":"qBittorrent","implementation":"QBittorrent"}]`))
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/downloadclient"):
			var submitted DownloadClient
			if err := json.NewDecoder(request.Body).Decode(&submitted); err != nil {
				t.Errorf("decode submitted client: %v", err)
			}
			if submitted.Implementation != "QBittorrent" {
				t.Errorf("submitted client = %+v", submitted)
			}
			_, _ = writer.Write([]byte(`{"id":8,"name":"qBittorrent","implementation":"QBittorrent"}`))
		case request.Method == http.MethodPut && strings.HasSuffix(request.URL.Path, "/downloadclient/8"):
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/downloadclient/test"):
			writer.WriteHeader(http.StatusOK)
		default:
			http.Error(writer, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewArrClient(
		NewHTTPClient(time.Second, 0, 0),
		&ServiceConfig{Name: "sonarr", URL: server.URL, APIKey: apiKey, Enabled: true},
	)
	if err := client.CheckHealth(context.Background()); err != nil {
		t.Fatalf("CheckHealth failed: %v", err)
	}
	existing, err := client.GetDownloadClients(context.Background())
	if err != nil {
		t.Fatalf("GetDownloadClients failed: %v", err)
	}
	if len(existing) != 1 || existing[0].ID != 7 {
		t.Fatalf("existing clients = %+v", existing)
	}
	created, err := client.AddDownloadClient(
		context.Background(),
		CreateQBittorrentClient("qBittorrent", "sdbx-gluetun", 8080, "admin", "synthetic-password"),
	)
	if err != nil {
		t.Fatalf("AddDownloadClient failed: %v", err)
	}
	if created.ID != 8 {
		t.Fatalf("created client = %+v", created)
	}
	if err := client.UpdateDownloadClient(context.Background(), created); err != nil {
		t.Fatalf("UpdateDownloadClient failed: %v", err)
	}
	if err := client.TestDownloadClient(context.Background(), created); err != nil {
		t.Fatalf("TestDownloadClient failed: %v", err)
	}

	expected := []string{
		"GET /api/v3/system/status",
		"GET /api/v3/downloadclient",
		"POST /api/v3/downloadclient",
		"PUT /api/v3/downloadclient/8",
		"POST /api/v3/downloadclient/test",
	}
	if strings.Join(requests, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("requests = %v, want %v", requests, expected)
	}
}

func TestArrClientUsesLidarrV1Path(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/system/status" {
			t.Errorf("path = %q", request.URL.Path)
			http.Error(writer, "wrong path", http.StatusNotFound)
			return
		}
		_, _ = writer.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := NewArrClient(
		NewHTTPClient(time.Second, 0, 0),
		&ServiceConfig{Name: "lidarr", URL: server.URL, APIKey: "synthetic"},
	)
	if err := client.CheckHealth(context.Background()); err != nil {
		t.Fatalf("CheckHealth failed: %v", err)
	}
}
