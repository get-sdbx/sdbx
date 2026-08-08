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

func TestReconcileArrRuntimeStateReloadsOnlyAuthenticationDrift(t *testing.T) {
	reloaded := false
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path != "/sonarr/api/v3/system/status" {
			http.NotFound(writer, request)
			return
		}
		if !reloaded {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = writer.Write([]byte(`{"version":"test"}`))
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	cfg.RetryAttempts = 0
	cfg.Services = map[string]*ServiceConfig{
		"sonarr": {
			Name:       "sonarr",
			URL:        "http://sdbx-sonarr:8989/sonarr",
			ControlURL: server.URL + "/sonarr",
			APIKey:     "synthetic-key",
			Enabled:    true,
		},
	}
	integrator := NewIntegrator(cfg)
	restarts := 0
	integrator.restart = func(_ context.Context, service string) error {
		if service != "sonarr" {
			t.Fatalf("restarted service = %q", service)
		}
		restarts++
		reloaded = true
		return nil
	}
	results := integrator.reconcileArrRuntimeState(context.Background())
	if restarts != 1 || len(results) != 1 || !results[0].Success {
		t.Fatalf("restarts=%d results=%#v", restarts, results)
	}
	if results := integrator.reconcileArrRuntimeState(context.Background()); len(results) != 0 {
		t.Fatalf("steady-state runtime results = %#v", results)
	}
}

func TestRunReportsUnreachableHostEndpointsWithoutLaunchingHelper(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = 50 * time.Millisecond
	cfg.RetryAttempts = 1
	cfg.RetryDelay = time.Millisecond
	cfg.Services = map[string]*ServiceConfig{
		"prowlarr": {
			Name:    "prowlarr",
			URL:     "http://127.0.0.1:1",
			Enabled: true,
		},
		"sonarr": {
			Name:    "sonarr",
			URL:     "http://127.0.0.1:1",
			Enabled: true,
		},
	}

	results, err := NewIntegrator(cfg).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Success {
		t.Fatalf("results = %#v", results)
	}
	if !strings.Contains(results[0].Message, "inspected container endpoints") {
		t.Fatalf("unexpected boundary error: %#v", results[0])
	}
}

func TestRunSkipsDockerNetworkProbeWhenNoAPIIntegrationExists(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Services = map[string]*ServiceConfig{
		"qbittorrent": {
			Name:    "qbittorrent",
			URL:     "http://127.0.0.1:1",
			Enabled: true,
		},
	}
	results, err := NewIntegrator(cfg).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("qBittorrent-only integrations = %#v, want none", results)
	}
}

func TestEndpointProbeIgnoresUnrelatedHealthyByDefaultServices(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = 20 * time.Millisecond
	cfg.RetryAttempts = 0
	cfg.Services = map[string]*ServiceConfig{
		"filebrowser": {
			Name:    "filebrowser",
			URL:     "http://127.0.0.1:1",
			Enabled: true,
		},
		"sonarr": {
			Name:    "sonarr",
			URL:     "http://127.0.0.1:1",
			Enabled: true,
		},
	}

	if NewIntegrator(cfg).integrationEndpointsReachable(context.Background()) {
		t.Fatal("unrelated service produced a false-positive endpoint probe")
	}
}

func TestSortedEnabledServiceNamesIsDeterministicAndNilSafe(t *testing.T) {
	services := map[string]*ServiceConfig{
		"sonarr":      {Name: "sonarr", Enabled: true},
		"filebrowser": {Name: "filebrowser", Enabled: true},
		"prowlarr":    {Name: "prowlarr", Enabled: false},
		"nil":         nil,
	}
	got := sortedEnabledServiceNames(services)
	want := []string{"filebrowser", "sonarr"}
	if len(got) != len(want) {
		t.Fatalf("names = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("names = %#v, want %#v", got, want)
		}
	}
}

func TestIntegratorServiceChecksAreNilSafe(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Services = map[string]*ServiceConfig{
		"prowlarr": nil,
		"sonarr":   nil,
	}
	integrator := NewIntegrator(cfg)
	if integrator.hasService("prowlarr") {
		t.Fatal("nil service was reported enabled")
	}
	if integrator.integrationEndpointsReachable(context.Background()) {
		t.Fatal("nil service produced a reachable endpoint")
	}
}

func TestServiceControlConfigKeepsStableAdvertisedURL(t *testing.T) {
	service := &ServiceConfig{
		Name:       "sonarr",
		URL:        "http://sdbx-sonarr:8989",
		ControlURL: "http://172.20.0.5:8989",
		Enabled:    true,
	}
	control := serviceControlConfig(service)
	if control.URL != service.ControlURL {
		t.Fatalf("control URL = %q", control.URL)
	}
	if service.URL != "http://sdbx-sonarr:8989" {
		t.Fatalf("stable URL mutated to %q", service.URL)
	}
}

func TestProwlarrApplicationMatchDetectsStableURLDrift(t *testing.T) {
	desired := CreateSonarrApplication(
		"sonarr",
		"http://sdbx-prowlarr:9696/prowlarr",
		"http://sdbx-sonarr:8989/sonarr",
		"synthetic-key",
		"fullSync",
	)
	existing := mergeManagedProwlarrApplication(desired, desired)
	existing.ID = 9
	if !prowlarrApplicationMatches(existing, desired) {
		t.Fatal("equivalent managed application did not match")
	}
	setProwlarrField(existing, "baseUrl", "http://sdbx-sonarr:8989")
	if prowlarrApplicationMatches(existing, desired) {
		t.Fatal("missing URL base was accepted as an equivalent application")
	}
	repaired := mergeManagedProwlarrApplication(existing, desired)
	if got, _ := prowlarrField(repaired, "baseUrl"); got != "http://sdbx-sonarr:8989/sonarr" {
		t.Fatalf("repaired base URL = %q", got)
	}
}

func TestCategoryReconciliationPreservesPathWhenTorrentsAreAssigned(t *testing.T) {
	edits := 0
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch request.URL.Path {
		case "/api/v2/torrents/categories":
			_, _ = writer.Write([]byte(`{"sonarr":{"name":"sonarr","savePath":""}}`))
		case "/api/v2/torrents/info":
			_, _ = writer.Write([]byte(`[{"name":"not-reported","category":"sonarr"}]`))
		case "/api/v2/torrents/editCategory":
			edits++
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := NewQBittorrentClient(
		NewHTTPClient(time.Second, 0, 0),
		&QBittorrentConfig{Host: server.URL, Port: 8080},
	)
	client.sessionCookie = "SID=synthetic"
	result := NewIntegrator(DefaultConfig()).reconcileQBittorrentCategory(
		context.Background(),
		client,
		"sonarr",
	)
	if !result.Success || edits != 0 || !strings.Contains(result.Message, "Preserved") {
		t.Fatalf("edits=%d result=%#v", edits, result)
	}
}

func TestQBittorrentAutomaticManagementReconcilesOnceWithoutExistingTorrentMutation(t *testing.T) {
	autoTMMEnabled := false
	preferenceWrites := 0
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch request.URL.Path {
		case "/api/v2/app/preferences":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"auto_tmm_enabled": autoTMMEnabled,
			})
		case "/api/v2/app/setPreferences":
			if err := request.ParseForm(); err != nil {
				t.Errorf("parse preferences: %v", err)
			}
			var preferences map[string]any
			if err := json.Unmarshal([]byte(request.Form.Get("json")), &preferences); err != nil {
				t.Errorf("decode preferences: %v", err)
			}
			if len(preferences) != 1 || preferences["auto_tmm_enabled"] != true {
				t.Errorf("unexpected preferences mutation: %#v", preferences)
			}
			autoTMMEnabled = true
			preferenceWrites++
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := NewQBittorrentClient(
		NewHTTPClient(time.Second, 0, 0),
		&QBittorrentConfig{Host: server.URL, Port: 8080},
	)
	client.sessionCookie = "SID=synthetic"
	integrator := NewIntegrator(DefaultConfig())
	result := integrator.reconcileQBittorrentAutomaticManagement(context.Background(), client)
	if !result.Success || preferenceWrites != 1 {
		t.Fatalf("first result=%#v writes=%d", result, preferenceWrites)
	}
	result = integrator.reconcileQBittorrentAutomaticManagement(context.Background(), client)
	if !result.Success || preferenceWrites != 1 || !strings.Contains(result.Message, "already enabled") {
		t.Fatalf("second result=%#v writes=%d", result, preferenceWrites)
	}
}

func TestQBTDownloadClientMatchesStableConnectionFields(t *testing.T) {
	desired := CreateQBittorrentClient(
		"qBittorrent",
		"sdbx-gluetun",
		8080,
		"admin",
		"synthetic-password",
	)
	setDownloadClientField(desired, qbtCategoryField("sonarr"), "sonarr")
	existing := *desired
	existing.Fields = append([]DownloadClientField(nil), desired.Fields...)
	for idx := range existing.Fields {
		if existing.Fields[idx].Name == "port" {
			existing.Fields[idx].Value = float64(8080)
		}
		if existing.Fields[idx].Name == "password" {
			existing.Fields[idx].Value = "********"
		}
	}
	if !qbtDownloadClientMatches(&existing, desired) {
		t.Fatal("equivalent API response did not match desired client")
	}

	for idx := range existing.Fields {
		if existing.Fields[idx].Name == "host" {
			existing.Fields[idx].Value = "172.20.0.2"
		}
	}
	if qbtDownloadClientMatches(&existing, desired) {
		t.Fatal("ephemeral bridge host was accepted as stable configuration")
	}
}

func TestWhisparrUsesRadarrCompatibleQBittorrentCategory(t *testing.T) {
	if field := qbtCategoryField("whisparr"); field != "movieCategory" {
		t.Fatalf("Whisparr category field = %q, want movieCategory", field)
	}
}

func TestMergeManagedDownloadClientPreservesServerEnvelope(t *testing.T) {
	existing := &DownloadClient{
		ID:                 7,
		Name:               "qBittorrent",
		Implementation:     "QBittorrent",
		ImplementationName: "qBittorrent",
		ConfigContract:     "QBittorrentSettings",
		InfoLink:           "https://example.invalid/schema-info",
		Protocol:           "torrent",
		Enable:             true,
		Tags:               []int{3},
		Fields: []DownloadClientField{
			{Name: "host", Value: "172.20.0.2"},
			{Name: "port", Value: float64(8080)},
			{Name: "password", Value: "********"},
			{Name: "contentLayout", Value: 0},
		},
	}
	desired := CreateQBittorrentClient(
		"qBittorrent",
		"sdbx-gluetun",
		8080,
		"admin",
		"synthetic-password",
	)
	setDownloadClientField(desired, qbtCategoryField("sonarr"), "sonarr")
	merged := mergeManagedDownloadClient(existing, desired)

	if merged.ID != existing.ID ||
		merged.ImplementationName != existing.ImplementationName ||
		merged.InfoLink != existing.InfoLink ||
		len(merged.Tags) != 1 {
		t.Fatalf("server envelope was not preserved: %#v", merged)
	}
	for name, want := range map[string]string{
		"host":       "sdbx-gluetun",
		"password":   "synthetic-password",
		"tvCategory": "sonarr",
	} {
		got, found := downloadClientField(merged, name)
		if !found || got != want {
			t.Errorf("%s = %q, %t; want %q", name, got, found, want)
		}
	}
	if contentLayout, found := downloadClientField(merged, "contentLayout"); !found || contentLayout != "0" {
		t.Errorf("server-owned field lost: contentLayout=%q found=%t", contentLayout, found)
	}
}
