package integrate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/get-sdbx/sdbx/internal/config"
	sdbxsecrets "github.com/get-sdbx/sdbx/internal/secrets"
)

func TestReadPlexTokenAndRenderTautulliSettings(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigPath = t.TempDir()
	preferences := filepath.Join(
		cfg.ConfigPath,
		"plex",
		"Library",
		"Application Support",
		"Plex Media Server",
		"Preferences.xml",
	)
	if err := os.MkdirAll(filepath.Dir(preferences), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		preferences,
		[]byte(`<Preferences PlexOnlineToken="synthetic-plex-token" Other="preserved"/>`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	token, err := ReadPlexToken(cfg)
	if err != nil || token != "synthetic-plex-token" {
		t.Fatalf("token=%q err=%v", token, err)
	}
	body := []byte("[General]\nhttp_root = /tautulli\n\n[PMS]\npms_ip = old\npms_port = 1\npms_token = stale\npms_ssl = 1\n")
	updated, err := renderTautulliPMSConfig(body, token)
	if err != nil {
		t.Fatal(err)
	}
	text := string(updated)
	for _, expected := range []string{
		"http_root = /tautulli",
		"pms_ip = sdbx-plex",
		"pms_port = 32400",
		"pms_token = synthetic-plex-token",
		"pms_ssl = 0",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("rendered Tautulli settings missing %q", expected)
		}
	}
}

func TestMaintainerrDownloadClientDisablesDataDeletion(t *testing.T) {
	updated := false
	saveCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/settings/download-client":
			if updated {
				_ = json.NewEncoder(w).Encode(maintainerrDownloadSetting{
					URL: "http://sdbx-gluetun:8080", Username: "admin",
					Password: "current-qbt", DeleteData: false, FallbackRatio: 1.0,
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"download_client_url":            "http://old:8080",
				"download_client_username":       "admin",
				"download_client_password":       "stale",
				"download_client_delete_data":    true,
				"download_client_fallback_ratio": 1.0,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/settings/test/download-client":
			var body maintainerrDownloadSetting
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.URL != "http://sdbx-gluetun:8080" || body.Password != "current-qbt" || body.DeleteData {
				http.Error(w, "unsafe settings", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(maintainerrResult{Status: "OK", Code: 1})
		case r.Method == http.MethodPost && r.URL.Path == "/api/settings/download-client":
			updated = true
			saveCount++
			_ = json.NewEncoder(w).Encode(maintainerrResult{Status: "OK", Code: 1})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	cfg.RetryAttempts = 0
	cfg.Services = map[string]*ServiceConfig{
		"qbittorrent": {Name: "qbittorrent", URL: "http://sdbx-gluetun:8080", APIKey: "current-qbt", Enabled: true},
	}
	integrator := NewIntegrator(cfg)
	result := integrator.integrateMaintainerrDownloadClient(
		context.Background(),
		newMaintainerrClient(integrator.httpClient, &ServiceConfig{URL: server.URL}),
	)
	if !result.Success || !updated {
		t.Fatalf("result=%#v updated=%t", result, updated)
	}
	result = integrator.integrateMaintainerrDownloadClient(
		context.Background(),
		newMaintainerrClient(integrator.httpClient, &ServiceConfig{URL: server.URL}),
	)
	if !result.Success || saveCount != 1 {
		t.Fatalf("second result=%#v saveCount=%d", result, saveCount)
	}
}

func TestMaintainerrDownloadClientKeepsSafeSettingsWhenUpstreamCookieIsUnsupported(t *testing.T) {
	stored := maintainerrDownloadSetting{
		URL: "http://old:8080", Username: "admin", Password: "stale",
		DeleteData: true, FallbackRatio: 1.0,
	}
	saveCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/settings/download-client":
			_ = json.NewEncoder(w).Encode(stored)
		case r.Method == http.MethodPost && r.URL.Path == "/api/settings/test/download-client":
			_ = json.NewEncoder(w).Encode(maintainerrResult{
				Status: "NOK",
				Code:   0,
				Message: "The download client accepted the login but returned 403 Forbidden - a qBittorrent Web UI security restriction. " +
					"Use Bypass authentication for clients in whitelisted IP subnets.",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/settings/download-client":
			if err := json.NewDecoder(r.Body).Decode(&stored); err != nil {
				t.Fatal(err)
			}
			saveCount++
			_ = json.NewEncoder(w).Encode(maintainerrResult{Status: "OK", Code: 1})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	cfg.RetryAttempts = 0
	cfg.Services = map[string]*ServiceConfig{
		"qbittorrent": {Name: "qbittorrent", URL: "http://sdbx-gluetun:8080", APIKey: "current-qbt", Enabled: true},
	}
	integrator := NewIntegrator(cfg)
	client := newMaintainerrClient(integrator.httpClient, &ServiceConfig{URL: server.URL})
	result := integrator.integrateMaintainerrDownloadClient(context.Background(), client)
	if !result.Success || saveCount != 1 || stored.DeleteData ||
		!strings.Contains(result.Message, "cleanup unavailable") {
		t.Fatalf("result=%#v saveCount=%d stored=%#v", result, saveCount, stored)
	}
	result = integrator.integrateMaintainerrDownloadClient(context.Background(), client)
	if !result.Success || saveCount != 1 {
		t.Fatalf("second result=%#v saveCount=%d", result, saveCount)
	}
}

func TestProfilarrCreatesAndVerifiesManagedInstances(t *testing.T) {
	created := map[string]bool{}
	createCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/arr":
			instances := make([]map[string]any, 0, 2)
			id := 1
			for _, kind := range []string{"radarr", "sonarr"} {
				if created[kind] {
					instances = append(instances, map[string]any{
						"id": id, "name": strings.ToUpper(kind[:1]) + kind[1:], "type": kind,
						"url":     "http://sdbx-" + kind + map[string]string{"radarr": ":7878/radarr", "sonarr": ":8989/sonarr"}[kind],
						"enabled": 1, "library_refresh_interval": 0,
					})
					id++
				}
			}
			_ = json.NewEncoder(w).Encode(instances)
		case r.Method == http.MethodPost && r.URL.Path == "/arr/validate":
			_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
		case r.Method == http.MethodPost && r.URL.Path == "/arr/new":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			created[r.Form.Get("type")] = true
			createCount++
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/logs"):
			_ = json.NewEncoder(w).Encode(map[string]any{"records": []any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	cfg.RetryAttempts = 0
	cfg.Services = map[string]*ServiceConfig{
		"profilarr": {Name: "profilarr", URL: server.URL, Enabled: true},
		"radarr":    {Name: "radarr", URL: "http://sdbx-radarr:7878/radarr", APIKey: "radarr-key", Enabled: true},
		"sonarr":    {Name: "sonarr", URL: "http://sdbx-sonarr:8989/sonarr", APIKey: "sonarr-key", Enabled: true},
	}
	integrator := NewIntegrator(cfg)
	results := integrator.integrateProfilarr(context.Background())
	if len(results) != 2 || !results[0].Success || !results[1].Success || !created["radarr"] || !created["sonarr"] {
		t.Fatalf("results=%#v created=%v", results, created)
	}
	results = integrator.integrateProfilarr(context.Background())
	if len(results) != 2 || !results[0].Success || !results[1].Success || createCount != 2 {
		t.Fatalf("second results=%#v createCount=%d", results, createCount)
	}
}

func TestQuiRotatesCredentialAndRepairsManagedInstance(t *testing.T) {
	password := "old-synthetic-password"
	instancePassword := "stale"
	instanceHost := "http://old:8080"
	passwordChanges := 0
	instanceUpdates := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/auth/check-setup":
			_ = json.NewEncoder(w).Encode(quiSetupState{SetupRequired: false})
		case r.Method == http.MethodPost && r.URL.Path == "/api/auth/login":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["password"] != password {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "user_session", Value: "synthetic", Path: "/"})
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "ok"})
		case r.Method == http.MethodPut && r.URL.Path == "/api/auth/change-password":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["currentPassword"] != password {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			password = body["newPassword"]
			passwordChanges++
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/api/instances":
			// Qui's cached activity telemetry may remain false after a successful
			// connection. The explicit instance test is the authoritative probe.
			_ = json.NewEncoder(w).Encode([]quiInstance{{ID: 1, Name: "sdbx-qbittorrent", Host: instanceHost, Username: "admin", Active: false, Connected: false}})
		case r.Method == http.MethodPut && r.URL.Path == "/api/instances/1":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			instancePassword, _ = body["password"].(string)
			instanceHost, _ = body["host"].(string)
			instanceUpdates++
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/instances/1/test":
			if instancePassword != "current-qbt" {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "qui_admin_password.txt"), []byte(password), 0o600); err != nil {
		t.Fatal(err)
	}
	project := config.DefaultConfig()
	project.SecretsPath = root
	project.PUID, project.PGID = os.Getuid(), os.Getgid()
	cfg := DefaultConfig()
	cfg.ProjectConfig = project
	cfg.RotateCredentials = true
	cfg.Timeout = time.Second
	cfg.RetryAttempts = 0
	cfg.Services = map[string]*ServiceConfig{
		"qui":         {Name: "qui", URL: server.URL, Enabled: true},
		"qbittorrent": {Name: "qbittorrent", URL: "http://sdbx-gluetun:8080", APIKey: "current-qbt", Enabled: true},
	}
	results := NewIntegrator(cfg).integrateQui(context.Background())
	if len(results) != 2 || !results[0].Success || !results[1].Success || instancePassword != "current-qbt" {
		t.Fatalf("results=%#v instancePasswordUpdated=%t", results, instancePassword == "current-qbt")
	}
	stored, err := sdbxsecrets.ReadSecret(root, "qui_admin_password.txt")
	if err != nil || stored != password || stored == "old-synthetic-password" {
		t.Fatalf("rotated credential was not persisted safely: err=%v", err)
	}
	cfg.RotateCredentials = false
	results = NewIntegrator(cfg).integrateQui(context.Background())
	if len(results) != 2 || !results[0].Success || !results[1].Success ||
		passwordChanges != 1 || instanceUpdates != 1 {
		t.Fatalf(
			"second results=%#v passwordChanges=%d instanceUpdates=%d",
			results,
			passwordChanges,
			instanceUpdates,
		)
	}
}

func TestQuiRestoresApplicationAndSecretWhenRotatedLoginFails(t *testing.T) {
	password := "old-synthetic-password"
	rejectNextLogin := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/auth/check-setup":
			_ = json.NewEncoder(w).Encode(quiSetupState{SetupRequired: false})
		case r.Method == http.MethodPost && r.URL.Path == "/api/auth/login":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if rejectNextLogin {
				rejectNextLogin = false
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if body["password"] != password {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "user_session", Value: "synthetic", Path: "/"})
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && r.URL.Path == "/api/auth/change-password":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["currentPassword"] != password {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			password = body["newPassword"]
			if password != "old-synthetic-password" {
				rejectNextLogin = true
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "qui_admin_password.txt"), []byte(password), 0o600); err != nil {
		t.Fatal(err)
	}
	project := config.DefaultConfig()
	project.SecretsPath = root
	project.PUID, project.PGID = os.Getuid(), os.Getgid()
	cfg := DefaultConfig()
	cfg.ProjectConfig = project
	cfg.RotateCredentials = true
	cfg.Timeout = time.Second
	cfg.RetryAttempts = 0
	cfg.Services = map[string]*ServiceConfig{
		"qui": {Name: "qui", URL: server.URL, Enabled: true},
	}
	results := NewIntegrator(cfg).integrateQui(context.Background())
	if len(results) != 1 || results[0].Success {
		t.Fatalf("results=%#v", results)
	}
	stored, err := sdbxsecrets.ReadSecret(root, "qui_admin_password.txt")
	if err != nil || stored != "old-synthetic-password" || password != stored {
		t.Fatalf("rollback mismatch: err=%v appMatchesSecret=%t", err, password == stored)
	}
}

func TestWizarrRotationUsesPrivateManagedSecretAndVerifiedPlex(t *testing.T) {
	plex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/identity" || r.Header.Get("X-Plex-Token") != "synthetic-plex-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer plex.Close()
	project := config.DefaultConfig()
	project.SecretsPath = t.TempDir()
	project.PUID, project.PGID = os.Getuid(), os.Getgid()
	cfg := DefaultConfig()
	cfg.ProjectConfig = project
	cfg.RotateCredentials = true
	cfg.Timeout = time.Second
	cfg.RetryAttempts = 0
	cfg.Services = map[string]*ServiceConfig{
		"plex":   {Name: "plex", URL: "http://sdbx-plex:32400", ControlURL: plex.URL, APIKey: "synthetic-plex-token", Enabled: true},
		"wizarr": {Name: "wizarr", URL: "http://sdbx-wizarr:5690", Enabled: true},
	}
	integrator := NewIntegrator(cfg)
	calls := 0
	integrator.wizarrReconcile = func(_ context.Context, password, token string, apply bool) error {
		if password == "" || token != "synthetic-plex-token" {
			t.Fatal("missing managed reconciliation input")
		}
		calls++
		return nil
	}
	result := integrator.integrateWizarr(context.Background())
	if !result.Success || calls != 2 {
		t.Fatalf("result=%#v calls=%d", result, calls)
	}
	info, err := os.Stat(filepath.Join(project.SecretsPath, "wizarr_admin_password.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("Wizarr recovery secret mode = %v", info.Mode().Perm())
	}
	cfg.RotateCredentials = false
	result = integrator.integrateWizarr(context.Background())
	if !result.Success || calls != 3 {
		t.Fatalf("second result=%#v calls=%d", result, calls)
	}
}

func TestWizarrTreatsLostExecOutputAsSuccessAfterVerifiedCommit(t *testing.T) {
	plex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer plex.Close()
	project := config.DefaultConfig()
	project.SecretsPath = t.TempDir()
	project.PUID, project.PGID = os.Getuid(), os.Getgid()
	cfg := DefaultConfig()
	cfg.ProjectConfig = project
	cfg.RotateCredentials = true
	cfg.Timeout = time.Second
	cfg.RetryAttempts = 0
	cfg.Services = map[string]*ServiceConfig{
		"plex":   {Name: "plex", URL: "http://sdbx-plex:32400", ControlURL: plex.URL, APIKey: "synthetic-plex-token", Enabled: true},
		"wizarr": {Name: "wizarr", URL: "http://sdbx-wizarr:5690", Enabled: true},
	}
	integrator := NewIntegrator(cfg)
	calls := 0
	integrator.wizarrReconcile = func(_ context.Context, _, _ string, apply bool) error {
		calls++
		if apply {
			return context.DeadlineExceeded
		}
		return nil
	}
	result := integrator.integrateWizarr(context.Background())
	if !result.Success || calls != 2 {
		t.Fatalf("result=%#v calls=%d", result, calls)
	}
}

func TestWizarrRestoresPreviousCredentialAfterFailedRotation(t *testing.T) {
	plex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer plex.Close()
	project := config.DefaultConfig()
	project.SecretsPath = t.TempDir()
	project.PUID, project.PGID = os.Getuid(), os.Getgid()
	const previous = "old-synthetic-password"
	if err := os.WriteFile(
		filepath.Join(project.SecretsPath, "wizarr_admin_password.txt"),
		[]byte(previous),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.ProjectConfig = project
	cfg.RotateCredentials = true
	cfg.Timeout = time.Second
	cfg.RetryAttempts = 0
	cfg.Services = map[string]*ServiceConfig{
		"plex":   {Name: "plex", URL: "http://sdbx-plex:32400", ControlURL: plex.URL, APIKey: "synthetic-plex-token", Enabled: true},
		"wizarr": {Name: "wizarr", URL: "http://sdbx-wizarr:5690", Enabled: true},
	}
	integrator := NewIntegrator(cfg)
	rollbackApplied := false
	integrator.wizarrReconcile = func(_ context.Context, password, _ string, apply bool) error {
		if apply && password == previous {
			rollbackApplied = true
			return nil
		}
		return context.DeadlineExceeded
	}
	result := integrator.integrateWizarr(context.Background())
	if result.Success || !rollbackApplied {
		t.Fatalf("result=%#v rollbackApplied=%t", result, rollbackApplied)
	}
	stored, err := sdbxsecrets.ReadSecret(project.SecretsPath, "wizarr_admin_password.txt")
	if err != nil || stored != previous {
		t.Fatalf("previous secret was not restored: err=%v", err)
	}
}
