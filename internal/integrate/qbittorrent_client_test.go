package integrate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestQBTDownloadClientEndpointSeparatesHostAndPort(t *testing.T) {
	for _, test := range []struct {
		name string
		cfg  QBittorrentConfig
		host string
		port int
	}{
		{
			name: "complete Docker URL",
			cfg:  QBittorrentConfig{Host: "http://sdbx-gluetun:8080", Port: 8080},
			host: "sdbx-gluetun",
			port: 8080,
		},
		{
			name: "host with explicit port",
			cfg:  QBittorrentConfig{Host: "sdbx-qbittorrent:9090", Port: 8080},
			host: "sdbx-qbittorrent",
			port: 9090,
		},
		{
			name: "bare host",
			cfg:  QBittorrentConfig{Host: "sdbx-qbittorrent", Port: 8080},
			host: "sdbx-qbittorrent",
			port: 8080,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			host, port := qbtDownloadClientEndpoint(&test.cfg)
			if host != test.host || port != test.port {
				t.Fatalf("endpoint = %s:%d, want %s:%d", host, port, test.host, test.port)
			}
		})
	}
}

func TestQBittorrentClientUsesAuthenticatedV2APIContract(t *testing.T) {
	const (
		username      = "admin"
		password      = "synthetic-qbt-password"
		session       = "synthetic-session"
		sessionCookie = "QBT_SID_8080"
	)
	var requests []string
	autoTMMEnabled := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.Method+" "+request.URL.Path)
		switch request.URL.Path {
		case "/api/v2/auth/login":
			if request.Header.Get("Cookie") != "" {
				t.Errorf("login inherited an unrelated session cookie: %q", request.Header.Get("Cookie"))
			}
			if err := request.ParseForm(); err != nil {
				t.Errorf("parse login form: %v", err)
			}
			if request.Form.Get("username") != username || request.Form.Get("password") != password {
				t.Errorf("login form = %v", request.Form)
			}
			http.SetCookie(writer, &http.Cookie{Name: sessionCookie, Value: session, HttpOnly: true})
			writer.WriteHeader(http.StatusNoContent)
		case "/api/v2/app/version":
			if request.Header.Get("Cookie") != sessionCookie+"="+session {
				t.Errorf("health cookie = %q", request.Header.Get("Cookie"))
			}
			_, _ = writer.Write([]byte("5.0.0"))
		case "/api/v2/app/preferences":
			_ = json.NewEncoder(writer).Encode(map[string]any{"auto_tmm_enabled": autoTMMEnabled})
		case "/api/v2/app/setPreferences":
			if err := request.ParseForm(); err != nil {
				t.Errorf("parse preferences form: %v", err)
			}
			var preferences map[string]any
			if err := json.Unmarshal([]byte(request.Form.Get("json")), &preferences); err != nil {
				t.Errorf("decode preferences: %v", err)
			}
			if len(preferences) != 1 || preferences["auto_tmm_enabled"] != true {
				t.Errorf("preferences = %#v", preferences)
			}
			autoTMMEnabled = true
		case "/api/v2/torrents/createCategory":
			if request.Header.Get("Cookie") != sessionCookie+"="+session {
				t.Errorf("category cookie = %q", request.Header.Get("Cookie"))
			}
			if err := request.ParseForm(); err != nil {
				t.Errorf("parse category form: %v", err)
			}
			if request.Form.Get("category") != "sonarr" {
				t.Errorf("category form = %v", request.Form)
			}
		case "/api/v2/torrents/editCategory":
			if err := request.ParseForm(); err != nil {
				t.Errorf("parse edit category form: %v", err)
			}
			if request.Form.Get("category") != "sonarr" ||
				request.Form.Get("savePath") != "/downloads/tv" {
				t.Errorf("edit category form = %v", request.Form)
			}
		case "/api/v2/torrents/categories":
			_, _ = writer.Write([]byte(`{"sonarr":{"name":"sonarr","savePath":"/downloads/tv"}}`))
		case "/api/v2/torrents/info":
			if request.URL.Query().Get("category") != "sonarr" {
				t.Errorf("category query = %q", request.URL.RawQuery)
			}
			_, _ = writer.Write([]byte(`[{"name":"synthetic-title","category":"sonarr"}]`))
		default:
			http.Error(writer, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatal(err)
	}
	sharedHTTPClient := NewHTTPClient(time.Second, 0, 0)
	sharedHTTPClient.client.Jar.SetCookies(parsed, []*http.Cookie{{
		Name: sessionCookie, Value: "stale-shared-session",
	}})
	client := NewQBittorrentClient(
		sharedHTTPClient,
		&QBittorrentConfig{
			Host:     "http://" + parsed.Hostname(),
			Port:     port,
			Username: username,
			Password: password,
		},
	)
	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if err := client.CheckHealth(context.Background()); err != nil {
		t.Fatalf("CheckHealth failed: %v", err)
	}
	preferences, err := client.GetPreferences(context.Background())
	if err != nil || preferences["auto_tmm_enabled"] != false {
		t.Fatalf("GetPreferences = %#v, %v", preferences, err)
	}
	if err := client.SetPreferences(context.Background(), map[string]interface{}{
		"auto_tmm_enabled": true,
	}); err != nil {
		t.Fatalf("SetPreferences failed: %v", err)
	}
	if err := client.CreateCategory(context.Background(), "sonarr", ""); err != nil {
		t.Fatalf("CreateCategory failed: %v", err)
	}
	if err := client.EditCategory(context.Background(), "sonarr", "/downloads/tv"); err != nil {
		t.Fatalf("EditCategory failed: %v", err)
	}
	categories, err := client.GetCategories(context.Background())
	if err != nil || categories["sonarr"].SavePath != "/downloads/tv" {
		t.Fatalf("categories=%#v err=%v", categories, err)
	}
	count, err := client.CountTorrentsInCategory(context.Background(), "sonarr")
	if err != nil || count != 1 {
		t.Fatalf("category count=%d err=%v", count, err)
	}

	expected := []string{
		"POST /api/v2/auth/login",
		"GET /api/v2/app/version",
		"GET /api/v2/app/preferences",
		"POST /api/v2/app/setPreferences",
		"POST /api/v2/torrents/createCategory",
		"POST /api/v2/torrents/editCategory",
		"GET /api/v2/torrents/categories",
		"GET /api/v2/torrents/info",
	}
	if strings.Join(requests, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("requests = %v, want %v", requests, expected)
	}
}

func TestIsQBittorrentSessionCookie(t *testing.T) {
	for _, test := range []struct {
		name string
		want bool
	}{
		{name: "SID", want: true},
		{name: "QBT_SID_8080", want: true},
		{name: "QBT_SID_", want: false},
		{name: "QBT_SID_8080_attacker", want: false},
		{name: "unrelated", want: false},
	} {
		if got := isQBittorrentSessionCookie(test.name); got != test.want {
			t.Errorf("isQBittorrentSessionCookie(%q) = %t, want %t", test.name, got, test.want)
		}
	}
}
