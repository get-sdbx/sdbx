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

func TestProwlarrClientUsesAuthenticatedV1APIContract(t *testing.T) {
	const apiKey = "synthetic-prowlarr-api-key"
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Api-Key") != apiKey {
			t.Errorf("API key header = %q", request.Header.Get("X-Api-Key"))
		}
		requests = append(requests, request.Method+" "+request.URL.Path)
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/system/status":
			_, _ = writer.Write([]byte(`{"version":"test"}`))
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/applications":
			_, _ = writer.Write([]byte(`[{"id":11,"name":"Sonarr","implementation":"Sonarr"}]`))
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/applications":
			var submitted ProwlarrApplication
			if err := json.NewDecoder(request.Body).Decode(&submitted); err != nil {
				t.Errorf("decode submitted application: %v", err)
			}
			if submitted.Implementation != "Sonarr" ||
				submitted.SyncLevel != "fullSync" ||
				!submitted.Enable {
				t.Errorf("submitted application = %+v", submitted)
			}
			fields := make(map[string]any, len(submitted.Fields))
			for _, field := range submitted.Fields {
				fields[field.Name] = field.Value
			}
			if fields["prowlarrUrl"] != "http://sdbx-prowlarr:9696" ||
				fields["baseUrl"] != "http://sdbx-sonarr:8989" {
				t.Errorf("submitted stable URLs = %#v", fields)
			}
			_, _ = writer.Write([]byte(`{"id":12,"name":"sonarr","implementation":"Sonarr"}`))
		case request.Method == http.MethodPut && request.URL.Path == "/api/v1/applications/12":
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/applications/test":
			writer.WriteHeader(http.StatusOK)
		default:
			http.Error(writer, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewProwlarrClient(
		NewHTTPClient(time.Second, 0, 0),
		&ServiceConfig{Name: "prowlarr", URL: server.URL, APIKey: apiKey, Enabled: true},
	)
	if err := client.CheckHealth(context.Background()); err != nil {
		t.Fatalf("CheckHealth failed: %v", err)
	}
	applications, err := client.GetApplications(context.Background())
	if err != nil {
		t.Fatalf("GetApplications failed: %v", err)
	}
	if len(applications) != 1 || applications[0].ID != 11 {
		t.Fatalf("applications = %+v", applications)
	}
	created, err := client.AddApplication(
		context.Background(),
		CreateSonarrApplication(
			"sonarr",
			"http://sdbx-prowlarr:9696",
			"http://sdbx-sonarr:8989",
			"synthetic",
			"fullSync",
		),
	)
	if err != nil {
		t.Fatalf("AddApplication failed: %v", err)
	}
	if created.ID != 12 {
		t.Fatalf("created application = %+v", created)
	}
	if err := client.UpdateApplication(context.Background(), created); err != nil {
		t.Fatalf("UpdateApplication failed: %v", err)
	}
	if err := client.TestApplication(context.Background(), created); err != nil {
		t.Fatalf("TestApplication failed: %v", err)
	}

	expected := []string{
		"GET /api/v1/system/status",
		"GET /api/v1/applications",
		"POST /api/v1/applications",
		"PUT /api/v1/applications/12",
		"POST /api/v1/applications/test",
	}
	if strings.Join(requests, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("requests = %v, want %v", requests, expected)
	}
}

func TestCreateWhisparrApplicationMatchesUpstreamContract(t *testing.T) {
	application := CreateWhisparrApplication(
		"whisparr",
		"http://sdbx-prowlarr:9696",
		"http://sdbx-whisparr:6969",
		"synthetic-api-key",
		"fullSync",
	)
	if application.Implementation != "Whisparr" ||
		application.ConfigContract != "WhisparrSettings" {
		t.Fatalf("application contract = %#v", application)
	}
	fields := make(map[string]any, len(application.Fields))
	for _, field := range application.Fields {
		fields[field.Name] = field.Value
	}
	categories, ok := fields["syncCategories"].([]int)
	if !ok {
		t.Fatalf("syncCategories = %#v", fields["syncCategories"])
	}
	want := []int{6000, 6010, 6020, 6030, 6040, 6045, 6050, 6070, 6080, 6090}
	if len(categories) != len(want) {
		t.Fatalf("syncCategories = %#v, want %#v", categories, want)
	}
	for index := range want {
		if categories[index] != want[index] {
			t.Fatalf("syncCategories = %#v, want %#v", categories, want)
		}
	}
}

func TestIntegrateFlaresolverrCreatesAndVerifiesManagedProxy(t *testing.T) {
	const apiKey = "synthetic-prowlarr-api-key"
	created := false
	createCount := 0
	postSaveFailures := 1
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Api-Key") != apiKey {
			t.Errorf("API key header = %q", request.Header.Get("X-Api-Key"))
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/indexerProxy":
			if created {
				_, _ = writer.Write([]byte(`[{"id":7,"name":"FlareSolverr","implementation":"FlareSolverr","fields":[{"name":"host","value":"http://sdbx-flaresolverr:8191/"}]}]`))
				return
			}
			_, _ = writer.Write([]byte(`[]`))
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/indexerProxy/test":
			var submitted map[string]any
			if err := json.NewDecoder(request.Body).Decode(&submitted); err != nil {
				t.Fatal(err)
			}
			if managedMapField(submitted, "host") != "http://sdbx-flaresolverr:8191/" {
				t.Fatalf("FlareSolverr host = %#v", submitted)
			}
			if created && postSaveFailures > 0 {
				postSaveFailures--
				http.Error(writer, "proxy reload pending", http.StatusBadRequest)
				return
			}
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/indexerProxy":
			created = true
			createCount++
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	cfg.RetryAttempts = 1
	cfg.RetryDelay = 0
	cfg.Services = map[string]*ServiceConfig{
		"prowlarr": {
			Name: "prowlarr", URL: server.URL, APIKey: apiKey, Enabled: true,
		},
		"flaresolverr": {
			Name: "flaresolverr", URL: "http://sdbx-flaresolverr:8191", Enabled: true,
		},
	}
	integrator := NewIntegrator(cfg)
	result := integrator.integrateFlaresolverr(
		context.Background(),
		NewProwlarrClient(integrator.httpClient, cfg.Services["prowlarr"]),
	)
	if !result.Success || !created {
		t.Fatalf("result=%#v created=%t", result, created)
	}
	result = integrator.integrateFlaresolverr(
		context.Background(),
		NewProwlarrClient(integrator.httpClient, cfg.Services["prowlarr"]),
	)
	if !result.Success || !created || createCount != 1 {
		t.Fatalf("second result=%#v created=%t createCount=%d", result, created, createCount)
	}
}
