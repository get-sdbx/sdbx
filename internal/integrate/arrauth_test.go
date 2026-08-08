package integrate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/get-sdbx/sdbx/internal/config"
	sdbxsecrets "github.com/get-sdbx/sdbx/internal/secrets"
)

type arrAuthTestState struct {
	mu       sync.Mutex
	method   string
	required string
	username string
	password string
	putCount int
}

func TestEnsureArrNativeAuthenticationReconcilesAndVerifiesCredential(t *testing.T) {
	for _, spec := range arrManagedAuthSpecs {
		t.Run(spec.name, func(t *testing.T) {
			state := &arrAuthTestState{
				method:   "external",
				required: "disabledForLocalAddresses",
			}
			apiKey := "synthetic-api-key"
			server := newArrAuthTestServer(t, spec.apiVersion, apiKey, state)
			defer server.Close()

			project := config.DefaultConfig()
			project.SecretsPath = filepath.Join(t.TempDir(), "secrets")
			integrationConfig := DefaultConfig()
			integrationConfig.ProjectConfig = project
			integrationConfig.Timeout = time.Second
			integrationConfig.RetryAttempts = 0
			integrator := NewIntegrator(integrationConfig)
			service := &ServiceConfig{
				Name:       spec.name,
				URL:        server.URL,
				ControlURL: server.URL,
				APIKey:     apiKey,
				Enabled:    true,
			}

			action, err := integrator.ensureArrNativeAuthentication(
				context.Background(),
				spec,
				service,
			)
			if err != nil {
				t.Fatal(err)
			}
			if action != "reconciled" {
				t.Fatalf("action = %q, want reconciled", action)
			}

			password, err := sdbxsecrets.ReadSecret(
				project.SecretsPath,
				spec.secretFile,
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(password) != 24 {
				t.Fatalf("managed password length = %d, want 24", len(password))
			}
			info, err := os.Stat(filepath.Join(project.SecretsPath, spec.secretFile))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("managed password mode = %o, want 600", info.Mode().Perm())
			}

			state.mu.Lock()
			if state.method != "forms" ||
				state.required != "enabled" ||
				state.username != arrManagedAdminUsername ||
				state.password != password ||
				state.putCount != 1 {
				t.Fatalf("reconciled state = %#v", state)
			}
			state.mu.Unlock()

			action, err = integrator.ensureArrNativeAuthentication(
				context.Background(),
				spec,
				service,
			)
			if err != nil {
				t.Fatal(err)
			}
			if action != "kept" {
				t.Fatalf("second action = %q, want kept", action)
			}
			state.mu.Lock()
			putCount := state.putCount
			state.mu.Unlock()
			if putCount != 1 {
				t.Fatalf("idempotent pass performed %d PUTs", putCount)
			}
		})
	}
}

func TestEnsureArrNativeAuthenticationRepairsCredentialDrift(t *testing.T) {
	spec := arrManagedAuthSpecs[0]
	state := &arrAuthTestState{
		method:   "forms",
		required: "enabled",
		username: arrManagedAdminUsername,
		password: "changed-outside-sdbx",
	}
	server := newArrAuthTestServer(t, spec.apiVersion, "api-key", state)
	defer server.Close()

	project := config.DefaultConfig()
	project.SecretsPath = filepath.Join(t.TempDir(), "secrets")
	if err := os.MkdirAll(project.SecretsPath, 0o700); err != nil {
		t.Fatal(err)
	}
	const managed = "managed-password-value"
	if err := os.WriteFile(
		filepath.Join(project.SecretsPath, spec.secretFile),
		[]byte(managed),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	integrationConfig := DefaultConfig()
	integrationConfig.ProjectConfig = project
	integrationConfig.Timeout = time.Second
	integrationConfig.RetryAttempts = 0
	integrator := NewIntegrator(integrationConfig)

	action, err := integrator.ensureArrNativeAuthentication(
		context.Background(),
		spec,
		&ServiceConfig{
			Name:       spec.name,
			URL:        server.URL,
			ControlURL: server.URL,
			APIKey:     "api-key",
			Enabled:    true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if action != "reconciled" {
		t.Fatalf("action = %q, want reconciled", action)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.password != managed || state.putCount != 1 {
		t.Fatalf("credential drift was not repaired: %#v", state)
	}
}

func TestEnsureArrNativeAuthenticationRotatesCredentialTransactionally(t *testing.T) {
	spec := arrManagedAuthSpecs[0]
	const previous = "previous-managed-password"
	state := &arrAuthTestState{
		method:   "forms",
		required: "enabled",
		username: arrManagedAdminUsername,
		password: previous,
	}
	server := newArrAuthTestServer(t, spec.apiVersion, "api-key", state)
	defer server.Close()

	project := config.DefaultConfig()
	project.SecretsPath = filepath.Join(t.TempDir(), "secrets")
	if err := os.MkdirAll(project.SecretsPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(project.SecretsPath, spec.secretFile),
		[]byte(previous),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	integrationConfig := DefaultConfig()
	integrationConfig.ProjectConfig = project
	integrationConfig.Timeout = time.Second
	integrationConfig.RetryAttempts = 0
	integrationConfig.RotateCredentials = true
	integrator := NewIntegrator(integrationConfig)

	action, err := integrator.ensureArrNativeAuthentication(
		context.Background(),
		spec,
		&ServiceConfig{
			Name:       spec.name,
			URL:        server.URL,
			ControlURL: server.URL,
			APIKey:     "api-key",
			Enabled:    true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if action != "rotated" {
		t.Fatalf("action = %q, want rotated", action)
	}
	rotated, err := sdbxsecrets.ReadSecret(project.SecretsPath, spec.secretFile)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == previous || len(rotated) != 24 {
		t.Fatalf("rotated credential length=%d unchanged=%t", len(rotated), rotated == previous)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.password != rotated || state.putCount != 1 {
		t.Fatalf("rotated state did not match persisted credential")
	}
}

func TestVerifyArrFormsCredentialRejectsCrossOriginRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			http.Redirect(
				writer,
				request,
				"https://example.invalid/",
				http.StatusFound,
			)
		},
	))
	defer server.Close()

	valid, err := verifyArrFormsCredential(
		context.Background(),
		server.URL,
		"user",
		"password",
		time.Second,
	)
	if err == nil || valid {
		t.Fatalf("cross-origin redirect valid=%t err=%v", valid, err)
	}
}

func newArrAuthTestServer(
	t *testing.T,
	apiVersion, apiKey string,
	state *arrAuthTestState,
) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	hostConfigPath := "/api/" + apiVersion + "/config/host"
	mux.HandleFunc(hostConfigPath, func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Api-Key") != apiKey {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		state.mu.Lock()
		defer state.mu.Unlock()
		switch request.Method {
		case http.MethodGet:
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"id":                     1,
				"authenticationMethod":   state.method,
				"authenticationRequired": state.required,
				"username":               state.username,
				"password":               "********",
				"bindAddress":            "*",
				"port":                   8989,
			})
		case http.MethodPut:
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				http.Error(writer, "bad body", http.StatusBadRequest)
				return
			}
			state.method, _ = body["authenticationMethod"].(string)
			state.required, _ = body["authenticationRequired"].(string)
			state.username, _ = body["username"].(string)
			state.password, _ = body["password"].(string)
			state.putCount++
			writer.WriteHeader(http.StatusAccepted)
		default:
			writer.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/login", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			writer.WriteHeader(http.StatusOK)
			return
		}
		if err := request.ParseForm(); err != nil {
			http.Error(writer, "bad form", http.StatusBadRequest)
			return
		}
		state.mu.Lock()
		valid := state.method == "forms" &&
			state.required == "enabled" &&
			request.Form.Get("username") == state.username &&
			request.Form.Get("password") == state.password
		state.mu.Unlock()
		if !valid {
			http.Redirect(writer, request, "/login?returnUrl=%2F", http.StatusFound)
			return
		}
		http.SetCookie(writer, &http.Cookie{
			Name:     "arr-session",
			Value:    "valid",
			Path:     "/",
			HttpOnly: true,
		})
		http.Redirect(writer, request, "/", http.StatusFound)
	})
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie("arr-session")
		if err != nil || cookie.Value != "valid" {
			http.Redirect(writer, request, "/login?returnUrl=%2F", http.StatusFound)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})
	return httptest.NewServer(mux)
}
