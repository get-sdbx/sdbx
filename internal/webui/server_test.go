package webui

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/backup"
	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/generator"
	"github.com/get-sdbx/sdbx/internal/management"
	"github.com/get-sdbx/sdbx/internal/registry"
)

const webUITestBackupPassphrase = "webui test backup passphrase"
const webUITestVersion = "test"

func TestDecodeJSONBodyRejectsUnboundedOrAmbiguousInput(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{
			name:        "wrong content type",
			contentType: "text/plain",
			body:        `{"value":"ok"}`,
		},
		{
			name:        "unknown field",
			contentType: "application/json",
			body:        `{"value":"ok","unexpected":"no"}`,
		},
		{
			name:        "trailing object",
			contentType: "application/json",
			body:        `{"value":"ok"}{"value":"again"}`,
		},
		{
			name:        "oversized body",
			contentType: "application/json",
			body:        `{"value":"` + strings.Repeat("x", maxAPIRequestBytes) + `"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPost,
				"/api/test",
				strings.NewReader(test.body),
			)
			request.Header.Set("Content-Type", test.contentType)
			recorder := httptest.NewRecorder()
			var target struct {
				Value string `json:"value"`
			}
			if err := decodeJSONBody(recorder, request, &target); err == nil {
				t.Fatal("unsafe JSON request body was accepted")
			}
		})
	}
}

func TestIndexDoesNotDiscloseToken(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if body := rec.Body.String(); strings.Contains(body, "test-token") ||
		strings.Contains(body, `name="sdbx-token"`) {
		t.Fatalf("unauthenticated index disclosed the console token")
	}
	if body := rec.Body.String(); strings.Contains(body, "38 embedded addons") ||
		!strings.Contains(body, `placeholder="Search addons"`) {
		t.Fatalf("index contains a stale catalog-size placeholder")
	}
	if body := rec.Body.String(); strings.Contains(body, "{{") ||
		!strings.Contains(body, `src="/static/app.js"`) {
		t.Fatalf("index was not served as the exact root-mounted document")
	}
}

func TestStaticAssetsUseAnExactPublicAllowlist(t *testing.T) {
	server := testServer(t)
	tests := []struct {
		path        string
		wantStatus  int
		contentType string
	}{
		{
			path:        "/static/app.js",
			wantStatus:  http.StatusOK,
			contentType: "text/javascript; charset=utf-8",
		},
		{
			path:        "/static/styles.css",
			wantStatus:  http.StatusOK,
			contentType: "text/css; charset=utf-8",
		},
		{
			path:        "/static/favicon.svg",
			wantStatus:  http.StatusOK,
			contentType: "image/svg+xml",
		},
		{path: "/static/index.html", wantStatus: http.StatusNotFound},
		{path: "/static/", wantStatus: http.StatusNotFound},
		{path: "/static/nested/app.js", wantStatus: http.StatusNotFound},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			recorder := httptest.NewRecorder()
			serveTestRequest(server, recorder, request)

			if recorder.Code != test.wantStatus {
				t.Fatalf(
					"status = %d, want %d: %s",
					recorder.Code,
					test.wantStatus,
					recorder.Body.String(),
				)
			}
			if test.contentType != "" {
				if got := recorder.Header().Get("Content-Type"); got != test.contentType {
					t.Fatalf("Content-Type = %q, want %q", got, test.contentType)
				}
				if recorder.Body.Len() == 0 {
					t.Fatal("allowlisted asset response is empty")
				}
			}
			if strings.Contains(recorder.Body.String(), "<title>SDBX Dashboard</title>") {
				t.Fatal("static asset route exposed the management index")
			}
		})
	}
}

func TestWebUIIsRootMountedOnly(t *testing.T) {
	server := testServer(t)
	for _, path := range []string{"/admin", "/admin/", "/nested/api/summary"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		recorder := httptest.NewRecorder()
		serveTestRequest(server, recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, recorder.Code)
		}
	}

	app, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	index, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{
		"app.js":     string(app),
		"index.html": string(index),
	} {
		if strings.Contains(source, "sdbx-base-path") ||
			strings.Contains(source, "SDBX_BASE_PATH") ||
			strings.Contains(source, "{{ .BasePath }}") {
			t.Fatalf("%s retains the retired base-path console mode", name)
		}
	}
}

func TestWebUICopyAvoidsInternalArchitectureJargon(t *testing.T) {
	for _, asset := range []string{"static/index.html", "static/app.js"} {
		source, err := staticFS.ReadFile(asset)
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(source))
		for _, rejected := range []string{
			"mothership",
			"typed broker",
			"broker mediated",
			"locked services",
			"locked seedbox graph",
			"verified graph",
			"bounded daemon output",
			"transactional regeneration",
		} {
			if strings.Contains(lower, rejected) {
				t.Fatalf("%s contains user-facing architecture jargon %q", asset, rejected)
			}
		}
	}
}

func TestWriteJSONEncodesBeforeCommittingResponse(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeJSON(
		recorder,
		http.StatusAccepted,
		map[string]any{"unsupported": make(chan struct{})},
	)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf(
			"status = %d, want %d",
			recorder.Code,
			http.StatusInternalServerError,
		)
	}
	var payload map[string]string
	decoder := json.NewDecoder(recorder.Body)
	if err := decoder.Decode(&payload); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if payload["code"] != "response_encoding_failed" {
		t.Fatalf("response payload = %#v", payload)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("response contains a second JSON document: %v", err)
	}
}

func TestWebUIRestrictsDynamicServiceRoutesToHTTPS(t *testing.T) {
	asset, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(asset)
	for _, required := range []string{
		"function safeRouteURL(value)",
		`return route.protocol === "https:" ? route.href : "";`,
		"const route = safeRouteURL(service.route);",
		"service.launcher?.enabled && safeRouteURL(service.route)",
		`data-nav="services"`,
		`href="${escapeHTML(route)}"`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("web UI is missing route-safety contract %q", required)
		}
	}
	if strings.Contains(source, `href="${escapeHTML(service.route)}"`) {
		t.Fatal("web UI writes an unvalidated service route into an href")
	}
}

func TestWebUIBootstrapsTokenFromURLFragmentOnly(t *testing.T) {
	asset, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(asset)
	for _, required := range []string{
		`new URLSearchParams(location.hash.slice(1))`,
		`sessionStorage.setItem(tokenStorageKey, supplied)`,
		`history.replaceState(null, "",`,
		`headers["X-SDBX-Token"] = token`,
		`sessionStorage.removeItem(tokenStorageKey)`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("web UI is missing out-of-band token contract %q", required)
		}
	}
	if strings.Contains(source, `meta[name="sdbx-token"]`) {
		t.Fatal("web UI still reads a token from unauthenticated HTML")
	}
}

func TestWebUIRequiresDistinctVPNDisableAcknowledgement(t *testing.T) {
	appAsset, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	indexAsset, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	app := string(appAsset)
	index := string(indexAsset)

	for _, required := range []string{
		`options.requireUnprotectedDownloads === true`,
		`!requiresUnprotectedDownloads || unprotectedInput.checked`,
		`confirmUnprotectedDownloads: decision.confirmUnprotectedDownloads`,
		`unprotectedInput.checked = false`,
	} {
		if !strings.Contains(app, required) {
			t.Fatalf("web UI is missing VPN-disable acknowledgement contract %q", required)
		}
	}
	if strings.Contains(
		app,
		`confirmUnprotectedDownloads: key === "vpn_enabled" && value === "false"`,
	) {
		t.Fatal("web UI still derives VPN-disable acknowledgement from the setting value")
	}
	for _, required := range []string{
		`id="impact-unprotected-input" type="checkbox"`,
		`torrent traffic may use the host public IP`,
		`It is never selected automatically.`,
	} {
		if !strings.Contains(index, required) {
			t.Fatalf("web UI is missing informed VPN-disable copy %q", required)
		}
	}
}

func TestMutatingRoutesRequireToken(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/actions/restart", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("Origin", "http://127.0.0.1")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestReadRoutesRequireOutOfBandTokenDespiteForgedOrigin(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/summary", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("Origin", "http://127.0.0.1")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if strings.Contains(rec.Body.String(), `"totalServices"`) {
		t.Fatalf("unauthenticated read disclosed management data: %s", rec.Body.String())
	}
}

func TestRemoteReadRequiresVerifiedTraefikCertificateAndAutheliaAdmin(t *testing.T) {
	operator := &readContractOperator{}
	server, err := New(Options{
		Operator:   operator,
		Token:      "test-token",
		PublicHost: "sdbx.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	newRequest := func() *http.Request {
		request := httptest.NewRequest(http.MethodGet, "https://sdbx.example.test/api/summary", nil)
		request.Host = "sdbx.example.test"
		request.Header.Set("Remote-User", "operator")
		request.Header.Set("Remote-Groups", "users, admins")
		request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{
			DNSNames: []string{"sdbx-traefik"},
		}}}}
		return request
	}

	authorized := httptest.NewRecorder()
	server.Handler().ServeHTTP(authorized, newRequest())
	if authorized.Code != http.StatusOK || !strings.Contains(authorized.Body.String(), `"projectId":"contract-test"`) {
		t.Fatalf("authorized remote response = %d %s", authorized.Code, authorized.Body.String())
	}

	forged := newRequest()
	forged.TLS = nil
	forgedRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(forgedRecorder, forged)
	if forgedRecorder.Code != http.StatusMisdirectedRequest || strings.Contains(forgedRecorder.Body.String(), "projectId") {
		t.Fatalf("forged proxy headers response = %d %s", forgedRecorder.Code, forgedRecorder.Body.String())
	}

	nonAdmin := newRequest()
	nonAdmin.Header.Set("Remote-Groups", "users")
	nonAdminRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(nonAdminRecorder, nonAdmin)
	if nonAdminRecorder.Code != http.StatusMisdirectedRequest || strings.Contains(nonAdminRecorder.Body.String(), "projectId") {
		t.Fatalf("non-admin remote response = %d %s", nonAdminRecorder.Code, nonAdminRecorder.Body.String())
	}
}

func TestRejectsNonLoopbackHostAndCrossOriginMutation(t *testing.T) {
	server := testServer(t)

	hostRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	hostRequest.Host = "attacker.example"
	hostRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(hostRecorder, hostRequest)
	if hostRecorder.Code != http.StatusMisdirectedRequest {
		t.Fatalf("non-loopback host status = %d", hostRecorder.Code)
	}

	originRequest := httptest.NewRequest(http.MethodPost, "/api/actions/restart", nil)
	originRequest.Host = "127.0.0.1"
	originRequest.Header.Set("Origin", "https://attacker.example")
	originRequest.Header.Set("Sec-Fetch-Site", "cross-site")
	originRequest.Header.Set("X-SDBX-Token", "test-token")
	originRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(originRecorder, originRequest)
	if originRecorder.Code != http.StatusForbidden {
		t.Fatalf("cross-origin mutation status = %d", originRecorder.Code)
	}
}

func TestSecurityHeadersAreSet(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()
	serveTestRequest(server, recorder, request)

	for _, header := range []string{
		"Content-Security-Policy",
		"Cross-Origin-Opener-Policy",
		"Permissions-Policy",
		"Referrer-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
	} {
		if recorder.Header().Get(header) == "" {
			t.Fatalf("security header %s is missing", header)
		}
	}
}

func TestSummaryDoesNotRequireDocker(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/summary", nil)
	rec := httptest.NewRecorder()

	serveTestRequest(server, rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"totalServices":3`) {
		t.Fatalf("summary did not use active graph: %s", rec.Body.String())
	}
}

type secretLogOperator struct {
	management.Operator
}

func (secretLogOperator) Logs(
	context.Context,
	management.LogsRequest,
) (*management.LogsResult, error) {
	return &management.LogsResult{
		Service: "synthetic",
		Logs:    "startup password=WEB_LOG_SECRET_CANARY\nready\n",
	}, nil
}

type readContractOperator struct {
	management.Operator
	logsRequest management.LogsRequest
	auditLimit  int
}

func (o *readContractOperator) Preview(
	_ context.Context,
	request management.ImpactRequest,
) (*management.Impact, error) {
	return &management.Impact{
		Operation:    request.Operation,
		Title:        "Synthetic impact",
		Consequences: []string{"One bounded operation"},
		Confirmation: request.Operation,
	}, nil
}

func (*readContractOperator) Summary(context.Context) (*management.Summary, error) {
	return &management.Summary{ProjectID: "contract-test", TotalServices: 1}, nil
}

func (*readContractOperator) Security(context.Context) (*management.SecurityReport, error) {
	return &management.SecurityReport{ProjectVerified: true, ImmutableImages: 1}, nil
}

func (*readContractOperator) Diagnostics(context.Context) (*management.DiagnosticsReport, error) {
	return &management.DiagnosticsReport{
		Healthy: true,
		Summary: management.DiagnosticsSummary{Total: 1, Passed: 1},
	}, nil
}

func (*readContractOperator) Services(context.Context) ([]management.Service, error) {
	return []management.Service{{
		Name:        "plex",
		Description: "Synthetic media server",
		Category:    "media",
		Route:       "https://plex.media.example.test/",
		RouteAuth:   "native-auth",
		Launcher: &management.ServiceLauncher{
			Enabled:  true,
			Group:    "media",
			Icon:     "plex",
			Subtitle: "Media server",
		},
		Status:  "running",
		Running: true,
	}}, nil
}

func (o *readContractOperator) Logs(
	_ context.Context,
	request management.LogsRequest,
) (*management.LogsResult, error) {
	o.logsRequest = request
	return &management.LogsResult{
		Service: request.Service,
		Logs:    "ready password=READ_CONTRACT_SECRET_CANARY\n",
	}, nil
}

func (*readContractOperator) Addons(context.Context) ([]management.Addon, error) {
	return []management.Addon{{Name: "sonarr", Enabled: true}}, nil
}

func (*readContractOperator) Settings(context.Context) (*management.Settings, error) {
	return &management.Settings{
		Values:    map[string]any{"domain": "media.example.test"},
		ValidKeys: []string{"domain"},
	}, nil
}

func (*readContractOperator) Backups(context.Context) ([]management.Backup, error) {
	return []management.Backup{{Name: "synthetic.tar.gz.age", Size: 42}}, nil
}

func (o *readContractOperator) Audit(
	_ context.Context,
	limit int,
) ([]management.AuditEvent, error) {
	o.auditLimit = limit
	return []management.AuditEvent{{
		RequestID: "request-1",
		Operation: "summary",
		Method:    http.MethodGet,
		Path:      "/v1/summary",
		Outcome:   "success",
	}}, nil
}

func TestReadEndpointsExposeBoundedTypedContracts(t *testing.T) {
	operator := &readContractOperator{}
	server, err := New(Options{Operator: operator, Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		path string
		want string
	}{
		{path: "/api/impact?operation=restart", want: `"operation":"restart"`},
		{path: "/api/summary", want: `"projectId":"contract-test"`},
		{path: "/api/security", want: `"immutableImages":1`},
		{path: "/api/diagnostics", want: `"healthy":true`},
		{path: "/api/audit?limit=999", want: `"requestId":"request-1"`},
		{path: "/api/status", want: `"launcher":{"enabled":true,"group":"media","icon":"plex","subtitle":"Media server"}`},
		{path: "/api/logs?service=plex&tail=9999", want: `"service":"plex"`},
		{path: "/api/addons", want: `"name":"sonarr"`},
		{path: "/api/config", want: `"domain":"media.example.test"`},
		{path: "/api/backups", want: `"name":"synthetic.tar.gz.age"`},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			recorder := httptest.NewRecorder()
			serveTestRequest(server, recorder, request)

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
			}
			if body := recorder.Body.String(); !strings.Contains(body, test.want) {
				t.Fatalf("response missing %q: %s", test.want, body)
			}
		})
	}
	if operator.logsRequest.Service != "plex" || operator.logsRequest.Tail != 200 {
		t.Fatalf("bounded logs request = %#v", operator.logsRequest)
	}
	if operator.auditLimit != 100 {
		t.Fatalf("bounded audit limit = %d, want 100", operator.auditLimit)
	}
	if body := requestBody(t, server, "/api/logs?service=plex"); strings.Contains(
		body,
		"READ_CONTRACT_SECRET_CANARY",
	) || !strings.Contains(body, "[REDACTED]") {
		t.Fatalf("logs response was not redacted: %s", body)
	}
}

func requestBody(t *testing.T, server *Server, path string) string {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	recorder := httptest.NewRecorder()
	serveTestRequest(server, recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("%s status = %d: %s", path, recorder.Code, recorder.Body.String())
	}
	return recorder.Body.String()
}

func TestLogsEndpointRedactsCredentialsAtWebBoundary(t *testing.T) {
	server, err := New(Options{
		Operator: secretLogOperator{},
		Token:    "test-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/logs?tail=20", nil)
	recorder := httptest.NewRecorder()
	serveTestRequest(server, recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if strings.Contains(body, "WEB_LOG_SECRET_CANARY") ||
		!strings.Contains(body, "[REDACTED]") {
		t.Fatalf("web log response leaked credential: %s", body)
	}
}

func TestSummaryIncludesRegistryWarnings(t *testing.T) {
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	server := testServerWithRegistry(t, projectDir, cfg, testRegistryWithWarningOnlyService(t))
	req := httptest.NewRequest(http.MethodGet, "/api/summary", nil)
	rec := httptest.NewRecorder()

	serveTestRequest(server, rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"registryWarnings":`) ||
		!strings.Contains(body, `"privileged mode`) ||
		!strings.Contains(body, `"service":"privileged-helper"`) {
		t.Fatalf("summary missing registry warning details: %s", body)
	}
}

func TestBackupActionRequiresConfirmation(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/backups/safe.tar.gz.age/delete", nil)
	req.Header.Set("X-SDBX-Token", "test-token")
	rec := httptest.NewRecorder()

	serveTestRequest(server, rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestBackupActionRequiresToken(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/backups/safe.tar.gz.age/delete", nil)
	req.Header.Set("X-SDBX-Confirm", "delete")
	req.Host = "127.0.0.1"
	req.Header.Set("Origin", "http://127.0.0.1")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestBackupDeleteRemovesBackupWithConfirmation(t *testing.T) {
	projectDir := t.TempDir()
	server := testServerInProject(t, projectDir)
	backupPath := filepath.Join(projectDir, "backups", "safe.tar.gz.age")
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(backupPath, []byte("backup"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/backups/safe.tar.gz.age/delete", nil)
	req.Header.Set("X-SDBX-Token", "test-token")
	req.Header.Set("X-SDBX-Confirm", "delete")
	rec := httptest.NewRecorder()

	serveTestRequest(server, rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Fatalf("backup should be deleted, stat err=%v", err)
	}
}

func TestBackupRestoreRestoresWithConfirmation(t *testing.T) {
	projectDir := t.TempDir()
	server := testServerInProject(t, projectDir)
	statePath := filepath.Join(projectDir, "configs", "app", "config.yml")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := backup.NewManager(projectDir).Create(
		context.Background(),
		backup.EncryptOptions{
			Passphrase: []byte(webUITestBackupPassphrase),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/backups/"+created.Name+"/restore",
		strings.NewReader(`{"passphrase":"`+webUITestBackupPassphrase+`"}`),
	)
	req.Header.Set("X-SDBX-Token", "test-token")
	req.Header.Set("X-SDBX-Confirm", "restore")
	rec := httptest.NewRecorder()

	serveTestRequest(server, rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(data) != "ok" {
		t.Fatalf("restored file = %q, want %q", string(data), "ok")
	}
}

func TestBackupCreateRequiresAndUsesEncryptionCredentials(t *testing.T) {
	projectDir := t.TempDir()
	secretsDir := filepath.Join(projectDir, "secrets")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(secretsDir, "canary.txt"),
		[]byte("WEBUI_SECRET_CANARY"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	server := testServerInProject(t, projectDir)

	missing := httptest.NewRequest(http.MethodPost, "/api/actions/backup", nil)
	missing.Header.Set("X-SDBX-Token", "test-token")
	missingRecorder := httptest.NewRecorder()
	serveTestRequest(server, missingRecorder, missing)
	if missingRecorder.Code != http.StatusBadRequest {
		t.Fatalf("missing credentials status = %d, want 400", missingRecorder.Code)
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/actions/backup",
		strings.NewReader(`{"passphrase":"`+webUITestBackupPassphrase+`"}`),
	)
	request.Header.Set("X-SDBX-Token", "test-token")
	recorder := httptest.NewRecorder()
	serveTestRequest(server, recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	entries, err := os.ReadDir(filepath.Join(projectDir, "backups"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".tar.gz.age") {
		t.Fatalf("backup entries = %#v, want one encrypted archive", entries)
	}
	archivePath := filepath.Join(projectDir, "backups", entries[0].Name())
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(archive, []byte("WEBUI_SECRET_CANARY")) {
		t.Fatal("Web UI backup leaked plaintext secret")
	}
	info, err := os.Stat(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %o, want 600", info.Mode().Perm())
	}
}

func TestBackupRestoreRelocatesCompatibleStateWhenRequested(t *testing.T) {
	projectDir := t.TempDir()
	server := testServerInProject(t, projectDir)
	statePath := filepath.Join(projectDir, "configs", "application", "state.db")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("portable-state\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	create := httptest.NewRequest(
		http.MethodPost,
		"/api/actions/backup",
		strings.NewReader(`{"passphrase":"`+webUITestBackupPassphrase+`"}`),
	)
	create.Header.Set("X-SDBX-Token", "test-token")
	createRecorder := httptest.NewRecorder()
	serveTestRequest(server, createRecorder, create)
	if createRecorder.Code != http.StatusOK {
		t.Fatalf(
			"create status = %d, want %d: %s",
			createRecorder.Code,
			http.StatusOK,
			createRecorder.Body.String(),
		)
	}
	entries, err := os.ReadDir(filepath.Join(projectDir, "backups"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("backup entries = %d, want 1", len(entries))
	}
	if err := os.WriteFile(statePath, []byte("changed-state\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	restore := httptest.NewRequest(
		http.MethodPost,
		"/api/backups/"+entries[0].Name()+"/restore",
		strings.NewReader(
			`{"passphrase":"`+webUITestBackupPassphrase+
				`","relocateManagedRoots":true}`,
		),
	)
	restore.Header.Set("X-SDBX-Token", "test-token")
	restore.Header.Set("X-SDBX-Confirm", "restore")
	restoreRecorder := httptest.NewRecorder()
	serveTestRequest(server, restoreRecorder, restore)
	if restoreRecorder.Code != http.StatusOK {
		t.Fatalf(
			"restore status = %d, want %d: %s",
			restoreRecorder.Code,
			http.StatusOK,
			restoreRecorder.Body.String(),
		)
	}
	if got := readFile(t, statePath); got != "portable-state\n" {
		t.Fatalf("restored application state = %q", got)
	}
}

func TestAddonEnableRegeneratesCompose(t *testing.T) {
	projectDir := t.TempDir()
	server := testServerWithCatalog(t, projectDir, config.DefaultConfig())

	req := httptest.NewRequest(http.MethodPost, "/api/addons/sonarr/enable", nil)
	req.Header.Set("X-SDBX-Token", "test-token")
	req.Header.Set("X-SDBX-Confirm", "enable")
	rec := httptest.NewRecorder()

	serveTestRequest(server, rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	compose := readFile(t, filepath.Join(projectDir, "compose.yaml"))
	if !strings.Contains(compose, "sdbx-sonarr") {
		t.Fatalf("compose.yaml did not include enabled addon:\n%s", compose)
	}
	sdbxConfig := readFile(t, filepath.Join(projectDir, ".sdbx.yaml"))
	if !strings.Contains(sdbxConfig, "- sonarr") {
		t.Fatalf(".sdbx.yaml did not include enabled addon:\n%s", sdbxConfig)
	}
}

func TestAddonEnablePreservesUserDatabaseAndRefreshesManagedPolicyAndEnv(t *testing.T) {
	projectDir := t.TempDir()
	userDatabase := filepath.Join(projectDir, "configs", "authelia", "users_database.yml")
	if err := os.MkdirAll(filepath.Dir(userDatabase), 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(userDatabase, []byte("custom users database"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	envPath := filepath.Join(projectDir, ".env")
	if err := os.WriteFile(envPath, []byte("PLEX_CLAIM=claim-token\nTUNNEL_TOKEN=tunnel-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	server := testServerWithCatalog(t, projectDir, config.DefaultConfig())
	if err := os.WriteFile(userDatabase, []byte("custom users database"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/addons/sonarr/enable", nil)
	req.Header.Set("X-SDBX-Token", "test-token")
	req.Header.Set("X-SDBX-Confirm", "enable")
	rec := httptest.NewRecorder()

	serveTestRequest(server, rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := readFile(t, userDatabase); got != "custom users database" {
		t.Fatalf("user database was overwritten: %q", got)
	}
	env := readFile(t, envPath)
	if strings.Contains(env, "claim-token") || strings.Contains(env, "tunnel-token") {
		t.Fatalf("legacy secret-bearing .env content survived: %q", env)
	}
	policy := readFile(
		t,
		filepath.Join(projectDir, "configs", "authelia", "configuration.yml"),
	)
	if !strings.Contains(policy, "sonarr.sdbx.example.com") ||
		!strings.Contains(policy, "default_policy: deny") {
		t.Fatalf("managed Authelia policy was not refreshed:\n%s", policy)
	}
}

func TestAddonDisableRegeneratesCompose(t *testing.T) {
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Addons = []string{"sonarr"}
	if err := os.WriteFile(filepath.Join(projectDir, "compose.yaml"), []byte("services:\n  sonarr:\n    container_name: sdbx-sonarr\n"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	server := testServerWithCatalog(t, projectDir, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/addons/sonarr/disable", nil)
	req.Header.Set("X-SDBX-Token", "test-token")
	req.Header.Set("X-SDBX-Confirm", "disable")
	rec := httptest.NewRecorder()

	serveTestRequest(server, rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	compose := readFile(t, filepath.Join(projectDir, "compose.yaml"))
	if strings.Contains(compose, "sdbx-sonarr") {
		t.Fatalf("compose.yaml still included disabled addon:\n%s", compose)
	}
	sdbxConfig := readFile(t, filepath.Join(projectDir, ".sdbx.yaml"))
	if strings.Contains(sdbxConfig, "- sonarr") {
		t.Fatalf(".sdbx.yaml still included disabled addon:\n%s", sdbxConfig)
	}
}

func TestAddonEnableRejectsUnverifiedGeneratedFiles(t *testing.T) {
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	server := testServerWithCatalog(t, projectDir, cfg)
	if err := os.WriteFile(
		filepath.Join(projectDir, "compose.yaml"),
		[]byte("tampered\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/addons/sonarr/enable", nil)
	req.Header.Set("X-SDBX-Token", "test-token")
	req.Header.Set("X-SDBX-Confirm", "enable")
	rec := httptest.NewRecorder()

	serveTestRequest(server, rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	if cfg.IsAddonEnabled("sonarr") {
		t.Fatal("addon remained enabled after regeneration failure")
	}
}

func TestConfigEndpointReturnsProjectSettings(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domain = "sdbx.one"
	cfg.Timezone = "UTC"
	server := testServerWithCatalog(t, t.TempDir(), cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	rec := httptest.NewRecorder()

	serveTestRequest(server, rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"domain":"sdbx.one"`) || !strings.Contains(body, `"timezone":"UTC"`) {
		t.Fatalf("config response missing expected settings: %s", body)
	}
	if !strings.Contains(body, `"fields"`) || !strings.Contains(body, `"key":"expose.mode"`) || !strings.Contains(body, `"type":"select"`) {
		t.Fatalf("config response missing settings field metadata: %s", body)
	}
}

func TestConfigSetRequiresToken(t *testing.T) {
	server := testServerWithCatalog(t, t.TempDir(), config.DefaultConfig())
	req := httptest.NewRequest(http.MethodPost, "/api/config/domain", bytes.NewBufferString(`{"value":"new.sdbx.one"}`))
	req.Host = "127.0.0.1"
	req.Header.Set("Origin", "http://127.0.0.1")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestConfigSetRegeneratesCompose(t *testing.T) {
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Domain = "old.sdbx.one"
	server := testServerWithCatalog(t, projectDir, cfg)
	req := httptest.NewRequest(http.MethodPost, "/api/config/domain", bytes.NewBufferString(`{"value":"new.sdbx.one"}`))
	req.Header.Set("X-SDBX-Token", "test-token")
	req.Header.Set("X-SDBX-Confirm", "save")
	rec := httptest.NewRecorder()

	serveTestRequest(server, rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	sdbxConfig := readFile(t, filepath.Join(projectDir, ".sdbx.yaml"))
	if !strings.Contains(sdbxConfig, "domain: new.sdbx.one") {
		t.Fatalf(".sdbx.yaml did not include updated domain:\n%s", sdbxConfig)
	}
	routes := readFile(
		t,
		filepath.Join(projectDir, "configs", "traefik", "dynamic", "middlewares.yml"),
	)
	if !strings.Contains(routes, ".new.sdbx.one") {
		t.Fatalf("Traefik routes did not include updated domain:\n%s", routes)
	}
	reloaded, err := config.LoadFile(filepath.Join(projectDir, ".sdbx.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Domain != "new.sdbx.one" {
		t.Fatalf("saved config domain = %q, want new.sdbx.one", reloaded.Domain)
	}
}

func TestConfigSetDoesNotReflectSensitiveInvalidInput(t *testing.T) {
	server := testServerWithCatalog(t, t.TempDir(), config.DefaultConfig())
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/config/password=WEB_SETTING_SECRET_CANARY",
		bytes.NewBufferString(`{"value":"ignored"}`),
	)
	request.Header.Set("X-SDBX-Token", "test-token")
	request.Header.Set("X-SDBX-Confirm", "save")
	recorder := httptest.NewRecorder()
	serveTestRequest(server, recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if strings.Contains(body, "WEB_SETTING_SECRET_CANARY") ||
		!strings.Contains(body, `"code":"invalid_setting"`) {
		t.Fatalf("invalid setting response reflected sensitive input: %s", body)
	}
}

func testServer(t *testing.T) *Server {
	t.Helper()
	return testServerInProject(t, t.TempDir())
}

func testServerInProject(t *testing.T, projectDir string) *Server {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Domain = "sdbx.one"
	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	return testServerWithRegistry(t, projectDir, cfg, reg)
}

func testServerWithCatalog(t *testing.T, projectDir string, cfg *config.Config) *Server {
	t.Helper()
	reg, err := registry.New(&registry.SourceConfig{
		APIVersion: registry.APIVersion,
		Kind:       registry.KindSourceConfig,
		Cache: registry.CacheConfig{
			Directory: filepath.Join(t.TempDir(), "cache"),
		},
	})
	if err != nil {
		t.Fatalf("registry.New failed: %v", err)
	}
	return testServerWithRegistry(t, projectDir, cfg, reg)
}

func testServerWithRegistry(t *testing.T, projectDir string, cfg *config.Config, reg *registry.Registry) *Server {
	t.Helper()
	prepareWebUITestProject(t, projectDir, cfg, reg)
	operator, err := management.NewProjectOperator(
		projectDir,
		webUITestVersion,
		reg,
		webUITestImageResolver{},
	)
	if err != nil {
		t.Fatalf("NewProjectOperator failed: %v", err)
	}
	server, err := New(Options{
		Operator: operator,
		Token:    "test-token",
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return server
}

type webUITestImageResolver struct{}

func (webUITestImageResolver) Resolve(
	_ context.Context,
	_, _ string,
) (registry.ResolvedImage, error) {
	digest := "sha256:" + strings.Repeat("c", 64)
	return registry.ResolvedImage{
		Digest: digest,
		PlatformDigests: map[string]string{
			"linux/amd64": digest,
			"linux/arm64": digest,
		},
	}, nil
}

func prepareWebUITestProject(
	t *testing.T,
	projectDir string,
	cfg *config.Config,
	reg *registry.Registry,
) {
	t.Helper()
	cfg.ProjectDir = projectDir
	lock, _, err := reg.GenerateLockFileWithOptions(
		context.Background(),
		cfg,
		registry.LockOptions{
			CLIVersion:        webUITestVersion,
			TargetPlatform:    "linux/" + runtime.GOARCH,
			AllowLocalSources: true,
			ImageResolver:     webUITestImageResolver{},
		},
	)
	if err != nil {
		t.Fatalf("GenerateLockFile failed: %v", err)
	}
	lockPath := filepath.Join(projectDir, ".sdbx.lock")
	if err := registry.NewLoader().SaveLockFile(lockPath, lock); err != nil {
		t.Fatalf("SaveLockFile failed: %v", err)
	}
	if err := generator.NewGeneratorWithLock(
		cfg,
		projectDir,
		reg,
		lock,
		webUITestVersion,
	).Generate(); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if err := registry.NewLoader().SaveLockFile(lockPath, lock); err != nil {
		t.Fatalf("save generated lock failed: %v", err)
	}
}

func serveTestRequest(server *Server, recorder *httptest.ResponseRecorder, request *http.Request) {
	request.Host = "127.0.0.1"
	if request.Header.Get("X-SDBX-Token") == "" {
		request.Header.Set("X-SDBX-Token", server.Token())
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		request.Header.Set("Origin", "http://127.0.0.1")
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		if request.ContentLength > 0 && request.Header.Get("Content-Type") == "" {
			request.Header.Set("Content-Type", "application/json")
		}
	}
	server.Handler().ServeHTTP(recorder, request)
}

func testRegistryWithWarningOnlyService(t *testing.T) *registry.Registry {
	t.Helper()
	sourceDir := t.TempDir()
	serviceDir := filepath.Join(sourceDir, "privileged-helper")
	if err := os.MkdirAll(serviceDir, 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(serviceDir, "service.yaml"), []byte(`
apiVersion: sdbx.one/v1
kind: Service
applicationAuth:
  mode: none
metadata:
  name: privileged-helper
  version: 1.0.0
  category: utility
  description: Privileged helper
permissions:
  - network:app
  - privileged
spec:
  image:
    repository: alpine
    tag: latest
  container:
    name_template: sdbx-{{ .Name }}
    privileged: true
  networking:
    networks:
      - name: app
conditions:
  always: true
`), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	reg, err := registry.New(&registry.SourceConfig{
		APIVersion: registry.APIVersion,
		Kind:       registry.KindSourceConfig,
		Sources: []registry.Source{
			{
				Name:     "local-test",
				Type:     "local",
				Path:     sourceDir,
				Priority: 100,
				Enabled:  true,
				Trust: registry.TrustLevel{
					AllowCatalogPermissions: []string{
						"network:app",
						registry.PermissionPrivileged,
					},
					AllowedRegistries: []string{"docker.io"},
				},
			},
		},
		Cache: registry.CacheConfig{
			Directory: filepath.Join(t.TempDir(), "cache"),
		},
	})
	if err != nil {
		t.Fatalf("registry.New failed: %v", err)
	}
	return reg
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) failed: %v", path, err)
	}
	return string(data)
}
