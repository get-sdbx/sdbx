package broker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/get-sdbx/sdbx/internal/addons"
	"github.com/get-sdbx/sdbx/internal/management"
	"github.com/get-sdbx/sdbx/internal/settings"
)

var testBrokerToken = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))

type fakeOperator struct {
	stackRequest         management.StackRequest
	addonRequest         management.AddonRequest
	settingRequest       management.SettingRequest
	createBackupRequest  management.CreateBackupRequest
	restoreBackupRequest management.RestoreBackupRequest
	deleteBackupRequest  management.DeleteBackupRequest
	stackCalls           int
	addonCalls           int
	settingCalls         int
	createBackupCalls    int
	deleteBackupCalls    int
	returnError          error
	logOutput            string
}

func (o *fakeOperator) Preview(
	_ context.Context,
	request management.ImpactRequest,
) (*management.Impact, error) {
	return &management.Impact{
		Operation:    request.Operation,
		Title:        "Typed preview",
		Consequences: []string{"Bounded operation"},
		Confirmation: request.Target,
	}, o.returnError
}

func (o *fakeOperator) Summary(context.Context) (*management.Summary, error) {
	if o.returnError != nil {
		return nil, o.returnError
	}
	return &management.Summary{Domain: "box.example.test", TotalServices: 4}, nil
}

func (o *fakeOperator) Security(
	context.Context,
) (*management.SecurityReport, error) {
	return &management.SecurityReport{ProjectVerified: true}, o.returnError
}

func (o *fakeOperator) Diagnostics(
	context.Context,
) (*management.DiagnosticsReport, error) {
	return &management.DiagnosticsReport{Healthy: true}, o.returnError
}

func (o *fakeOperator) Services(context.Context) ([]management.Service, error) {
	return []management.Service{{Name: "authelia", Status: "missing"}}, o.returnError
}

func (o *fakeOperator) Logs(
	_ context.Context,
	request management.LogsRequest,
) (*management.LogsResult, error) {
	output := o.logOutput
	if output == "" {
		output = "bounded logs"
	}
	return &management.LogsResult{Service: request.Service, Logs: output}, o.returnError
}

func (o *fakeOperator) Addons(context.Context) ([]management.Addon, error) {
	return []management.Addon{{Name: "sonarr"}}, o.returnError
}

func (o *fakeOperator) SetAddon(
	_ context.Context,
	request management.AddonRequest,
) (*addons.Result, error) {
	o.addonRequest = request
	o.addonCalls++
	return &addons.Result{Name: request.Name, Action: request.Action}, o.returnError
}

func (o *fakeOperator) Settings(context.Context) (*management.Settings, error) {
	return &management.Settings{Values: map[string]any{"domain": "box.example.test"}}, o.returnError
}

func (o *fakeOperator) SetSetting(
	_ context.Context,
	request management.SettingRequest,
) (*settings.Result, error) {
	o.settingRequest = request
	o.settingCalls++
	return &settings.Result{Key: request.Key, Value: request.Value}, o.returnError
}

func (o *fakeOperator) Backups(context.Context) ([]management.Backup, error) {
	return []management.Backup{}, o.returnError
}

func (o *fakeOperator) CreateBackup(
	_ context.Context,
	request management.CreateBackupRequest,
) (*management.Backup, error) {
	o.createBackupRequest = request
	o.createBackupRequest.Passphrase = append([]byte(nil), request.Passphrase...)
	o.createBackupCalls++
	return &management.Backup{Name: "backup.age", Timestamp: time.Unix(1, 0)}, o.returnError
}

func (o *fakeOperator) RestoreBackup(
	_ context.Context,
	request management.RestoreBackupRequest,
) error {
	o.restoreBackupRequest = request
	return o.returnError
}

func (o *fakeOperator) DeleteBackup(
	_ context.Context,
	request management.DeleteBackupRequest,
) error {
	o.deleteBackupRequest = request
	o.deleteBackupCalls++
	return o.returnError
}

func (o *fakeOperator) Stack(
	_ context.Context,
	request management.StackRequest,
) error {
	o.stackRequest = request
	o.stackCalls++
	return o.returnError
}

type fixedAuthorizer struct {
	actor *Actor
	err   error
}

func (a fixedAuthorizer) Authorize(*http.Request) (*Actor, error) {
	return a.actor, a.err
}

func testBrokerServer(t *testing.T, operator management.Operator) *httptest.Server {
	t.Helper()
	authorizer, err := NewStaticTokenAuthorizer(testBrokerToken)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(operator, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(server.Handler())
}

func TestBrokerRequiresAuthorizationAndHidesBackendErrors(t *testing.T) {
	operator := &fakeOperator{returnError: errors.New("password=SUPER_SECRET /private/path")}
	server := testBrokerServer(t, operator)
	defer server.Close()

	unauthorized, err := http.Get(server.URL + "/v1/summary")
	if err != nil {
		t.Fatal(err)
	}
	defer unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.StatusCode)
	}

	request, err := http.NewRequest(http.MethodGet, server.URL+"/v1/summary", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testBrokerToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(response.Body)
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("backend failure status = %d: %s", response.StatusCode, body.String())
	}
	if strings.Contains(body.String(), "SUPER_SECRET") ||
		strings.Contains(body.String(), "/private/path") {
		t.Fatalf("broker leaked backend error: %s", body.String())
	}
}

func TestAnyAuthorizerRequiresAndReturnsARealActor(t *testing.T) {
	if _, err := NewAnyAuthorizer(nil, nil); err == nil {
		t.Fatal("all-nil authorizer set was accepted")
	}

	expected := &Actor{
		Subject:  "accepted-admin",
		Groups:   []string{AdminGroup},
		AuthTime: time.Now().Unix(),
	}
	authorizer, err := NewAnyAuthorizer(
		nil,
		fixedAuthorizer{err: errors.New("rejected")},
		fixedAuthorizer{},
		fixedAuthorizer{actor: &Actor{Subject: " \t "}},
		fixedAuthorizer{actor: expected},
	)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := authorizer.Authorize(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	if actor != expected {
		t.Fatalf("actor = %#v, want %#v", actor, expected)
	}

	rejected, err := NewAnyAuthorizer(
		fixedAuthorizer{err: errors.New("rejected")},
		fixedAuthorizer{},
		fixedAuthorizer{actor: &Actor{Subject: " \t "}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if actor, err := rejected.Authorize(
		httptest.NewRequest(http.MethodGet, "/", nil),
	); err == nil || actor != nil {
		t.Fatalf("invalid actor result = (%#v, %v), want rejection", actor, err)
	}
}

func TestBrokerRejectsInvalidActorFailClosed(t *testing.T) {
	actors := []struct {
		name  string
		actor *Actor
	}{
		{
			name: "nil",
		},
		{
			name:  "empty-subject",
			actor: &Actor{},
		},
		{
			name:  "whitespace-subject",
			actor: &Actor{Subject: " \t "},
		},
	}
	for _, actorCase := range actors {
		t.Run(actorCase.name, func(t *testing.T) {
			operator := &fakeOperator{}
			server, err := NewServer(
				operator,
				fixedAuthorizer{actor: actorCase.actor},
			)
			if err != nil {
				t.Fatal(err)
			}

			requestCases := []struct {
				method string
				path   string
				body   string
			}{
				{
					method: http.MethodGet,
					path:   "/v1/summary",
				},
				{
					method: http.MethodPost,
					path:   "/v1/stack",
					body:   `{"action":"restart","confirm":"restart"}`,
				},
			}
			for _, requestCase := range requestCases {
				request := httptest.NewRequest(
					requestCase.method,
					requestCase.path,
					strings.NewReader(requestCase.body),
				)
				request.Header.Set("Content-Type", "application/json")
				recorder := httptest.NewRecorder()
				server.Handler().ServeHTTP(recorder, request)
				if recorder.Code != http.StatusUnauthorized {
					t.Fatalf(
						"%s %s status = %d, want 401",
						requestCase.method,
						requestCase.path,
						recorder.Code,
					)
				}
			}
			if operator.stackCalls != 0 {
				t.Fatalf(
					"invalid actor reached operator %d times",
					operator.stackCalls,
				)
			}
		})
	}

	contextActors := []*Actor{
		nil,
		{},
		{Subject: " \t "},
	}
	for _, contextActor := range contextActors {
		actor, ok := ActorFromContext(withActor(context.Background(), contextActor))
		if ok || actor != nil {
			t.Fatalf(
				"invalid context actor = (%#v, %t), want (nil, false)",
				actor,
				ok,
			)
		}
	}
}

func TestBrokerClientRoundTripUsesTypedOperations(t *testing.T) {
	operator := &fakeOperator{}
	server := testBrokerServer(t, operator)
	defer server.Close()
	client, err := newClient(server.Client(), server.URL, testBrokerToken)
	if err != nil {
		t.Fatal(err)
	}

	summary, err := client.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Domain != "box.example.test" || summary.TotalServices != 4 {
		t.Fatalf("summary = %#v", summary)
	}
	security, err := client.Security(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !security.ProjectVerified {
		t.Fatalf("security = %#v", security)
	}
	diagnostics, err := client.Diagnostics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !diagnostics.Healthy {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	services, err := client.Services(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 1 || services[0].Name != "authelia" {
		t.Fatalf("services = %#v", services)
	}
	impact, err := client.Preview(context.Background(), management.ImpactRequest{
		Operation: "stack.restart",
		Target:    "restart",
	})
	if err != nil {
		t.Fatal(err)
	}
	if impact.Operation != "stack.restart" || impact.Title != "Typed preview" {
		t.Fatalf("impact = %#v", impact)
	}
	logs, err := client.Logs(context.Background(), management.LogsRequest{
		Service: "authelia",
		Tail:    50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if logs.Logs != "bounded logs" {
		t.Fatalf("logs = %#v", logs)
	}
	availableAddons, err := client.Addons(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(availableAddons) != 1 || availableAddons[0].Name != "sonarr" {
		t.Fatalf("addons = %#v", availableAddons)
	}
	addonResult, err := client.SetAddon(context.Background(), management.AddonRequest{
		Name:    "sonarr",
		Action:  "enable",
		Confirm: "enable sonarr",
	})
	if err != nil {
		t.Fatal(err)
	}
	if addonResult.Name != "sonarr" ||
		addonResult.Action != "enable" ||
		operator.addonCalls != 1 ||
		operator.addonRequest.Confirm != "enable sonarr" {
		t.Fatalf(
			"addon result/request = %#v / %#v",
			addonResult,
			operator.addonRequest,
		)
	}
	currentSettings, err := client.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if currentSettings.Values["domain"] != "box.example.test" {
		t.Fatalf("settings = %#v", currentSettings)
	}
	settingResult, err := client.SetSetting(
		context.Background(),
		management.SettingRequest{
			Key:     "domain",
			Value:   "media.example.test",
			Confirm: "set domain",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if settingResult.Key != "domain" ||
		settingResult.Value != "media.example.test" ||
		operator.settingCalls != 1 ||
		operator.settingRequest.Confirm != "set domain" {
		t.Fatalf(
			"setting result/request = %#v / %#v",
			settingResult,
			operator.settingRequest,
		)
	}
	backups, err := client.Backups(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 0 {
		t.Fatalf("backups = %#v", backups)
	}
	createPassphrase := []byte("synthetic broker create passphrase")
	createdBackup, err := client.CreateBackup(
		context.Background(),
		management.CreateBackupRequest{
			Passphrase: createPassphrase,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if createdBackup.Name != "backup.age" ||
		operator.createBackupCalls != 1 ||
		string(operator.createBackupRequest.Passphrase) !=
			"synthetic broker create passphrase" {
		t.Fatalf(
			"created backup/request = %#v / %#v",
			createdBackup,
			operator.createBackupRequest,
		)
	}
	if err := client.Stack(context.Background(), management.StackRequest{
		Action:  "restart",
		Confirm: "restart",
	}); err != nil {
		t.Fatal(err)
	}
	if operator.stackRequest.Action != "restart" {
		t.Fatalf("stack request = %#v", operator.stackRequest)
	}
	restorePassphrase := []byte("synthetic broker restore passphrase")
	if err := client.RestoreBackup(
		context.Background(),
		management.RestoreBackupRequest{
			Name:                 "portable.tar.gz.age",
			Passphrase:           restorePassphrase,
			Confirm:              "restore",
			RelocateManagedRoots: true,
		},
	); err != nil {
		t.Fatal(err)
	}
	if operator.restoreBackupRequest.Name != "portable.tar.gz.age" ||
		!operator.restoreBackupRequest.RelocateManagedRoots {
		t.Fatalf(
			"restore backup request = %#v",
			operator.restoreBackupRequest,
		)
	}
	if err := client.DeleteBackup(
		context.Background(),
		management.DeleteBackupRequest{
			Name:    "portable.tar.gz.age",
			Confirm: "delete portable.tar.gz.age",
		},
	); err != nil {
		t.Fatal(err)
	}
	if operator.deleteBackupCalls != 1 ||
		operator.deleteBackupRequest.Name != "portable.tar.gz.age" ||
		operator.deleteBackupRequest.Confirm != "delete portable.tar.gz.age" {
		t.Fatalf("delete backup request = %#v", operator.deleteBackupRequest)
	}
}

func TestBrokerRedactsCredentialBearingLogs(t *testing.T) {
	operator := &fakeOperator{
		logOutput: "password=BROKER_LOG_SECRET_CANARY\nready\n",
	}
	server := testBrokerServer(t, operator)
	defer server.Close()
	client, err := newClient(server.Client(), server.URL, testBrokerToken)
	if err != nil {
		t.Fatal(err)
	}
	logs, err := client.Logs(context.Background(), management.LogsRequest{
		Service: "authelia",
		Tail:    20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.Logs, "BROKER_LOG_SECRET_CANARY") ||
		!strings.Contains(logs.Logs, "[REDACTED]") {
		t.Fatalf("broker log response leaked credential: %#v", logs)
	}
}

func TestBrokerOperationErrorsAreTypedAndDoNotLeak(t *testing.T) {
	testCases := []struct {
		name       string
		backendErr error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "unverified-project",
			backendErr: management.ErrProjectUnverified,
			wantStatus: http.StatusConflict,
			wantCode:   "project_not_verified",
		},
		{
			name:       "internal-operation-failure",
			backendErr: errors.New("password=BROKER_OPERATION_SECRET /private/path"),
			wantStatus: http.StatusBadRequest,
			wantCode:   "stack_action_failed",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			server := testBrokerServer(
				t,
				&fakeOperator{returnError: testCase.backendErr},
			)
			defer server.Close()
			client, err := newClient(server.Client(), server.URL, testBrokerToken)
			if err != nil {
				t.Fatal(err)
			}
			err = client.Stack(context.Background(), management.StackRequest{
				Action:  "restart",
				Confirm: "restart",
			})
			var apiError *APIError
			if !errors.As(err, &apiError) {
				t.Fatalf("error = %T %v, want *APIError", err, err)
			}
			if apiError.Status != testCase.wantStatus ||
				apiError.Code != testCase.wantCode {
				t.Fatalf("API error = %#v", apiError)
			}
			rendered := apiError.Error()
			if !strings.Contains(rendered, testCase.wantCode) ||
				strings.Contains(rendered, "BROKER_OPERATION_SECRET") ||
				strings.Contains(rendered, "/private/path") {
				t.Fatalf("unsafe API error = %q", rendered)
			}
		})
	}
}

func TestBrokerRejectsUnknownFieldsAndOversizedBodies(t *testing.T) {
	server := testBrokerServer(t, &fakeOperator{})
	defer server.Close()

	for _, body := range []string{
		`{"action":"up","confirm":"up","command":"rm"}`,
		`{"padding":"` + strings.Repeat("x", maxRequestBytes) + `"}`,
	} {
		request, err := http.NewRequest(
			http.MethodPost,
			server.URL+"/v1/stack",
			strings.NewReader(body),
		)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+testBrokerToken)
		request.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid body status = %d", response.StatusCode)
		}
	}
}

func TestBrokerRejectsMalformedLogTail(t *testing.T) {
	server := testBrokerServer(t, &fakeOperator{})
	defer server.Close()
	request, err := http.NewRequest(
		http.MethodGet,
		server.URL+"/v1/logs?tail=20junk",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testBrokerToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed tail status = %d, want 400", response.StatusCode)
	}
}

func TestBrokerRequiresAdminGroupAndRecentAuthentication(t *testing.T) {
	testCases := []struct {
		name       string
		actor      *Actor
		wantStatus int
		wantCalls  int
	}{
		{
			name: "non-admin",
			actor: &Actor{
				Subject:  "viewer",
				Groups:   []string{"sdbx-viewer"},
				AuthTime: time.Now().Unix(),
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "stale-admin",
			actor: &Actor{
				Subject:  "admin",
				Groups:   []string{AdminGroup},
				AuthTime: time.Now().Add(-time.Hour).Unix(),
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "recent-admin",
			actor: &Actor{
				Subject:  "admin",
				Groups:   []string{AdminGroup},
				AuthTime: time.Now().Unix(),
			},
			wantStatus: http.StatusOK,
			wantCalls:  1,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			operator := &fakeOperator{}
			server, err := NewServer(operator, fixedAuthorizer{actor: testCase.actor})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(
				http.MethodPost,
				"/v1/stack",
				strings.NewReader(`{"action":"restart","confirm":"restart"}`),
			)
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, request)
			if recorder.Code != testCase.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, testCase.wantStatus)
			}
			if operator.stackCalls != testCase.wantCalls {
				t.Fatalf("stack calls = %d, want %d", operator.stackCalls, testCase.wantCalls)
			}
		})
	}
}

func TestBrokerRecentAuthenticationWindowIsConfigurable(t *testing.T) {
	if _, err := NewServer(
		&fakeOperator{},
		fixedAuthorizer{actor: &Actor{}},
		WithRecentAuthMaxAge(0),
	); err == nil {
		t.Fatal("zero recent authentication window was accepted")
	}

	operator := &fakeOperator{}
	server, err := NewServer(
		operator,
		fixedAuthorizer{actor: &Actor{
			Subject:  "admin",
			Groups:   []string{AdminGroup},
			AuthTime: time.Now().Add(-2 * time.Second).Unix(),
		}},
		WithRecentAuthMaxAge(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/stack",
		strings.NewReader(`{"action":"restart","confirm":"restart"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
	if operator.stackCalls != 0 {
		t.Fatalf("stale custom-window actor reached operator %d times", operator.stackCalls)
	}
}

func TestBrokerRestrictsSensitiveReadsToAdminGroup(t *testing.T) {
	viewer := &Actor{
		Subject:  "viewer",
		Groups:   []string{"sdbx-viewer"},
		AuthTime: time.Now().Unix(),
	}
	server, err := NewServer(&fakeOperator{}, fixedAuthorizer{actor: viewer})
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		"/v1/audit",
		"/v1/logs?tail=20",
		"/v1/settings",
		"/v1/backups",
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("%s status = %d, want 403", path, recorder.Code)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/summary", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("viewer summary status = %d, want 200", recorder.Code)
	}
}

func TestFileAuditorRecordsRedactedOperationMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "events.jsonl")
	auditor, err := OpenFileAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	operator := &fakeOperator{}
	authorizer := fixedAuthorizer{actor: &Actor{
		Subject:  "admin\nforged",
		Groups:   []string{AdminGroup},
		AuthTime: time.Now().Unix(),
	}}
	server, err := NewServer(operator, authorizer, WithAuditor(auditor))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/backups",
		strings.NewReader(`{"recipient":"AUDIT_SECRET_CANARY"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("audit mode = %o, want 600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("AUDIT_SECRET_CANARY")) {
		t.Fatal("audit log leaked a request secret")
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit lines = %d, want start and completion", len(lines))
	}
	for _, line := range lines {
		var event AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("invalid audit JSON: %v", err)
		}
		if event.Operation != "backup.create" || event.Actor != "admin\nforged" {
			t.Fatalf("audit event = %#v", event)
		}
	}
}

func TestAuditEndpointRequiresAdminAndReturnsRecentEvents(t *testing.T) {
	auditor, err := OpenFileAuditor(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditor.Close()
	if err := auditor.Record(context.Background(), AuditEvent{
		Timestamp: time.Now(),
		RequestID: "seed-event",
		Actor:     "admin",
		Groups:    []string{AdminGroup},
		Operation: "backup.create",
		Method:    http.MethodPost,
		Path:      "/v1/backups",
		Outcome:   "succeeded",
		Status:    http.StatusOK,
	}); err != nil {
		t.Fatal(err)
	}

	nonAdmin, err := NewServer(
		&fakeOperator{},
		fixedAuthorizer{actor: &Actor{
			Subject:  "viewer",
			Groups:   []string{"sdbx-viewer"},
			AuthTime: time.Now().Unix(),
		}},
		WithAuditor(auditor),
	)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/audit?limit=10", nil)
	recorder := httptest.NewRecorder()
	nonAdmin.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("non-admin audit status = %d, want 403", recorder.Code)
	}

	static, err := NewStaticTokenAuthorizer(testBrokerToken)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(&fakeOperator{}, static, WithAuditor(auditor))
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	client, err := newClient(httpServer.Client(), httpServer.URL, testBrokerToken)
	if err != nil {
		t.Fatal(err)
	}
	events, err := client.Audit(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 ||
		events[0].RequestID != "seed-event" ||
		events[0].Operation != "backup.create" {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestFileAuditorRedactsCredentialBearingFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	auditor, err := OpenFileAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	defer auditor.Close()
	if err := auditor.Record(context.Background(), AuditEvent{
		Actor:     "token=AUDIT_FIELD_SECRET_CANARY",
		Operation: "summary.read",
		Method:    http.MethodGet,
		Path:      "/v1/summary",
		Outcome:   "succeeded",
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("AUDIT_FIELD_SECRET_CANARY")) ||
		!bytes.Contains(data, []byte("[REDACTED]")) {
		t.Fatalf("audit field was not redacted: %s", data)
	}
}

func TestFileAuditorRedactsLegacyFieldsWhenReading(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	legacy := `{"actor":"password=AUDIT_READ_SECRET_CANARY","operation":"summary.read","method":"GET","path":"/v1/summary","outcome":"succeeded"}` + "\n"
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	auditor, err := OpenFileAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	defer auditor.Close()
	events, err := auditor.Recent(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 ||
		strings.Contains(events[0].Actor, "AUDIT_READ_SECRET_CANARY") ||
		!strings.Contains(events[0].Actor, "[REDACTED]") {
		t.Fatalf("legacy audit event was not redacted: %#v", events)
	}
}

func TestTokenFileIsPersistentAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime", "client.token")
	token, err := EnsureTokenFile(TokenFileOptions{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := EnsureTokenFile(TokenFileOptions{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if token != reloaded {
		t.Fatal("broker token rotated unexpectedly")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("token mode = %o, want 640", info.Mode().Perm())
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokenFile(path); err == nil {
		t.Fatal("world-readable token file was accepted")
	}
}

func TestTokenFileProvisioningRepairsRequestedGroupAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership proof runs in the Linux amd64 QA container")
	}
	parent := filepath.Join(t.TempDir(), "runtime")
	path := filepath.Join(parent, "client.token")
	firstGID := 42001
	token, err := EnsureTokenFile(TokenFileOptions{Path: path, GID: &firstGID})
	if err != nil {
		t.Fatal(err)
	}
	assertTokenOwnership(t, parent, 0, firstGID)
	assertTokenOwnership(t, path, 0, firstGID)

	secondGID := 42002
	reloaded, err := EnsureTokenFile(TokenFileOptions{Path: path, GID: &secondGID})
	if err != nil {
		t.Fatal(err)
	}
	if reloaded != token {
		t.Fatal("ownership repair rotated the broker token")
	}
	assertTokenOwnership(t, parent, 0, secondGID)
	assertTokenOwnership(t, path, 0, secondGID)
	if _, err := LoadTokenFile(path); err != nil {
		t.Fatalf("repaired token is unreadable: %v", err)
	}
}

func TestInvalidTokenFileIsNotReownedAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership proof runs in the Linux amd64 QA container")
	}
	parent := filepath.Join(t.TempDir(), "runtime")
	if err := os.MkdirAll(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "client.token")
	contents := []byte(strings.Repeat("a", 32) + "\n")
	if err := os.WriteFile(path, contents, 0o640); err != nil {
		t.Fatal(err)
	}
	firstGID := 42003
	if err := os.Chown(path, 0, firstGID); err != nil {
		t.Fatal(err)
	}

	requestedGID := 42004
	if _, err := EnsureTokenFile(TokenFileOptions{
		Path: path,
		GID:  &requestedGID,
	}); err == nil {
		t.Fatal("invalid token file was accepted")
	}
	assertTokenOwnership(t, path, 0, firstGID)
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, contents) {
		t.Fatal("invalid token contents changed before validation failed")
	}
}

func TestTokenFileRejectsInvalidRequestedGroup(t *testing.T) {
	gid := -1
	if _, err := EnsureTokenFile(TokenFileOptions{
		Path: filepath.Join(t.TempDir(), "client.token"),
		GID:  &gid,
	}); err == nil {
		t.Fatal("negative broker token group ID was accepted")
	}
}

func assertTokenOwnership(t *testing.T, path string, uid, gid int) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("%s has no numeric ownership metadata", path)
	}
	if int(stat.Uid) != uid || int(stat.Gid) != gid {
		t.Fatalf(
			"%s ownership = %d:%d, want %d:%d",
			path,
			stat.Uid,
			stat.Gid,
			uid,
			gid,
		)
	}
}

func TestStaticTokenRequiresCanonical256BitBase64URL(t *testing.T) {
	valid, err := NewStaticTokenAuthorizer(testBrokerToken)
	if err != nil || valid == nil {
		t.Fatalf("canonical token rejected: %v", err)
	}
	for name, token := range map[string]string{
		"short legacy value":  strings.Repeat("a", 32),
		"padded":              testBrokerToken + "=",
		"leading whitespace":  " " + testBrokerToken,
		"trailing whitespace": testBrokerToken + " ",
		"embedded newline":    testBrokerToken[:20] + "\n" + testBrokerToken[20:],
		"non URL alphabet":    testBrokerToken[:42] + "+",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewStaticTokenAuthorizer(token); err == nil {
				t.Fatal("noncanonical broker token was accepted")
			}
		})
	}
}

func TestTokenFileRequiresExactModeAndSingleCanonicalLine(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		mode     os.FileMode
		wantOK   bool
	}{
		{
			name:     "canonical with newline",
			contents: testBrokerToken + "\n",
			mode:     0o640,
			wantOK:   true,
		},
		{
			name:     "canonical without newline",
			contents: testBrokerToken,
			mode:     0o640,
			wantOK:   true,
		},
		{
			name:     "legacy weak value",
			contents: strings.Repeat("a", 32) + "\n",
			mode:     0o640,
		},
		{
			name:     "multiple lines",
			contents: testBrokerToken + "\n" + testBrokerToken + "\n",
			mode:     0o640,
		},
		{
			name:     "CRLF",
			contents: testBrokerToken + "\r\n",
			mode:     0o640,
		},
		{
			name:     "leading whitespace",
			contents: " " + testBrokerToken,
			mode:     0o640,
		},
		{
			name:     "owner only",
			contents: testBrokerToken + "\n",
			mode:     0o600,
		},
		{
			name:     "group writable",
			contents: testBrokerToken + "\n",
			mode:     0o660,
		},
		{
			name:     "owner executable",
			contents: testBrokerToken + "\n",
			mode:     0o740,
		},
		{
			name:     "world readable",
			contents: testBrokerToken + "\n",
			mode:     0o644,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "client.token")
			if err := os.WriteFile(path, []byte(test.contents), test.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			token, err := LoadTokenFile(path)
			if test.wantOK {
				if err != nil {
					t.Fatal(err)
				}
				if token != testBrokerToken {
					t.Fatalf("token = %q", token)
				}
				return
			}
			if err == nil {
				t.Fatal("unsafe token file was accepted")
			}
		})
	}
}

func TestConcurrentTokenProvisioningConvergesWithoutStagingCopies(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "runtime")
	if err := os.MkdirAll(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "client.token")
	const workers = 16
	start := make(chan struct{})
	tokens := make(chan string, workers)
	errs := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			token, err := EnsureTokenFile(TokenFileOptions{Path: path})
			tokens <- token
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(tokens)
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent EnsureTokenFile failed: %v", err)
		}
	}
	var winner string
	for token := range tokens {
		if winner == "" {
			winner = token
		}
		if token != winner {
			t.Fatalf("concurrent tokens differ: %q != %q", token, winner)
		}
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "client.token" {
		t.Fatalf("token directory contains staging residue: %#v", entries)
	}
}

func TestExclusiveTokenWriteCleansStagingLinkOnCollision(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "client.token")
	if err := os.WriteFile(path, []byte(testBrokerToken+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	err = writeTokenFileExclusive(
		root,
		"client.token",
		[]byte(testBrokerToken+"\n"),
		nil,
	)
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("collision error = %v, want os.ErrExist", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "client.token" {
		t.Fatalf("token collision left staging residue: %#v", entries)
	}
}

func TestProvisionedBrokerAndConsoleTokensAreDistinct(t *testing.T) {
	parent := t.TempDir()
	brokerToken, err := EnsureTokenFile(TokenFileOptions{
		Path: filepath.Join(parent, "client.token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	consoleToken, err := EnsureTokenFile(TokenFileOptions{
		Path: filepath.Join(parent, "console.token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if brokerToken == consoleToken {
		t.Fatal("broker and console tokens are identical")
	}
}

func TestFileAuditorAndTokenRejectSymlinks(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte(testBrokerToken), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokenFile(link); err == nil {
		t.Fatal("symlink token was accepted")
	}
	if _, err := OpenFileAuditor(link); err == nil {
		t.Fatal("symlink audit log was accepted")
	}
}

func TestUnixBrokerRoundTripAndSocketPermissions(t *testing.T) {
	authorizer, err := NewStaticTokenAuthorizer(testBrokerToken)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(&fakeOperator{}, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// Darwin limits Unix-domain socket paths to roughly 104 bytes. The default
	// per-user temporary directory is already long enough that the broker's
	// private staging component can cross that limit.
	socketRoot, err := os.MkdirTemp("/tmp", "sdbx-broker-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketRoot) })
	socketPath := filepath.Join(socketRoot, "runtime", "sdbxd.sock")
	result := make(chan error, 1)
	go func() {
		result <- ServeUnix(ctx, server.Handler(), UnixServerOptions{
			SocketPath: socketPath,
			SocketMode: 0o660,
		})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		info, statErr := os.Lstat(socketPath)
		if statErr == nil {
			if info.Mode().Perm() != 0o660 || info.Mode()&os.ModeSocket == 0 {
				t.Fatalf("socket mode = %v, want Unix socket 0660", info.Mode())
			}
			break
		}
		select {
		case serveErr := <-result:
			t.Fatalf("broker stopped before creating socket: %v", serveErr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("broker socket was not created: %v", statErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	client, err := NewUnixClient(socketPath, testBrokerToken)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := client.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Domain != "box.example.test" {
		t.Fatalf("summary = %#v", summary)
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("broker did not shut down after cancellation")
	}
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("broker socket survived shutdown: %v", err)
	}
}

func TestClientClearsPassphraseBuffer(t *testing.T) {
	server := testBrokerServer(t, &fakeOperator{})
	defer server.Close()
	client, err := newClient(server.Client(), server.URL, testBrokerToken)
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("temporary secret")
	if _, err := client.CreateBackup(
		context.Background(),
		management.CreateBackupRequest{Passphrase: passphrase},
	); err != nil {
		t.Fatal(err)
	}
	for _, value := range passphrase {
		if value != 0 {
			t.Fatal("client did not clear passphrase buffer")
		}
	}
}
