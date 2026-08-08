package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/get-sdbx/sdbx/internal/management"
	"github.com/get-sdbx/sdbx/internal/redact"
)

type Server struct {
	operator         management.Operator
	authorizer       Authorizer
	auditor          Auditor
	recentAuthMaxAge time.Duration
}

type ServerOption func(*Server) error

func WithAuditor(auditor Auditor) ServerOption {
	return func(server *Server) error {
		if auditor == nil {
			return fmt.Errorf("broker auditor is required")
		}
		server.auditor = auditor
		return nil
	}
}

func WithRecentAuthMaxAge(maxAge time.Duration) ServerOption {
	return func(server *Server) error {
		if maxAge <= 0 {
			return fmt.Errorf("recent authentication age must be positive")
		}
		server.recentAuthMaxAge = maxAge
		return nil
	}
}

func NewServer(
	operator management.Operator,
	authorizer Authorizer,
	options ...ServerOption,
) (*Server, error) {
	if operator == nil {
		return nil, fmt.Errorf("management operator is required")
	}
	if authorizer == nil {
		return nil, fmt.Errorf("broker authorizer is required")
	}
	server := &Server{
		operator:         operator,
		authorizer:       authorizer,
		recentAuthMaxAge: 10 * time.Minute,
	}
	for _, option := range options {
		if err := option(server); err != nil {
			return nil, err
		}
	}
	return server, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	mux.HandleFunc("GET /v1/impact", s.handleImpact)
	mux.HandleFunc("GET /v1/summary", s.handleSummary)
	mux.HandleFunc("GET /v1/security", s.handleSecurity)
	mux.HandleFunc("GET /v1/diagnostics", s.handleDiagnostics)
	mux.HandleFunc("GET /v1/audit", s.handleAudit)
	mux.HandleFunc("GET /v1/services", s.handleServices)
	mux.HandleFunc("GET /v1/logs", s.handleLogs)
	mux.HandleFunc("GET /v1/addons", s.handleAddons)
	mux.HandleFunc("POST /v1/addons", s.handleSetAddon)
	mux.HandleFunc("GET /v1/settings", s.handleSettings)
	mux.HandleFunc("POST /v1/settings", s.handleSetSetting)
	mux.HandleFunc("GET /v1/backups", s.handleBackups)
	mux.HandleFunc("POST /v1/backups", s.handleCreateBackup)
	mux.HandleFunc("POST /v1/backups/restore", s.handleRestoreBackup)
	mux.HandleFunc("POST /v1/backups/delete", s.handleDeleteBackup)
	mux.HandleFunc("POST /v1/stack", s.handleStack)
	return s.secure(s.authorize(s.enforcePolicy(s.audit(mux))))
}

func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, err := s.authorizer.Authorize(r)
		if err != nil || !actorHasIdentity(actor) {
			s.writeError(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r.WithContext(withActor(r.Context(), actor)))
	})
}

func (s *Server) enforcePolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requiresAdminGroup(r) {
			next.ServeHTTP(w, r)
			return
		}
		actor, ok := ActorFromContext(r.Context())
		if !ok || !hasGroup(actor.Groups, AdminGroup) {
			s.writeError(w, r, http.StatusForbidden, "admin_group_required")
			return
		}
		if requiresRecentAuthentication(r) {
			authenticatedAt := time.Unix(actor.AuthTime, 0)
			if actor.AuthTime <= 0 ||
				authenticatedAt.After(time.Now().Add(time.Minute)) ||
				time.Since(authenticatedAt) > s.recentAuthMaxAge {
				s.writeError(w, r, http.StatusForbidden, "recent_authentication_required")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func requiresAdminGroup(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return true
	}
	switch r.URL.Path {
	case "/v1/audit", "/v1/logs", "/v1/settings", "/v1/backups":
		return true
	default:
		return false
	}
}

func (s *Server) audit(next http.Handler) http.Handler {
	if s.auditor == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		actor, _ := ActorFromContext(r.Context())
		event := AuditEvent{
			Timestamp: time.Now().UTC(),
			RequestID: newRequestID(),
			Operation: operationName(r),
			Method:    r.Method,
			Path:      r.URL.Path,
			Outcome:   "started",
		}
		if actor != nil {
			event.Actor = actor.Subject
			event.Groups = append([]string(nil), actor.Groups...)
		}
		if err := s.auditor.Record(r.Context(), event); err != nil {
			s.writeError(w, r, http.StatusServiceUnavailable, "audit_unavailable")
			return
		}
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		event.Timestamp = time.Now().UTC()
		event.Status = recorder.status
		event.Outcome = "succeeded"
		if recorder.status >= http.StatusBadRequest {
			event.Outcome = "failed"
		}
		if err := s.auditor.Record(context.Background(), event); err != nil {
			fmt.Fprintf(os.Stderr, "broker audit completion failed for request %s\n", event.RequestID)
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusRecorder) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.wrote = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

type actorContextKey struct{}

func withActor(ctx context.Context, actor *Actor) context.Context {
	return context.WithValue(ctx, actorContextKey{}, actor)
}

func ActorFromContext(ctx context.Context) (*Actor, bool) {
	actor, ok := ctx.Value(actorContextKey{}).(*Actor)
	if !ok || !actorHasIdentity(actor) {
		return nil, false
	}
	return actor, true
}

func hasGroup(groups []string, expected string) bool {
	for _, group := range groups {
		if subtleConstantStringEqual(group, expected) {
			return true
		}
	}
	return false
}

func subtleConstantStringEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}

func requiresRecentAuthentication(r *http.Request) bool {
	switch r.URL.Path {
	case "/v1/addons",
		"/v1/settings",
		"/v1/backups/restore",
		"/v1/backups/delete",
		"/v1/stack":
		return true
	default:
		return false
	}
}

func operationName(r *http.Request) string {
	switch r.URL.Path {
	case "/v1/addons":
		return "addon.change"
	case "/v1/settings":
		return "setting.change"
	case "/v1/backups":
		return "backup.create"
	case "/v1/backups/restore":
		return "backup.restore"
	case "/v1/backups/delete":
		return "backup.delete"
	case "/v1/stack":
		return "stack.change"
	default:
		return "management.request"
	}
}

func newRequestID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "unavailable"
	}
	return hex.EncodeToString(raw[:])
}

func (s *Server) handleImpact(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := s.operator.Preview(ctx, management.ImpactRequest{
		Operation: r.URL.Query().Get("operation"),
		Target:    r.URL.Query().Get("target"),
	})
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "impact_preview_failed")
		return
	}
	s.writeData(w, http.StatusOK, result)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.writeData(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"api_version": APIVersion,
	})
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	readValue(s, w, r, "summary_failed", s.operator.Summary)
}

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	readValue(s, w, r, "security_failed", s.operator.Security)
}

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	result, err := s.operator.Diagnostics(ctx)
	if err != nil {
		s.writeError(w, r, http.StatusBadGateway, "diagnostics_failed")
		return
	}
	s.writeData(w, http.StatusOK, result)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.auditor.(AuditReader)
	if !ok {
		s.writeError(w, r, http.StatusServiceUnavailable, "audit_unavailable")
		return
	}
	limit, err := parseBoundedInt(r.URL.Query().Get("limit"), 1, 500)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid_audit_limit")
		return
	}
	result, err := reader.Recent(r.Context(), limit)
	if err != nil {
		s.writeError(w, r, http.StatusBadGateway, "audit_read_failed")
		return
	}
	s.writeData(w, http.StatusOK, result)
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	readValue(s, w, r, "services_failed", s.operator.Services)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	tail, err := parseBoundedInt(r.URL.Query().Get("tail"), 1, 1000)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid_log_tail")
		return
	}
	result, err := s.operator.Logs(r.Context(), management.LogsRequest{
		Service: r.URL.Query().Get("service"),
		Tail:    tail,
	})
	if err != nil {
		s.writeError(w, r, http.StatusBadGateway, "logs_failed")
		return
	}
	if result != nil {
		result.Logs = redact.Text(result.Logs)
	}
	s.writeData(w, http.StatusOK, result)
}

func (s *Server) handleAddons(w http.ResponseWriter, r *http.Request) {
	readValue(s, w, r, "addons_failed", s.operator.Addons)
}

func (s *Server) handleSetAddon(w http.ResponseWriter, r *http.Request) {
	var request management.AddonRequest
	if !s.decode(w, r, &request) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	result, err := s.operator.SetAddon(ctx, request)
	if err != nil {
		s.writeOperationError(w, r, err, "addon_change_failed")
		return
	}
	s.writeData(w, http.StatusOK, result)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	readValue(s, w, r, "settings_failed", s.operator.Settings)
}

func (s *Server) handleSetSetting(w http.ResponseWriter, r *http.Request) {
	var request management.SettingRequest
	if !s.decode(w, r, &request) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	result, err := s.operator.SetSetting(ctx, request)
	if err != nil {
		s.writeOperationError(w, r, err, "setting_change_failed")
		return
	}
	s.writeData(w, http.StatusOK, result)
}

func (s *Server) handleBackups(w http.ResponseWriter, r *http.Request) {
	readValue(s, w, r, "backups_failed", s.operator.Backups)
}

func (s *Server) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	var request createBackupWireRequest
	if !s.decode(w, r, &request) {
		return
	}
	defer zeroBytes(request.Passphrase)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	result, err := s.operator.CreateBackup(ctx, management.CreateBackupRequest{
		Recipient:  request.Recipient,
		Passphrase: request.Passphrase,
	})
	if err != nil {
		s.writeOperationError(w, r, err, "backup_create_failed")
		return
	}
	s.writeData(w, http.StatusOK, result)
}

func (s *Server) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	var request restoreBackupWireRequest
	if !s.decode(w, r, &request) {
		return
	}
	defer zeroBytes(request.Passphrase)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	err := s.operator.RestoreBackup(ctx, management.RestoreBackupRequest{
		Name:                 request.Name,
		Passphrase:           request.Passphrase,
		Confirm:              request.Confirm,
		RelocateManagedRoots: request.RelocateManagedRoots,
	})
	if err != nil {
		s.writeOperationError(w, r, err, "backup_restore_failed")
		return
	}
	s.writeData(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDeleteBackup(w http.ResponseWriter, r *http.Request) {
	var request management.DeleteBackupRequest
	if !s.decode(w, r, &request) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	if err := s.operator.DeleteBackup(ctx, request); err != nil {
		s.writeOperationError(w, r, err, "backup_delete_failed")
		return
	}
	s.writeData(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleStack(w http.ResponseWriter, r *http.Request) {
	var request management.StackRequest
	if !s.decode(w, r, &request) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	if err := s.operator.Stack(ctx, request); err != nil {
		s.writeOperationError(w, r, err, "stack_action_failed")
		return
	}
	s.writeData(w, http.StatusOK, map[string]bool{"ok": true})
}

func readValue[T any](
	s *Server,
	w http.ResponseWriter,
	r *http.Request,
	code string,
	fn func(context.Context) (T, error),
) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := fn(ctx)
	if err != nil {
		s.writeError(w, r, http.StatusBadGateway, code)
		return
	}
	s.writeData(w, http.StatusOK, result)
}

func (s *Server) decode(
	w http.ResponseWriter,
	r *http.Request,
	target any,
) bool {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		s.writeError(w, r, http.StatusUnsupportedMediaType, "json_required")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid_request")
		return false
	}
	defer zeroBytes(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid_request")
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		s.writeError(w, r, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func (s *Server) writeOperationError(
	w http.ResponseWriter,
	r *http.Request,
	err error,
	fallbackCode string,
) {
	if errors.Is(err, management.ErrProjectUnverified) {
		s.writeError(w, r, http.StatusConflict, "project_not_verified")
		return
	}
	s.writeError(w, r, http.StatusBadRequest, fallbackCode)
}

func (s *Server) writeData(w http.ResponseWriter, status int, data any) {
	raw, err := json.Marshal(data)
	if err != nil {
		s.writeBareError(w, http.StatusInternalServerError, "response_encoding_failed")
		return
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope{
		APIVersion: APIVersion,
		Data:       raw,
	})
}

func (s *Server) writeError(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	code string,
) {
	actor, _ := ActorFromContext(r.Context())
	subject := "unauthenticated"
	if actor != nil && actor.Subject != "" {
		subject = safeLogField(actor.Subject)
	}
	fmt.Fprintf(
		os.Stderr,
		"broker request %s for %s failed [%s]\n",
		safeLogField(r.URL.Path),
		subject,
		code,
	)
	s.writeBareError(w, status, code)
}

func safeLogField(value string) string {
	value = boundedAuditField(value)
	return strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return '?'
		}
		return character
	}, value)
}

func (s *Server) writeBareError(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope{
		APIVersion: APIVersion,
		Error: &APIError{
			Code:    code,
			Message: "The broker rejected or could not complete the operation.",
		},
	})
}

func parseBoundedInt(raw string, minimum, maximum int) (int, error) {
	if raw == "" {
		return 200, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("integer is outside the allowed range")
	}
	return value, nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
