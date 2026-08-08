package webui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/get-sdbx/sdbx/internal/management"
	"github.com/get-sdbx/sdbx/internal/redact"
)

const maxAPIRequestBytes = 64 << 10

//go:embed static/*
var staticFS embed.FS

type Server struct {
	operator   management.Operator
	token      string
	index      []byte
	publicHost string
}

type Options struct {
	Operator management.Operator
	Token    string
	// PublicHost enables the remote console trust path. Requests for this host
	// must arrive over a verified mTLS connection and carry an Authelia admin
	// identity copied by the trusted proxy.
	PublicHost string
}

func New(options Options) (*Server, error) {
	if options.Operator == nil {
		return nil, fmt.Errorf("management broker client is required")
	}
	publicHost := strings.TrimSpace(options.PublicHost)
	if publicHost != "" && strings.ContainsAny(publicHost, "/:@\\\x00\r\n\t ") {
		return nil, fmt.Errorf("public console hostname is invalid")
	}

	token := options.Token
	if token == "" {
		var err error
		token, err = newToken()
		if err != nil {
			return nil, err
		}
	}

	index, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		return nil, fmt.Errorf("load management console index: %w", err)
	}

	return &Server{
		operator:   options.Operator,
		token:      token,
		index:      index,
		publicHost: publicHost,
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /static/{asset}", s.handleStaticAsset)
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /api/summary", s.requireClient(s.handleSummary))
	mux.HandleFunc("GET /api/security", s.requireClient(s.handleSecurity))
	mux.HandleFunc("GET /api/diagnostics", s.requireClient(s.handleDiagnostics))
	mux.HandleFunc("GET /api/audit", s.requireClient(s.handleAudit))
	mux.HandleFunc("GET /api/impact", s.requireClient(s.handleImpact))
	mux.HandleFunc("GET /api/status", s.requireClient(s.handleStatus))
	mux.HandleFunc("GET /api/logs", s.requireClient(s.handleLogs))
	mux.HandleFunc("GET /api/addons", s.requireClient(s.handleAddons))
	mux.HandleFunc("POST /api/addons/{name}/{action}", s.requireMutation(s.handleAddonAction))
	mux.HandleFunc("GET /api/config", s.requireClient(s.handleConfig))
	mux.HandleFunc("POST /api/config/{key}", s.requireMutation(s.handleConfigSet))
	mux.HandleFunc("GET /api/backups", s.requireClient(s.handleBackups))
	mux.HandleFunc("POST /api/backups/{name}/{action}", s.requireMutation(s.handleBackupAction))
	mux.HandleFunc("POST /api/actions/{action}", s.requireMutation(s.handleAction))

	return s.securityHeaders(s.validateHost(mux))
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := w.Header()
		headers.Set("Cache-Control", "no-store")
		headers.Set(
			"Content-Security-Policy",
			"default-src 'self'; base-uri 'none'; connect-src 'self'; "+
				"font-src 'self'; form-action 'self'; frame-ancestors 'none'; "+
				"img-src 'self' data:; object-src 'none'; script-src 'self'; "+
				"style-src 'self'",
		)
		headers.Set("Cross-Origin-Opener-Policy", "same-origin")
		headers.Set("Cross-Origin-Resource-Policy", "same-origin")
		headers.Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
		headers.Set("Referrer-Policy", "no-referrer")
		headers.Set("X-Content-Type-Options", "nosniff")
		headers.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) validateHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackHTTPHost(r.Host) &&
			!(equalHTTPHost(r.Host, s.publicHost) && s.isRemoteAdminRequest(r)) {
			writePublicError(
				w,
				http.StatusMisdirectedRequest,
				"invalid_host",
				"Requests must use a localhost or loopback host.",
			)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func equalHTTPHost(hostport, expected string) bool {
	host := hostport
	if parsed, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsed
	}
	return expected != "" && strings.EqualFold(host, expected)
}

func (s *Server) isRemoteAdminRequest(r *http.Request) bool {
	if s.publicHost == "" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 ||
		strings.TrimSpace(r.Header.Get("Remote-User")) == "" {
		return false
	}
	leaf := r.TLS.VerifiedChains[0][0]
	if leaf.VerifyHostname("sdbx-traefik") != nil {
		return false
	}
	for _, group := range strings.Split(r.Header.Get("Remote-Groups"), ",") {
		if strings.TrimSpace(group) == "admins" {
			return true
		}
	}
	return false
}

func isLoopbackHTTPHost(hostport string) bool {
	host := hostport
	if parsed, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsed
	} else if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		host = strings.Trim(hostport, "[]")
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) Token() string {
	return s.token
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(s.index)
}

func (s *Server) handleStaticAsset(w http.ResponseWriter, r *http.Request) {
	asset := r.PathValue("asset")
	contentType := ""
	switch asset {
	case "app.js":
		contentType = "text/javascript; charset=utf-8"
	case "styles.css":
		contentType = "text/css; charset=utf-8"
	case "favicon.svg":
		contentType = "image/svg+xml"
	default:
		http.NotFound(w, r)
		return
	}
	content, err := staticFS.ReadFile("static/" + asset)
	if err != nil {
		writeInternalError(
			w,
			r,
			http.StatusInternalServerError,
			"asset_unavailable",
			err,
		)
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(content)
}

func (s *Server) handleImpact(w http.ResponseWriter, r *http.Request) {
	impact, err := s.operator.Preview(r.Context(), management.ImpactRequest{
		Operation: r.URL.Query().Get("operation"),
		Target:    r.URL.Query().Get("target"),
	})
	if err != nil {
		writeInternalError(w, r, http.StatusBadRequest, "impact_preview_failed", err)
		return
	}
	writeJSON(w, http.StatusOK, impact)
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := s.operator.Summary(r.Context())
	if err != nil {
		writeInternalError(w, r, http.StatusBadGateway, "summary_unavailable", err)
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	report, err := s.operator.Security(r.Context())
	if err != nil {
		writeInternalError(w, r, http.StatusBadGateway, "security_unavailable", err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	report, err := s.operator.Diagnostics(ctx)
	if err != nil {
		writeInternalError(w, r, http.StatusBadGateway, "diagnostics_unavailable", err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

type auditReader interface {
	Audit(context.Context, int) ([]management.AuditEvent, error)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	operator, ok := s.operator.(auditReader)
	if !ok {
		writePublicError(
			w,
			http.StatusServiceUnavailable,
			"audit_unavailable",
			"Audit history is unavailable through this management client.",
		)
		return
	}
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit < 1 || limit > 500 {
		limit = 100
	}
	events, err := operator.Audit(r.Context(), limit)
	if err != nil {
		writeInternalError(w, r, http.StatusBadGateway, "audit_unavailable", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	services, err := s.operator.Services(r.Context())
	if err != nil {
		writeInternalError(w, r, http.StatusBadGateway, "status_unavailable", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"services": services})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	tail, _ := strconv.Atoi(r.URL.Query().Get("tail"))
	if tail <= 0 || tail > 1000 {
		tail = 200
	}

	service := r.URL.Query().Get("service")
	result, err := s.operator.Logs(r.Context(), management.LogsRequest{
		Service: service,
		Tail:    tail,
	})
	if err != nil {
		writeInternalError(w, r, http.StatusBadGateway, "logs_unavailable", err)
		return
	}
	if result != nil {
		result.Logs = redact.Text(result.Logs)
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAddons(w http.ResponseWriter, r *http.Request) {
	addons, err := s.operator.Addons(r.Context())
	if err != nil {
		writeInternalError(w, r, http.StatusInternalServerError, "addons_unavailable", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"addons": addons})
}

func (s *Server) handleAddonAction(w http.ResponseWriter, r *http.Request) {
	result, err := s.operator.SetAddon(r.Context(), management.AddonRequest{
		Name:    r.PathValue("name"),
		Action:  r.PathValue("action"),
		Confirm: r.Header.Get("X-SDBX-Confirm"),
	})
	if err != nil {
		if errors.Is(err, management.ErrProjectUnverified) {
			writeInternalError(w, r, http.StatusConflict, "project_not_verified", err)
			return
		}
		writeInternalError(w, r, http.StatusInternalServerError, "addon_change_failed", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "addon": result})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	document, err := s.operator.Settings(r.Context())
	if err != nil {
		writeInternalError(w, r, http.StatusBadGateway, "settings_unavailable", err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (s *Server) handleConfigSet(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Value                       string `json:"value"`
		ConfirmUnprotectedDownloads bool   `json:"confirmUnprotectedDownloads"`
	}
	if err := decodeJSONBody(w, r, &payload); err != nil {
		writePublicError(
			w,
			http.StatusBadRequest,
			"invalid_request",
			"The request body is invalid.",
		)
		return
	}

	result, err := s.operator.SetSetting(r.Context(), management.SettingRequest{
		Key:                         r.PathValue("key"),
		Value:                       payload.Value,
		ConfirmUnprotectedDownloads: payload.ConfirmUnprotectedDownloads,
		Confirm:                     r.Header.Get("X-SDBX-Confirm"),
	})
	if err != nil {
		if errors.Is(err, management.ErrProjectUnverified) {
			writeInternalError(w, r, http.StatusConflict, "project_not_verified", err)
			return
		}
		writePublicError(
			w,
			http.StatusBadRequest,
			"invalid_setting",
			"The setting value is invalid.",
		)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "setting": result})
}

func (s *Server) handleBackups(w http.ResponseWriter, r *http.Request) {
	backups, err := s.operator.Backups(r.Context())
	if err != nil {
		writeInternalError(w, r, http.StatusInternalServerError, "backups_unavailable", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"backups": backups})
}

func (s *Server) handleBackupAction(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	action := r.PathValue("action")
	if r.Header.Get("X-SDBX-Confirm") != action {
		writePublicError(
			w,
			http.StatusBadRequest,
			"confirmation_required",
			"An exact confirmation header is required for this backup action.",
		)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	switch action {
	case "restore":
		var payload struct {
			Passphrase           string `json:"passphrase"`
			RelocateManagedRoots bool   `json:"relocateManagedRoots"`
		}
		if err := decodeJSONBody(w, r, &payload); err != nil {
			writePublicError(
				w,
				http.StatusBadRequest,
				"invalid_request",
				"Encrypted restore credentials are required.",
			)
			return
		}
		passphrase := []byte(payload.Passphrase)
		payload.Passphrase = ""
		defer wipeBytes(passphrase)
		if err := s.operator.RestoreBackup(ctx, management.RestoreBackupRequest{
			Name:                 name,
			Passphrase:           passphrase,
			Confirm:              action,
			RelocateManagedRoots: payload.RelocateManagedRoots,
		}); err != nil {
			writeInternalError(w, r, http.StatusBadRequest, "restore_failed", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "backup": name, "action": action})
	case "delete":
		if err := s.operator.DeleteBackup(ctx, management.DeleteBackupRequest{
			Name:    name,
			Confirm: action,
		}); err != nil {
			writeInternalError(w, r, http.StatusInternalServerError, "backup_delete_failed", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "backup": name, "action": action})
	default:
		writePublicError(
			w,
			http.StatusBadRequest,
			"unsupported_action",
			"Unsupported backup action.",
		)
	}
}

func (s *Server) handleAction(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	action := r.PathValue("action")
	switch action {
	case "up", "down", "restart":
		writeOperationStatus(
			w,
			r,
			"stack_"+action+"_failed",
			s.operator.Stack(ctx, management.StackRequest{
				Action:  action,
				Confirm: r.Header.Get("X-SDBX-Confirm"),
			}),
		)
	case "backup":
		var payload struct {
			Recipient  string `json:"recipient"`
			Passphrase string `json:"passphrase"`
		}
		if err := decodeJSONBody(w, r, &payload); err != nil {
			writePublicError(
				w,
				http.StatusBadRequest,
				"invalid_request",
				"Encrypted backup credentials are required.",
			)
			return
		}
		passphrase := []byte(payload.Passphrase)
		payload.Passphrase = ""
		defer wipeBytes(passphrase)
		created, err := s.operator.CreateBackup(ctx, management.CreateBackupRequest{
			Recipient:  payload.Recipient,
			Passphrase: passphrase,
		})
		if err != nil {
			writeInternalError(w, r, http.StatusBadRequest, "backup_create_failed", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "backup": created})
	default:
		writePublicError(
			w,
			http.StatusBadRequest,
			"unsupported_action",
			"Unsupported stack action.",
		)
	}
}

func wipeBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func (s *Server) requireClient(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provided := []byte(r.Header.Get("X-SDBX-Token"))
		expected := []byte(s.token)
		if subtle.ConstantTimeCompare(provided, expected) != 1 &&
			!s.isRemoteAdminRequest(r) {
			writePublicError(
				w,
				http.StatusForbidden,
				"invalid_token",
				"The management request token is invalid.",
			)
			return
		}
		next(w, r)
	}
}

func (s *Server) requireMutation(next http.HandlerFunc) http.HandlerFunc {
	return s.requireClient(func(w http.ResponseWriter, r *http.Request) {
		if !sameRequestOrigin(r) {
			writePublicError(
				w,
				http.StatusForbidden,
				"invalid_origin",
				"Management requests must originate from this console.",
			)
			return
		}
		next(w, r)
	})
}

func sameRequestOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return parsed.Scheme == scheme && strings.EqualFold(parsed.Host, r.Host)
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, target any) error {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		return fmt.Errorf("Content-Type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIRequestBytes)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("invalid JSON request body")
	}
	defer wipeBytes(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON request body")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("request body must contain exactly one JSON object")
	}
	return nil
}

func writeOperationStatus(
	w http.ResponseWriter,
	r *http.Request,
	code string,
	err error,
) {
	if err != nil {
		writeInternalError(w, r, http.StatusInternalServerError, code, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		status = http.StatusInternalServerError
		encoded = []byte(
			`{"code":"response_encoding_failed","error":"The response could not be encoded."}`,
		)
	}
	encoded = append(encoded, '\n')
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}

func writePublicError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{
		"code":  code,
		"error": message,
	})
}

func writeInternalError(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	code string,
	err error,
) {
	// Keep backend error strings out of browser responses and logs: Docker,
	// filesystem, and integration failures may contain host paths or
	// credential-adjacent values. The stable code is sufficient to correlate
	// a failure without copying secrets into durable output.
	_ = err
	fmt.Fprintf(
		os.Stderr,
		"web console request %q failed [%s]\n",
		redact.Text(r.URL.Path),
		code,
	)
	writePublicError(
		w,
		status,
		code,
		"The operation failed. Review the local SDBX logs using this error code.",
	)
}

func newToken() (string, error) {
	bytes := make([]byte, 32)
	defer wipeBytes(bytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return strings.TrimRight(base64.URLEncoding.EncodeToString(bytes), "="), nil
}
