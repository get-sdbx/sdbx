package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

type OIDCOptions struct {
	Issuer     string
	ClientID   string
	HTTPClient *http.Client
}

type idTokenVerifier interface {
	Verify(context.Context, string) (*oidc.IDToken, error)
}

type OIDCAuthorizer struct {
	verifier idTokenVerifier
	clientID string
}

const (
	maxOIDCResponseBody = 1 << 20
	maxOIDCRedirects    = 10
	defaultOIDCTimeout  = 15 * time.Second
)

func NewOIDCAuthorizer(
	ctx context.Context,
	options OIDCOptions,
) (*OIDCAuthorizer, error) {
	issuer := strings.TrimRight(strings.TrimSpace(options.Issuer), "/")
	clientID := strings.TrimSpace(options.ClientID)
	if issuer == "" || clientID == "" {
		return nil, fmt.Errorf("OIDC issuer and client ID are required")
	}
	parsed, err := url.Parse(issuer)
	if err != nil ||
		!parsed.IsAbs() ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return nil, fmt.Errorf("OIDC issuer must be an absolute URL")
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	loopback := strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback()
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback) {
		return nil, fmt.Errorf("OIDC issuer must use HTTPS")
	}
	client := secureOIDCHTTPClient(options.HTTPClient, parsed)
	ctx = oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	var discovered struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := provider.Claims(&discovered); err != nil {
		return nil, fmt.Errorf("inspect OIDC provider metadata: %w", err)
	}
	jwksURI, err := url.Parse(discovered.JWKSURI)
	if err != nil || !jwksURI.IsAbs() || !sameOIDCOrigin(parsed, jwksURI) {
		return nil, fmt.Errorf("OIDC JWKS URI must use the issuer origin")
	}
	return &OIDCAuthorizer{
		verifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
		clientID: clientID,
	}, nil
}

func (a *OIDCAuthorizer) Authorize(r *http.Request) (*Actor, error) {
	rawToken, err := bearerToken(r)
	if err != nil {
		return nil, err
	}
	token, err := a.verifier.Verify(r.Context(), rawToken)
	if err != nil {
		return nil, errors.New("OIDC token verification failed")
	}
	var claims oidcActorClaims
	if err := token.Claims(&claims); err != nil {
		return nil, errors.New("OIDC claims are invalid")
	}
	if claims.AuthorizedParty != "" && claims.AuthorizedParty != a.clientID {
		return nil, errors.New("OIDC authorized party does not match this client")
	}
	if len(token.Audience) > 1 && claims.AuthorizedParty != a.clientID {
		return nil, errors.New("OIDC multi-audience token requires this client as authorized party")
	}
	subject := strings.TrimSpace(token.Subject)
	if subject == "" {
		subject = strings.TrimSpace(claims.Subject)
	}
	if subject == "" {
		return nil, errors.New("OIDC subject is required")
	}
	return &Actor{
		Subject:  subject,
		Groups:   append([]string(nil), claims.Groups...),
		AuthTime: claims.AuthTime,
	}, nil
}

func bearerToken(r *http.Request) (string, error) {
	scheme, value, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	value = strings.TrimSpace(value)
	if !ok || !strings.EqualFold(scheme, "Bearer") || value == "" {
		return "", errors.New("missing bearer authorization")
	}
	return value, nil
}

type oidcActorClaims struct {
	Subject         string         `json:"sub"`
	Groups          oidcStringList `json:"groups"`
	AuthTime        int64          `json:"auth_time"`
	AuthorizedParty string         `json:"azp"`
}

func secureOIDCHTTPClient(base *http.Client, issuer *url.URL) *http.Client {
	client := &http.Client{}
	if base != nil {
		*client = *base
	}
	if client.Timeout <= 0 {
		client.Timeout = defaultOIDCTimeout
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client.Transport = &oidcTransport{
		base:   transport,
		issuer: issuer,
	}
	previousRedirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) == 0 {
			return nil
		}
		if len(via) >= maxOIDCRedirects {
			return fmt.Errorf("stopped after %d OIDC redirects", maxOIDCRedirects)
		}
		if !sameOIDCOrigin(issuer, req.URL) {
			return fmt.Errorf("refusing cross-origin OIDC redirect")
		}
		if previousRedirect != nil {
			return previousRedirect(req, via)
		}
		return nil
	}
	return client
}

type oidcTransport struct {
	base   http.RoundTripper
	issuer *url.URL
}

func (t *oidcTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || !sameOIDCOrigin(t.issuer, request.URL) {
		return nil, fmt.Errorf("refusing cross-origin OIDC request")
	}
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > maxOIDCResponseBody {
		_ = response.Body.Close()
		return nil, fmt.Errorf("OIDC response exceeds %d bytes", maxOIDCResponseBody)
	}
	response.Body = &boundedOIDCBody{
		body:      response.Body,
		remaining: maxOIDCResponseBody,
	}
	return response, nil
}

type boundedOIDCBody struct {
	body      io.ReadCloser
	remaining int64
}

func (b *boundedOIDCBody) Read(buffer []byte) (int, error) {
	if b.remaining <= 0 {
		var extra [1]byte
		count, err := b.body.Read(extra[:])
		if count > 0 {
			return 0, fmt.Errorf("OIDC response exceeds %d bytes", maxOIDCResponseBody)
		}
		return 0, err
	}
	if int64(len(buffer)) > b.remaining {
		buffer = buffer[:b.remaining]
	}
	count, err := b.body.Read(buffer)
	b.remaining -= int64(count)
	return count, err
}

func (b *boundedOIDCBody) Close() error {
	return b.body.Close()
}

func sameOIDCOrigin(left, right *url.URL) bool {
	if left == nil || right == nil {
		return false
	}
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(oidcURLHost(left), oidcURLHost(right))
}

func oidcURLHost(value *url.URL) string {
	port := value.Port()
	if port == "" {
		switch strings.ToLower(value.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return value.Hostname() + ":" + port
}

type oidcStringList []string

func (values *oidcStringList) UnmarshalJSON(data []byte) error {
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		*values = normalizeGroups(list)
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*values = normalizeGroups([]string{single})
		return nil
	}
	return fmt.Errorf("groups claim must be a string or string array")
}

func normalizeGroups(groups []string) []string {
	result := make([]string, 0, len(groups))
	seen := make(map[string]bool, len(groups))
	for _, group := range groups {
		group = strings.TrimSpace(group)
		if group == "" || seen[group] {
			continue
		}
		seen[group] = true
		result = append(result, group)
	}
	return result
}
