package broker

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOIDCAuthorizerVerifiesIssuerSignatureAudienceExpiryAndClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	issuer = server.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"jwks_uri":                              issuer + "/jwks",
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": "test-key",
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   encodeRSAExponent(key.E),
			}},
		})
	})

	authorizer, err := NewOIDCAuthorizer(context.Background(), OIDCOptions{
		Issuer:   issuer,
		ClientID: "sdbx-console",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	valid := signTestIDToken(t, key, map[string]any{
		"iss":       issuer,
		"sub":       "admin-user",
		"aud":       "sdbx-console",
		"exp":       now.Add(time.Hour).Unix(),
		"iat":       now.Unix(),
		"auth_time": now.Unix(),
		"groups":    []string{"sdbx-viewer", AdminGroup},
	})
	request := httptest.NewRequest(http.MethodGet, "/v1/summary", nil)
	request.Header.Set("Authorization", "Bearer "+valid)
	actor, err := authorizer.Authorize(request)
	if err != nil {
		t.Fatal(err)
	}
	if actor.Subject != "admin-user" ||
		!hasGroup(actor.Groups, AdminGroup) ||
		actor.AuthTime != now.Unix() {
		t.Fatalf("actor = %#v", actor)
	}

	testCases := map[string]map[string]any{
		"wrong-audience": {
			"iss": issuer, "sub": "admin-user", "aud": "other-client",
			"exp": now.Add(time.Hour).Unix(),
		},
		"expired": {
			"iss": issuer, "sub": "admin-user", "aud": "sdbx-console",
			"exp": now.Add(-time.Hour).Unix(),
		},
		"wrong-issuer": {
			"iss": issuer + "/other", "sub": "admin-user", "aud": "sdbx-console",
			"exp": now.Add(time.Hour).Unix(),
		},
		"multi-audience-missing-azp": {
			"iss": issuer, "sub": "admin-user",
			"aud": []string{"sdbx-console", "other-client"},
			"exp": now.Add(time.Hour).Unix(),
		},
		"multi-audience-wrong-azp": {
			"iss": issuer, "sub": "admin-user",
			"aud": []string{"sdbx-console", "other-client"},
			"azp": "other-client", "exp": now.Add(time.Hour).Unix(),
		},
	}
	for name, claims := range testCases {
		t.Run(name, func(t *testing.T) {
			raw := signTestIDToken(t, key, claims)
			request := httptest.NewRequest(http.MethodGet, "/v1/summary", nil)
			request.Header.Set("Authorization", "Bearer "+raw)
			if _, err := authorizer.Authorize(request); err == nil {
				t.Fatalf("%s token was accepted", name)
			}
		})
	}

	multiAudience := signTestIDToken(t, key, map[string]any{
		"iss": issuer, "sub": "admin-user",
		"aud": []string{"sdbx-console", "other-client"},
		"azp": "sdbx-console", "exp": now.Add(time.Hour).Unix(),
	})
	request = httptest.NewRequest(http.MethodGet, "/v1/summary", nil)
	request.Header.Set("Authorization", "Bearer "+multiAudience)
	if _, err := authorizer.Authorize(request); err != nil {
		t.Fatalf("bound multi-audience token was rejected: %v", err)
	}

	parts := strings.Split(valid, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"forged"}`))
	request = httptest.NewRequest(http.MethodGet, "/v1/summary", nil)
	request.Header.Set("Authorization", "Bearer "+strings.Join(parts, "."))
	if _, err := authorizer.Authorize(request); err == nil {
		t.Fatal("forged OIDC token was accepted")
	}
}

func TestOIDCDiscoveryRejectsCrossOriginRedirect(t *testing.T) {
	var attackerRequests atomic.Int32
	attacker := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		attackerRequests.Add(1)
	}))
	defer attacker.Close()

	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL, http.StatusTemporaryRedirect)
	}))
	defer issuer.Close()

	_, err := NewOIDCAuthorizer(context.Background(), OIDCOptions{
		Issuer:   issuer.URL,
		ClientID: "sdbx-console",
	})
	if err == nil || !strings.Contains(err.Error(), "cross-origin OIDC redirect") {
		t.Fatalf("NewOIDCAuthorizer() error = %v, want redirect refusal", err)
	}
	if got := attackerRequests.Load(); got != 0 {
		t.Fatalf("attacker requests = %d, want 0", got)
	}
}

func TestOIDCDiscoveryRejectsCrossOriginJWKS(t *testing.T) {
	var attackerRequests atomic.Int32
	attacker := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		attackerRequests.Add(1)
	}))
	defer attacker.Close()

	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"jwks_uri":                              attacker.URL + "/jwks",
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer server.Close()
	issuer = server.URL

	_, err := NewOIDCAuthorizer(context.Background(), OIDCOptions{
		Issuer:   issuer,
		ClientID: "sdbx-console",
	})
	if err == nil || !strings.Contains(err.Error(), "JWKS URI must use the issuer origin") {
		t.Fatalf("NewOIDCAuthorizer() error = %v, want JWKS origin refusal", err)
	}
	if got := attackerRequests.Load(); got != 0 {
		t.Fatalf("attacker requests = %d, want 0", got)
	}
}

func TestOIDCDiscoveryResponseIsBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxOIDCResponseBody+1)))
	}))
	defer server.Close()

	_, err := NewOIDCAuthorizer(context.Background(), OIDCOptions{
		Issuer:   server.URL,
		ClientID: "sdbx-console",
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("NewOIDCAuthorizer() error = %v, want response bound", err)
	}
}

func TestOIDCIssuerRequiresHTTPSExceptLoopback(t *testing.T) {
	if _, err := NewOIDCAuthorizer(context.Background(), OIDCOptions{
		Issuer:   "http://identity.example.test",
		ClientID: "sdbx",
	}); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("insecure issuer error = %v", err)
	}
}

func signTestIDToken(
	t *testing.T,
	key *rsa.PrivateKey,
	claims map[string]any,
) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{
		"alg": "RS256",
		"kid": "test-key",
		"typ": "JWT",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(encoded))
	signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		key,
		crypto.SHA256,
		digest[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	return encoded + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func encodeRSAExponent(exponent int) string {
	value := big.NewInt(int64(exponent)).Bytes()
	return base64.RawURLEncoding.EncodeToString(value)
}

func ExampleOIDCAuthorizer() {
	fmt.Println("Authelia tokens are verified through issuer discovery and JWKS")
	// Output: Authelia tokens are verified through issuer discovery and JWKS
}
