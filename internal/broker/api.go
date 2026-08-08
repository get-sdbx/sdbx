// Package broker transports the typed SDBX management API over a protected
// local Unix socket.
package broker

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	APIVersion       = "sdbx.management/v1"
	AdminGroup       = "sdbx-admin"
	staticTokenBytes = 32
	maxRequestBytes  = 64 << 10
	maxResponseBytes = 4 << 20
)

type Actor struct {
	Subject  string   `json:"subject"`
	Groups   []string `json:"groups,omitempty"`
	AuthTime int64    `json:"auth_time,omitempty"`
}

type Authorizer interface {
	Authorize(*http.Request) (*Actor, error)
}

type StaticTokenAuthorizer struct {
	token string
}

func NewStaticTokenAuthorizer(token string) (*StaticTokenAuthorizer, error) {
	if err := validateStaticToken(token); err != nil {
		return nil, err
	}
	return &StaticTokenAuthorizer{token: token}, nil
}

func validateStaticToken(token string) error {
	if len(token) != base64.RawURLEncoding.EncodedLen(staticTokenBytes) {
		return fmt.Errorf("broker token must be a canonical 256-bit base64url value")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	defer zeroBytes(decoded)
	if err != nil ||
		len(decoded) != staticTokenBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != token {
		return fmt.Errorf("broker token must be a canonical 256-bit base64url value")
	}
	return nil
}

func (a *StaticTokenAuthorizer) Authorize(r *http.Request) (*Actor, error) {
	value, err := bearerToken(r)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(value), []byte(a.token)) != 1 {
		return nil, errors.New("invalid bearer authorization")
	}
	return &Actor{
		Subject:  "local-management-client",
		Groups:   []string{AdminGroup},
		AuthTime: time.Now().Unix(),
	}, nil
}

type AnyAuthorizer struct {
	authorizers []Authorizer
}

func NewAnyAuthorizer(authorizers ...Authorizer) (*AnyAuthorizer, error) {
	filtered := make([]Authorizer, 0, len(authorizers))
	for _, authorizer := range authorizers {
		if authorizer != nil {
			filtered = append(filtered, authorizer)
		}
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("at least one broker authorizer is required")
	}
	return &AnyAuthorizer{authorizers: filtered}, nil
}

func (a *AnyAuthorizer) Authorize(r *http.Request) (*Actor, error) {
	for _, authorizer := range a.authorizers {
		actor, err := authorizer.Authorize(r)
		if err == nil && actorHasIdentity(actor) {
			return actor, nil
		}
	}
	return nil, errors.New("no broker authorizer accepted the request")
}

func actorHasIdentity(actor *Actor) bool {
	return actor != nil && strings.TrimSpace(actor.Subject) != ""
}

type envelope struct {
	APIVersion string          `json:"apiVersion"`
	Data       json.RawMessage `json:"data,omitempty"`
	Error      *APIError       `json:"error,omitempty"`
}

type APIError struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *APIError) Error() string {
	return e.Code + ": " + e.Message
}

type createBackupWireRequest struct {
	Recipient  string `json:"recipient,omitempty"`
	Passphrase []byte `json:"passphrase,omitempty"`
}

type restoreBackupWireRequest struct {
	Name                 string `json:"name"`
	Passphrase           []byte `json:"passphrase"`
	Confirm              string `json:"confirm"`
	RelocateManagedRoots bool   `json:"relocate_managed_roots,omitempty"`
}
