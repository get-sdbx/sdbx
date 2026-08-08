package vpn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
)

func TestFetchPublicIPRejectsRedirectWithoutContactingTarget(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		_ *http.Request,
	) {
		targetRequests.Add(1)
		_, _ = w.Write([]byte("127.0.0.1"))
	}))
	t.Cleanup(target.Close)

	redirect := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(redirect.Close)

	_, err := fetchPublicIP(
		context.Background(),
		newPublicIPHTTPClient(),
		redirect.URL,
	)
	if err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("fetchPublicIP() error = %v, want rejected redirect", err)
	}
	if got := targetRequests.Load(); got != 0 {
		t.Fatalf("redirect target received %d requests, want 0", got)
	}
}

func TestFetchPublicIPAcceptsOnlyBoundedSuccessfulResponse(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		want       string
		wantError  string
	}{
		{
			name:       "valid",
			statusCode: http.StatusOK,
			body:       "198.51.100.42\n",
			want:       "198.51.100.42\n",
		},
		{
			name:       "non-success",
			statusCode: http.StatusServiceUnavailable,
			body:       "unavailable",
			wantError:  "HTTP 503",
		},
		{
			name:       "oversized",
			statusCode: http.StatusOK,
			body:       strings.Repeat("x", maxIPBodyBytes+1),
			wantError:  "exceeded 64 bytes",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(
				w http.ResponseWriter,
				_ *http.Request,
			) {
				w.WriteHeader(test.statusCode)
				_, _ = w.Write([]byte(test.body))
			}))
			t.Cleanup(server.Close)

			got, err := fetchPublicIP(
				context.Background(),
				newPublicIPHTTPClient(),
				server.URL,
			)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("fetchPublicIP() error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("fetchPublicIP() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestCheckerProvesDistinctHealthyEgress(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.VPNEnabled = true
	cfg.TorrentPort = 51413
	checker := &Checker{
		CheckGluetun: func(context.Context) (bool, error) {
			return true, nil
		},
		HostEgress: func(context.Context) (string, error) {
			return "198.51.100.10\n", nil
		},
		TunnelEgress: func(context.Context) (string, error) {
			return "203.0.113.20\n", nil
		},
	}

	status := checker.Check(context.Background(), cfg)
	if !status.ProtectionProven || !status.EgressSeparated || !status.GluetunHealthy {
		t.Fatalf("status = %#v, want proven protection", status)
	}
	if status.HostEgressIP != "198.51.100.10" ||
		status.TunnelEgressIP != "203.0.113.20" ||
		status.TorrentPeerPort != 51413 {
		t.Fatalf("status = %#v, want normalized egress and peer port", status)
	}
}

func TestCheckerDoesNotClaimProtectionForMatchingEgress(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.VPNEnabled = true
	checker := &Checker{
		CheckGluetun: func(context.Context) (bool, error) {
			return true, nil
		},
		HostEgress: func(context.Context) (string, error) {
			return "203.0.113.10", nil
		},
		TunnelEgress: func(context.Context) (string, error) {
			return "203.0.113.10", nil
		},
	}

	status := checker.Check(context.Background(), cfg)
	if status.ProtectionProven || status.EgressSeparated {
		t.Fatalf("status = %#v, matching egress must be inconclusive", status)
	}
	if !strings.Contains(status.Message, "could not be proven") {
		t.Fatalf("message = %q, want inconclusive result", status.Message)
	}
}

func TestCheckerFailsClosedOnUnhealthyGluetun(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.VPNEnabled = true
	checker := &Checker{
		CheckGluetun: func(context.Context) (bool, error) {
			return false, nil
		},
		HostEgress: func(context.Context) (string, error) {
			t.Fatal("unhealthy Gluetun must stop before public-IP probes")
			return "", nil
		},
		TunnelEgress: func(context.Context) (string, error) {
			t.Fatal("unhealthy Gluetun must stop before public-IP probes")
			return "", nil
		},
	}

	status := checker.Check(context.Background(), cfg)
	if status.ProtectionProven || status.GluetunHealthy {
		t.Fatalf("status = %#v, want unhealthy result", status)
	}
}

func TestCheckerReportsProbeAndValidationFailures(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.VPNEnabled = true
	tests := []struct {
		name    string
		host    func(context.Context) (string, error)
		tunnel  func(context.Context) (string, error)
		wantMsg string
	}{
		{
			name: "host failure",
			host: func(context.Context) (string, error) {
				return "", errors.New("host offline")
			},
			tunnel: func(context.Context) (string, error) {
				return "203.0.113.20", nil
			},
			wantMsg: "host egress probe failed",
		},
		{
			name: "tunnel invalid response",
			host: func(context.Context) (string, error) {
				return "198.51.100.10", nil
			},
			tunnel: func(context.Context) (string, error) {
				return "<html>error</html>", nil
			},
			wantMsg: "Gluetun egress probe returned an invalid public IP",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			checker := &Checker{
				CheckGluetun: func(context.Context) (bool, error) {
					return true, nil
				},
				HostEgress:   test.host,
				TunnelEgress: test.tunnel,
			}
			status := checker.Check(context.Background(), cfg)
			if status.ProtectionProven || !strings.Contains(status.Message, test.wantMsg) {
				t.Fatalf("status = %#v, want message containing %q", status, test.wantMsg)
			}
		})
	}
}

func TestCheckerReportsExplicitlyDisabledProtectionWithoutProbing(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.VPNEnabled = false
	checker := &Checker{
		CheckGluetun: func(context.Context) (bool, error) {
			t.Fatal("disabled VPN must not probe Gluetun")
			return false, nil
		},
	}

	status := checker.Check(context.Background(), cfg)
	if status.Configured || status.ProtectionProven {
		t.Fatalf("status = %#v, want explicitly unprotected result", status)
	}
	if !strings.Contains(status.Message, "host public IP") {
		t.Fatalf("message = %q, want explicit host egress warning", status.Message)
	}
}

func TestCheckerRedactsProbeErrors(t *testing.T) {
	const canary = "VPN_PROBE_SECRET_CANARY"
	cfg := config.DefaultConfig()
	cfg.VPNEnabled = true
	checker := &Checker{
		CheckGluetun: func(context.Context) (bool, error) {
			return false, errors.New("authorization=Bearer " + canary)
		},
		HostEgress: func(context.Context) (string, error) {
			return "198.51.100.10", nil
		},
		TunnelEgress: func(context.Context) (string, error) {
			return "203.0.113.20", nil
		},
	}
	status := checker.Check(context.Background(), cfg)
	if strings.Contains(status.Message, canary) ||
		!strings.Contains(status.Message, "[REDACTED]") {
		t.Fatalf("VPN status leaked credential: %q", status.Message)
	}
}
