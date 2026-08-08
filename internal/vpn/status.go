// Package vpn verifies the effective download-network protection boundary.
package vpn

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/docker"
	"github.com/get-sdbx/sdbx/internal/redact"
)

const (
	publicIPURL    = "https://api.ipify.org"
	maxIPBodyBytes = 64
)

// Status is the machine-readable result of a VPN egress verification.
type Status struct {
	Configured       bool   `json:"configured"`
	GluetunHealthy   bool   `json:"gluetunHealthy"`
	HostEgressIP     string `json:"hostEgressIp,omitempty"`
	TunnelEgressIP   string `json:"tunnelEgressIp,omitempty"`
	EgressSeparated  bool   `json:"egressSeparated"`
	ProtectionProven bool   `json:"protectionProven"`
	TorrentPeerPort  int    `json:"torrentPeerPort"`
	Message          string `json:"message"`
}

// Checker owns injectable probes so status behavior can be tested without
// Docker or disclosing the test host's public IP.
type Checker struct {
	CheckGluetun func(context.Context) (bool, error)
	HostEgress   func(context.Context) (string, error)
	TunnelEgress func(context.Context) (string, error)
}

// NewChecker returns a checker backed by the current project Compose stack.
func NewChecker(projectDir string) *Checker {
	compose := docker.NewCompose(projectDir)
	httpClient := newPublicIPHTTPClient()
	return &Checker{
		CheckGluetun: func(ctx context.Context) (bool, error) {
			return compose.IsHealthy(ctx, "gluetun")
		},
		HostEgress: func(ctx context.Context) (string, error) {
			return fetchPublicIP(ctx, httpClient, publicIPURL)
		},
		TunnelEgress: func(ctx context.Context) (string, error) {
			return compose.Exec(ctx, "gluetun", "wget", "-qO-", publicIPURL)
		},
	}
}

func newPublicIPHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		// The endpoint is fixed by SDBX. Following an upstream redirect would
		// turn a status probe into a request to an unreviewed destination,
		// including a loopback or link-local service.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func fetchPublicIP(
	ctx context.Context,
	client *http.Client,
	endpoint string,
) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IP service returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxIPBodyBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxIPBodyBytes {
		return "", fmt.Errorf("IP service response exceeded %d bytes", maxIPBodyBytes)
	}
	return string(body), nil
}

// Check verifies that Gluetun is healthy and that the host and tunnel disclose
// distinct, valid public IP addresses. Distinct egress is evidence of network
// separation; a matching result is reported as inconclusive rather than
// incorrectly claiming that the tunnel is down.
func (c *Checker) Check(ctx context.Context, cfg *config.Config) Status {
	status := Status{}
	if cfg != nil {
		status.Configured = cfg.VPNEnabled
		status.TorrentPeerPort = cfg.TorrentPort
	}
	if !status.Configured {
		status.Message = "VPN disabled by configuration; torrent traffic uses the host public IP"
		return status
	}
	if c == nil || c.CheckGluetun == nil || c.HostEgress == nil || c.TunnelEgress == nil {
		status.Message = "VPN status checker is not fully configured"
		return status
	}

	healthy, err := c.CheckGluetun(ctx)
	if err != nil {
		status.Message = "could not inspect Gluetun health: " + redact.Text(err.Error())
		return status
	}
	status.GluetunHealthy = healthy
	if !healthy {
		status.Message = "Gluetun is not running and healthy"
		return status
	}

	type probeResult struct {
		ip  string
		err error
	}
	hostResult := make(chan probeResult, 1)
	tunnelResult := make(chan probeResult, 1)
	go func() {
		ip, probeErr := c.HostEgress(ctx)
		hostResult <- probeResult{ip: ip, err: probeErr}
	}()
	go func() {
		ip, probeErr := c.TunnelEgress(ctx)
		tunnelResult <- probeResult{ip: ip, err: probeErr}
	}()

	host := <-hostResult
	tunnel := <-tunnelResult
	if host.err != nil {
		status.Message = "host egress probe failed: " + redact.Text(host.err.Error())
		return status
	}
	if tunnel.err != nil {
		status.Message = "Gluetun egress probe failed: " + redact.Text(tunnel.err.Error())
		return status
	}
	hostIP, err := validatedIP(host.ip)
	if err != nil {
		status.Message = "host egress probe returned " + redact.Text(err.Error())
		return status
	}
	tunnelIP, err := validatedIP(tunnel.ip)
	if err != nil {
		status.Message = "Gluetun egress probe returned " + redact.Text(err.Error())
		return status
	}

	status.HostEgressIP = hostIP
	status.TunnelEgressIP = tunnelIP
	status.EgressSeparated = hostIP != tunnelIP
	if !status.EgressSeparated {
		status.Message = "host and Gluetun disclose the same public IP; tunnel separation could not be proven"
		return status
	}

	status.ProtectionProven = true
	status.Message = "Gluetun is healthy and exposes a distinct tunnel egress"
	return status
}

func validatedIP(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if len(value) > maxIPBodyBytes || net.ParseIP(value) == nil {
		return "", fmt.Errorf("an invalid public IP")
	}
	return value, nil
}
