// Package cloudflare derives the remotely managed Cloudflare Tunnel routes
// required by one verified SDBX service graph.
package cloudflare

import (
	"fmt"
	"sort"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
	sdbxrouting "github.com/get-sdbx/sdbx/internal/routing"
)

const (
	// ManagementMode is the only Cloudflare Tunnel management model supported
	// by SDBX v1. The connector token authenticates cloudflared; published
	// application routes remain owned by the Cloudflare dashboard or API.
	ManagementMode = "remote"

	// OriginService is resolved from the cloudflared container on the private
	// edge network. The Traefik tunnel entrypoint is never published by the
	// host.
	OriginService = "http://traefik:8081"
)

// Route maps one public hostname to the private SDBX Traefik entrypoint.
type Route struct {
	Hostname string `json:"hostname"`
	Service  string `json:"service"`
}

// Plan is the complete Cloudflare-side configuration required by an active
// SDBX graph. URLs remain service-specific so operators can verify every
// intended public route after configuring the hostname mappings.
type Plan struct {
	Management string   `json:"management"`
	Routes     []Route  `json:"routes"`
	URLs       []string `json:"urls"`
}

// BuildPlan derives unique hostnames and URLs from the verified active graph.
func BuildPlan(
	cfg *config.Config,
	graph *registry.ResolutionGraph,
) (Plan, error) {
	if cfg == nil {
		return Plan{}, fmt.Errorf("project configuration is required")
	}
	if graph == nil {
		return Plan{}, fmt.Errorf("verified service graph is required")
	}
	if cfg.Expose.Mode != config.ExposeModeCloudflared {
		return Plan{}, fmt.Errorf(
			"Cloudflare route planning requires expose.mode=%s",
			config.ExposeModeCloudflared,
		)
	}
	if len(graph.Errors) > 0 {
		return Plan{}, fmt.Errorf(
			"service resolution failed: %w",
			graph.Errors[0],
		)
	}

	hostnames := make(map[string]struct{})
	urls := make(map[string]struct{})
	dashboardHost := sdbxrouting.SharedHostname(cfg)
	hostnames[dashboardHost] = struct{}{}
	urls["https://"+dashboardHost] = struct{}{}
	for _, name := range graph.Order {
		resolved := graph.Services[name]
		if resolved == nil ||
			!resolved.Enabled ||
			resolved.FinalDefinition == nil ||
			!resolved.FinalDefinition.Routing.Enabled {
			continue
		}
		definition := resolved.FinalDefinition
		hostnames[sdbxrouting.Hostname(cfg, definition)] = struct{}{}
		urls[sdbxrouting.URL(cfg, definition)] = struct{}{}
	}

	plan := Plan{
		Management: ManagementMode,
		Routes:     make([]Route, 0, len(hostnames)),
		URLs:       make([]string, 0, len(urls)),
	}
	for hostname := range hostnames {
		plan.Routes = append(plan.Routes, Route{
			Hostname: hostname,
			Service:  OriginService,
		})
	}
	for url := range urls {
		plan.URLs = append(plan.URLs, url)
	}
	sort.Slice(plan.Routes, func(i, j int) bool {
		return plan.Routes[i].Hostname < plan.Routes[j].Hostname
	})
	sort.Strings(plan.URLs)
	return plan, nil
}
