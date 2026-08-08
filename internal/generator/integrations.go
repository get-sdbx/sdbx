package generator

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
	sdbxrouting "github.com/get-sdbx/sdbx/internal/routing"
)

// IntegrationsGenerator generates Traefik, Authelia, and environment
// integration configuration from one verified graph.
type IntegrationsGenerator struct {
	Config *config.Config
}

// NewIntegrationsGenerator creates a new integrations generator
func NewIntegrationsGenerator(cfg *config.Config) *IntegrationsGenerator {
	return &IntegrationsGenerator{Config: cfg}
}

// TraefikDynamicConfig represents traefik dynamic configuration
type TraefikDynamicConfig struct {
	HTTP TraefikHTTP `yaml:"http"`
	TLS  TraefikTLS  `yaml:"tls"`
}

// TraefikHTTP represents Traefik HTTP configuration
type TraefikHTTP struct {
	Middlewares      map[string]TraefikMiddleware       `yaml:"middlewares"`
	Routers          map[string]TraefikRouter           `yaml:"routers"`
	Services         map[string]TraefikService          `yaml:"services"`
	ServersTransport map[string]TraefikServersTransport `yaml:"serversTransports"`
}

// TraefikRouter is a complete file-provider HTTP route. SDBX intentionally
// avoids Docker discovery so the public reverse proxy never needs Docker API
// access.
type TraefikRouter struct {
	Rule        string            `yaml:"rule"`
	EntryPoints []string          `yaml:"entryPoints"`
	Middlewares []string          `yaml:"middlewares,omitempty"`
	Service     string            `yaml:"service"`
	TLS         *TraefikRouterTLS `yaml:"tls,omitempty"`
}

// TraefikRouterTLS enables TLS using the entrypoint's static policy.
type TraefikRouterTLS struct{}

// TraefikService defines the only backend URL a generated router may reach.
type TraefikService struct {
	LoadBalancer TraefikLoadBalancer `yaml:"loadBalancer"`
}

// TraefikLoadBalancer defines static backend servers for a routed service.
type TraefikLoadBalancer struct {
	Servers          []TraefikServer `yaml:"servers"`
	ServersTransport string          `yaml:"serversTransport,omitempty"`
}

// TraefikServersTransport pins the private CA, SNI, TLS floor, and client
// certificate used to reach a non-container backend.
type TraefikServersTransport struct {
	ServerName   string                     `yaml:"serverName"`
	Certificates []TraefikClientCertificate `yaml:"certificates"`
	RootCAs      []string                   `yaml:"rootCAs"`
	MinVersion   string                     `yaml:"minVersion"`
	MaxVersion   string                     `yaml:"maxVersion"`
}

// TraefikClientCertificate is one mTLS certificate and private-key pair.
// Traefik's file-provider schema requires both paths in the same list item.
type TraefikClientCertificate struct {
	CertFile string `yaml:"certFile"`
	KeyFile  string `yaml:"keyFile"`
}

// TraefikServer is a generated internal HTTP endpoint.
type TraefikServer struct {
	URL string `yaml:"url"`
}

// TraefikMiddleware represents a Traefik middleware
type TraefikMiddleware struct {
	StripPrefix   *StripPrefixMiddleware   `yaml:"stripPrefix,omitempty"`
	ForwardAuth   *ForwardAuthMiddleware   `yaml:"forwardAuth,omitempty"`
	Headers       *HeadersMiddleware       `yaml:"headers,omitempty"`
	RedirectRegex *RedirectRegexMiddleware `yaml:"redirectRegex,omitempty"`
}

// HeadersMiddleware defines response headers that are safe across the
// heterogeneous SDBX application catalog.
type HeadersMiddleware struct {
	ContentTypeNoSniff   bool              `yaml:"contentTypeNosniff"`
	ReferrerPolicy       string            `yaml:"referrerPolicy"`
	STSSeconds           int               `yaml:"stsSeconds,omitempty"`
	ForceSTSHeader       bool              `yaml:"forceSTSHeader,omitempty"`
	CustomRequestHeaders map[string]string `yaml:"customRequestHeaders,omitempty"`
	CustomResponseHeader map[string]string `yaml:"customResponseHeaders,omitempty"`
}

// TraefikTLS defines the default TLS policy loaded through the file provider.
type TraefikTLS struct {
	Options map[string]TraefikTLSOption `yaml:"options"`
}

// TraefikTLSOption defines the minimum protocol policy for every TLS router.
type TraefikTLSOption struct {
	MinVersion string `yaml:"minVersion"`
	SNIStrict  bool   `yaml:"sniStrict"`
}

// StripPrefixMiddleware represents StripPrefix middleware config
type StripPrefixMiddleware struct {
	Prefixes []string `yaml:"prefixes"`
}

// RedirectRegexMiddleware redirects an exact public URL to another canonical
// URL without exposing a new backend.
type RedirectRegexMiddleware struct {
	Regex       string `yaml:"regex"`
	Replacement string `yaml:"replacement"`
	Permanent   bool   `yaml:"permanent"`
}

// ForwardAuthMiddleware represents ForwardAuth middleware config
type ForwardAuthMiddleware struct {
	Address             string   `yaml:"address"`
	TrustForwardHeader  bool     `yaml:"trustForwardHeader"`
	MaxResponseBodySize int      `yaml:"maxResponseBodySize"`
	AuthResponseHeaders []string `yaml:"authResponseHeaders,omitempty"`
}

// GenerateTraefikDynamic generates traefik dynamic middlewares config
func (g *IntegrationsGenerator) GenerateTraefikDynamic(graph *registry.ResolutionGraph) ([]byte, error) {
	cfg := TraefikDynamicConfig{
		HTTP: TraefikHTTP{
			Middlewares:      make(map[string]TraefikMiddleware),
			Routers:          make(map[string]TraefikRouter),
			Services:         make(map[string]TraefikService),
			ServersTransport: make(map[string]TraefikServersTransport),
		},
		TLS: TraefikTLS{
			Options: map[string]TraefikTLSOption{
				"default": {
					MinVersion: "VersionTLS12",
					SNIStrict:  true,
				},
			},
		},
	}

	securityHeaders := &HeadersMiddleware{
		ContentTypeNoSniff: true,
		ReferrerPolicy:     "same-origin",
		CustomResponseHeader: map[string]string{
			"Server":       "",
			"X-Powered-By": "",
		},
	}
	if g.Config.Expose.Mode == config.ExposeModeDirect ||
		g.Config.Expose.Mode == config.ExposeModeCloudflared {
		securityHeaders.STSSeconds = 31536000
	}
	// The remote-managed tunnel terminates public TLS at Cloudflare and sends
	// plain HTTP to Traefik over the private edge network. Traefik therefore
	// cannot infer that HSTS is safe from the origin request's TLS state.
	// Force the response header only for this explicitly HTTPS-only boundary.
	if g.Config.Expose.Mode == config.ExposeModeCloudflared {
		securityHeaders.ForceSTSHeader = true
	}
	cfg.HTTP.Middlewares["security-headers"] = TraefikMiddleware{
		Headers: securityHeaders,
	}
	if g.Config.Expose.Mode == config.ExposeModeCloudflared {
		// The tunnel entrypoint deliberately does not trust client-supplied
		// forwarding headers. Recreate only the scheme metadata guaranteed by
		// the remote-managed Cloudflare Tunnel before ForwardAuth executes.
		cfg.HTTP.Middlewares["tunnel-forwarded-scheme"] = TraefikMiddleware{
			Headers: &HeadersMiddleware{
				CustomRequestHeaders: map[string]string{
					"X-Forwarded-Port":  "443",
					"X-Forwarded-Proto": "https",
					"X-Forwarded-Ssl":   "on",
				},
			},
		}
	}

	// Add the current Authelia ForwardAuth authorization endpoint. Session
	// cookies carry the public Authelia URL, so no redirect query is needed.
	cfg.HTTP.Middlewares["authelia"] = TraefikMiddleware{
		ForwardAuth: &ForwardAuthMiddleware{
			Address: "http://authelia:9091/api/authz/forward-auth",
			// Exposed entrypoints explicitly trust no upstream IPs, so
			// Traefik strips client-supplied forwarding headers before this
			// middleware consumes the canonical values it synthesized.
			TrustForwardHeader:  true,
			MaxResponseBodySize: 8192,
			AuthResponseHeaders: []string{
				"Remote-User",
				"Remote-Groups",
				"Remote-Name",
				"Remote-Email",
			},
		},
	}

	// The management dashboard owns only the shared root and its private API
	// and static namespaces. Application subpaths keep their existing routes.
	// Traefik authenticates an admin with Authelia, then reaches the host process
	// through a dedicated mutually authenticated TLS transport.
	hostname := sdbxrouting.SharedHostname(g.Config)
	entrypoint := "websecure"
	middlewares := []string{"security-headers", "authelia"}
	if g.Config.Expose.Mode == config.ExposeModeCloudflared {
		entrypoint = "tunnel"
		middlewares = append([]string{"tunnel-forwarded-scheme"}, middlewares...)
	}
	dashboardRouter := TraefikRouter{
		Rule: fmt.Sprintf(
			"Host(`%s`) && (Path(`/`) || PathPrefix(`/api/`) || PathPrefix(`/static/`))",
			hostname,
		),
		EntryPoints: []string{entrypoint},
		Middlewares: middlewares,
		Service:     "dashboard",
	}
	if g.Config.Expose.Mode == config.ExposeModeLAN ||
		g.Config.Expose.Mode == config.ExposeModeDirect {
		dashboardRouter.TLS = &TraefikRouterTLS{}
	}
	cfg.HTTP.Routers["dashboard"] = dashboardRouter
	cfg.HTTP.Services["dashboard"] = TraefikService{
		LoadBalancer: TraefikLoadBalancer{
			Servers:          []TraefikServer{{URL: "https://host.docker.internal:18777"}},
			ServersTransport: "console-mtls",
		},
	}
	cfg.HTTP.ServersTransport["console-mtls"] = TraefikServersTransport{
		ServerName: "sdbx-console.internal",
		Certificates: []TraefikClientCertificate{
			{
				CertFile: "/run/secrets/console_proxy_client_cert",
				KeyFile:  "/run/secrets/console_proxy_client_key",
			},
		},
		RootCAs:    []string{"/run/secrets/console_proxy_ca"},
		MinVersion: "VersionTLS13",
		MaxVersion: "VersionTLS13",
	}

	// Generate complete file-provider routes and the optional strip-prefix
	// middlewares they reference. A catalog may not shadow another service by
	// declaring the same effective rule with a different auth classification.
	routeOwners := make(map[string]string)
	for _, serviceName := range graph.Order {
		resolved := graph.Services[serviceName]
		if !resolved.Enabled {
			continue
		}

		def := resolved.FinalDefinition
		if !def.Routing.Enabled ||
			!registry.MatchesActivationConditions(def.Conditions, g.Config) {
			continue
		}

		name := def.Metadata.Name
		rule := sdbxrouting.Rule(g.Config, def)
		if owner, exists := routeOwners[rule]; exists {
			return nil, fmt.Errorf(
				"services %q and %q resolve to the same Traefik route %q",
				owner,
				name,
				rule,
			)
		}
		routeOwners[rule] = name

		middlewares := make([]string, 0, 4)
		if g.Config.Expose.Mode == config.ExposeModeCloudflared {
			middlewares = append(middlewares, "tunnel-forwarded-scheme")
		}
		middlewares = append(middlewares, "security-headers")
		if def.Routing.Auth.RequiresForwardAuth() {
			// ForwardAuth must see the operator-facing path. Running a
			// strip-prefix middleware first makes the generated Authelia
			// resource policy miss and fall through to its deny default.
			middlewares = append(middlewares, "authelia")
		}
		if sdbxrouting.Strategy(g.Config, def) == config.RoutingStrategyPath &&
			def.Routing.PathRouting.Strategy == "stripPrefix" {
			middlewareName := fmt.Sprintf("strip-%s", name)
			cfg.HTTP.Middlewares[middlewareName] = TraefikMiddleware{
				StripPrefix: &StripPrefixMiddleware{
					Prefixes: []string{sdbxrouting.Path(g.Config, def)},
				},
			}
			middlewares = append(middlewares, middlewareName)
		}

		entrypoint := "websecure"
		if g.Config.Expose.Mode == config.ExposeModeCloudflared {
			entrypoint = "tunnel"
		}
		router := TraefikRouter{
			Rule:        rule,
			EntryPoints: []string{entrypoint},
			Middlewares: middlewares,
			Service:     name,
		}
		if g.Config.Expose.Mode == config.ExposeModeLAN ||
			g.Config.Expose.Mode == config.ExposeModeDirect {
			router.TLS = &TraefikRouterTLS{}
		}

		backend, err := g.traefikBackendService(graph, def)
		if err != nil {
			return nil, err
		}
		cfg.HTTP.Routers[name] = router
		cfg.HTTP.Services[name] = TraefikService{
			LoadBalancer: TraefikLoadBalancer{
				Servers: []TraefikServer{{
					URL: fmt.Sprintf("http://%s:%d", backend, def.Routing.Port),
				}},
			},
		}
	}

	return yaml.Marshal(cfg)
}

func (g *IntegrationsGenerator) traefikBackendService(
	graph *registry.ResolutionGraph,
	def *registry.ServiceDefinition,
) (string, error) {
	mode := strings.TrimSpace(def.Spec.Networking.Mode)
	if def.Spec.Networking.ModeTemplate != "" {
		rendered, err := renderCatalogTemplate(
			def.Spec.Networking.ModeTemplate,
			TemplateContext{
				Config: catalogTemplateConfig(g.Config, def),
				Name:   def.Metadata.Name,
			},
		)
		if err != nil {
			return "", fmt.Errorf(
				"render network mode for Traefik backend %s: %w",
				def.Metadata.Name,
				err,
			)
		}
		mode = strings.TrimSpace(rendered)
	}

	backend := def.Metadata.Name
	if target, ok := strings.CutPrefix(mode, "service:"); ok {
		backend = strings.TrimSpace(target)
	}
	resolved, ok := graph.Services[backend]
	if !ok || resolved == nil || !resolved.Enabled ||
		resolved.FinalDefinition == nil ||
		!registry.MatchesActivationConditions(
			resolved.FinalDefinition.Conditions,
			g.Config,
		) {
		return "", fmt.Errorf(
			"Traefik backend %q for %s is not an enabled service",
			backend,
			def.Metadata.Name,
		)
	}
	if backend != def.Metadata.Name {
		declaredDependency := false
		for _, dependency := range def.Spec.Dependencies.Required {
			if dependency == backend {
				declaredDependency = true
				break
			}
		}
		for _, dependency := range def.Spec.Dependencies.Conditional {
			if dependency.Name == backend {
				declaredDependency = true
				break
			}
		}
		if !declaredDependency {
			return "", fmt.Errorf(
				"Traefik backend %q for %s is not a declared dependency",
				backend,
				def.Metadata.Name,
			)
		}
	}
	return backend, nil
}

// AutheliaAccessRule represents an Authelia access control rule
type AutheliaAccessRule struct {
	Domain    string   `yaml:"domain"`
	Resources []string `yaml:"resources,omitempty"`
	Subject   []string `yaml:"subject,omitempty"`
	Policy    string   `yaml:"policy"`
}

// GenerateAutheliaAccessRules generates Authelia access control rules
func (g *IntegrationsGenerator) GenerateAutheliaAccessRules(graph *registry.ResolutionGraph) ([]AutheliaAccessRule, error) {
	rules := []AutheliaAccessRule{{
		Domain: sdbxrouting.SharedHostname(g.Config),
		Resources: []string{
			`^/$`,
			`^/api(?:/.*)?$`,
			`^/static(?:/.*)?$`,
		},
		Subject: []string{"group:admins"},
		Policy:  g.Config.Auth.Factor,
	}}

	for _, serviceName := range graph.Order {
		resolved := graph.Services[serviceName]
		if !resolved.Enabled {
			continue
		}

		def := resolved.FinalDefinition

		// Only routed services with auth
		if !def.Routing.Enabled {
			continue
		}

		// Check conditions
		if !registry.MatchesActivationConditions(def.Conditions, g.Config) {
			continue
		}

		if !def.Routing.Auth.RequiresForwardAuth() {
			continue
		}

		rule := AutheliaAccessRule{
			Domain: sdbxrouting.Hostname(g.Config, def),
			Policy: g.Config.Auth.Factor,
		}
		if def.Routing.Auth.Mode == registry.AuthModeAdminOnly {
			rule.Subject = []string{"group:admins"}
		}
		if sdbxrouting.Strategy(g.Config, def) == config.RoutingStrategyPath {
			path := sdbxrouting.Path(g.Config, def)
			if path == "/" {
				rule.Resources = []string{`^/.*$`}
			} else {
				rule.Resources = []string{
					"^" + regexp.QuoteMeta(path) + `([/?].*)?$`,
				}
			}
		}
		rules = append(rules, rule)
	}

	// Path-mode routes share one domain. Specific resource rules must precede
	// the root catch-all or the first-match policy would shadow them.
	sort.SliceStable(rules, func(i, j int) bool {
		left, right := "", ""
		if len(rules[i].Resources) > 0 {
			left = rules[i].Resources[0]
		}
		if len(rules[j].Resources) > 0 {
			right = rules[j].Resources[0]
		}
		return len(left) > len(right)
	})

	return rules, nil
}

// getServiceURL returns the full URL for a service
func (g *IntegrationsGenerator) getServiceURL(def *registry.ServiceDefinition) string {
	return sdbxrouting.URL(g.Config, def)
}

// GenerateEnvFile generates the .env file content
func (g *IntegrationsGenerator) GenerateEnvFile(graph *registry.ResolutionGraph) ([]byte, error) {
	var lines []string

	lines = append(lines, "# SDBX Environment Configuration")
	lines = append(lines, "# Generated by sdbx init")
	lines = append(lines, "")

	// Core settings
	lines = append(lines, fmt.Sprintf("SDBX_DOMAIN=%s", g.Config.Domain))
	lines = append(lines, fmt.Sprintf("SDBX_EXPOSE_MODE=%s", g.Config.Expose.Mode))
	lines = append(lines, fmt.Sprintf("SDBX_TIMEZONE=%s", g.Config.Timezone))
	lines = append(lines, "")

	// Paths
	lines = append(lines, fmt.Sprintf("SDBX_CONFIG_PATH=%s", g.Config.ConfigPath))
	lines = append(lines, fmt.Sprintf("SDBX_DATA_PATH=%s", g.Config.DataPath))
	lines = append(lines, fmt.Sprintf("SDBX_DOWNLOADS_PATH=%s", g.Config.DownloadsPath))
	lines = append(lines, fmt.Sprintf("SDBX_MEDIA_PATH=%s", g.Config.MediaPath))
	lines = append(lines, "")

	// Permissions
	lines = append(lines, fmt.Sprintf("PUID=%d", g.Config.PUID))
	lines = append(lines, fmt.Sprintf("PGID=%d", g.Config.PGID))
	lines = append(lines, fmt.Sprintf("UMASK=%s", g.Config.Umask))
	lines = append(lines, "")

	// VPN
	if g.Config.VPNEnabled {
		lines = append(lines, fmt.Sprintf("SDBX_VPN_PROVIDER=%s", g.Config.VPNProvider))
		lines = append(lines, fmt.Sprintf("SDBX_VPN_COUNTRY=%s", g.Config.VPNCountry))
		lines = append(lines, "")
	}
	lines = append(lines, fmt.Sprintf("SDBX_TORRENT_PEER_PORT=%d", g.Config.TorrentPort))
	lines = append(lines, "")

	// TLS
	if g.Config.Expose.Mode == config.ExposeModeDirect {
		lines = append(lines, fmt.Sprintf("TRAEFIK_ACME_EMAIL=%s", g.Config.Expose.TLS.Email))
		lines = append(lines, "")
	}

	// Enabled addons
	if len(g.Config.Addons) > 0 {
		lines = append(lines, fmt.Sprintf("# Addons: %s", strings.Join(g.Config.Addons, ", ")))
	}

	return []byte(strings.Join(lines, "\n") + "\n"), nil
}
