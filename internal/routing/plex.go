package routing

import (
	"fmt"
	"strings"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

// PlexAdvertiseURLs advertises an explicitly enabled private listener alongside
// the routed HTTPS endpoint. The private listener does not replace public TLS.
func PlexAdvertiseURLs(cfg *config.Config, definition *registry.ServiceDefinition) string {
	var urls []string
	if binding := cfg.Plex.LANBinding(); binding != "" {
		urls = append(urls, "http://"+binding+"/")
	}
	if cfg.Expose.Mode != config.ExposeModeLAN {
		urls = append(urls, fmt.Sprintf("https://%s:443/", Hostname(cfg, definition)))
	}
	return strings.Join(urls, ",")
}
