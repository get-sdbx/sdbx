package integrate

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/securefs"
)

// arrPorts is the canonical internal-Docker-network port for each *arr.
// These match the linuxserver image defaults and can't be overridden via the
// path-migrated configs without also updating the corresponding service.yaml.
var arrPorts = map[string]int{
	"sonarr":   8989,
	"radarr":   7878,
	"lidarr":   8686,
	"whisparr": 6969,
	"prowlarr": 9696,
}

// IsArr returns true if the given service name is one of the *arr family
// that stores its API key in <ApiKey> in /config/config.xml.
func IsArr(name string) bool {
	_, ok := arrPorts[name]
	return ok
}

// ArrPort returns the internal port for the given *arr service.
func ArrPort(name string) int {
	return arrPorts[name]
}

// ArrDockerURL builds the docker-network URL for an *arr service using its
// canonical container name (sdbx-<name>) and port.
func ArrDockerURL(name string) string {
	port := arrPorts[name]
	if port == 0 {
		return ""
	}
	return fmt.Sprintf("http://sdbx-%s:%d", name, port)
}

// QBittorrentDockerURL returns the URL other containers use to reach
// qBittorrent. With VPN enabled qBT shares Gluetun's network namespace;
// without VPN it has its own address on the application network.
func QBittorrentDockerURL(cfg *config.Config) string {
	if cfg != nil && cfg.VPNEnabled {
		return "http://sdbx-gluetun:8080"
	}
	return "http://sdbx-qbittorrent:8080"
}

// arrConfigXMLPath returns the host filesystem path to an *arr's config.xml.
// Honors the project's configured ConfigPath (which may be absolute, e.g.
// /opt/sdbx/configs after a path migration) rather than the hardcoded
// "configs/" relative directory.
func arrConfigXMLPath(cfg *config.Config, name string) string {
	root := cfg.ConfigPath
	if root == "" {
		root = "./configs"
	}
	return filepath.Join(root, name, "config.xml")
}

// secretsFilePath returns the host filesystem path to a secrets file under
// the configured SecretsPath.
func secretsFilePath(cfg *config.Config, name string) string {
	root := cfg.SecretsPath
	if root == "" {
		root = "./secrets"
	}
	return filepath.Join(root, name)
}

// apiKeyRE matches the <ApiKey>...</ApiKey> element in an *arr's config.xml.
// Whitespace-tolerant inside the value, anchored to the tag.
var apiKeyRE = regexp.MustCompile(`(?s)<ApiKey>\s*([^<]+?)\s*</ApiKey>`)

// urlBaseRE matches the <UrlBase>...</UrlBase> element. *arrs configured for
// path routing (Settings → General → URL Base = "/sonarr" etc.) serve their
// API at the prefixed path; integrators must include the prefix when calling
// e.g. /api/v3/system/status.
var urlBaseRE = regexp.MustCompile(`(?s)<UrlBase>\s*([^<]*?)\s*</UrlBase>`)

// ReadArrAPIKey reads <ApiKey> out of an *arr's config.xml on disk. Returns
// "" with no error if the file does not exist or contains no key — callers
// should treat this as "not yet provisioned" rather than a hard failure.
func ReadArrAPIKey(cfg *config.Config, name string) (string, error) {
	path := arrConfigXMLPath(cfg, name)
	data, err := securefs.ReadRegularFile(path, maxManagedConfigSize)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	m := apiKeyRE.FindSubmatch(data)
	if m == nil {
		return "", nil
	}
	return strings.TrimSpace(string(m[1])), nil
}

// ReadArrUrlBase reads <UrlBase> out of an *arr's config.xml. Returns the
// URL prefix the *arr serves itself under (e.g. "/sonarr" when path routing
// is in use), or "" if no prefix is set. Errors only on read failures other
// than not-exist.
func ReadArrUrlBase(cfg *config.Config, name string) (string, error) {
	path := arrConfigXMLPath(cfg, name)
	data, err := securefs.ReadRegularFile(path, maxManagedConfigSize)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	m := urlBaseRE.FindSubmatch(data)
	if m == nil {
		return "", nil
	}
	base := strings.TrimSpace(string(m[1]))
	// Normalise: ensure leading slash (so callers can blindly concatenate),
	// but no trailing slash (so "/sonarr" + "/api/..." produces "/sonarr/api/...").
	if base == "" {
		return "", nil
	}
	if !strings.HasPrefix(base, "/") {
		base = "/" + base
	}
	base = strings.TrimRight(base, "/")
	return base, nil
}

// EnabledArrs returns the names of *arr services that are currently enabled
// in the project config, in a deterministic order (the order this package
// ranges over).
func EnabledArrs(cfg *config.Config) []string {
	order := []string{"prowlarr", "sonarr", "radarr", "lidarr", "whisparr"}
	out := make([]string, 0, len(order))
	for _, name := range order {
		if IsServiceEnabled(cfg, name) {
			out = append(out, name)
		}
	}
	return out
}

// IsServiceEnabled returns whether the verified registry graph marked the
// service active. Operational callers must resolve and attach that graph
// before invoking integration helpers.
func IsServiceEnabled(cfg *config.Config, name string) bool {
	if cfg == nil || cfg.ActiveServices == nil {
		return false
	}
	return cfg.ActiveServices[name]
}
