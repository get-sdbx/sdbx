package integrate

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/get-sdbx/sdbx/internal/commandexec"
	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/redact"
)

// ContainerAddressResolver resolves one known SDBX container on its expected
// logical Compose network.
type ContainerAddressResolver interface {
	Resolve(
		context.Context,
		string,
		string,
	) (netip.Addr, error)
}

// DockerContainerAddressResolver resolves addresses through the host Docker
// CLI. It never mounts or opens the Docker socket inside another container.
type DockerContainerAddressResolver struct{}

// Resolve returns the address on a Compose network whose name ends in the
// requested logical suffix, such as "_app" or "_download".
func (DockerContainerAddressResolver) Resolve(
	ctx context.Context,
	containerName string,
	networkSuffix string,
) (netip.Addr, error) {
	if !strings.HasPrefix(containerName, "sdbx-") {
		return netip.Addr{}, fmt.Errorf(
			"refusing to inspect non-SDBX container %q",
			containerName,
		)
	}
	if networkSuffix != "_app" && networkSuffix != "_download" {
		return netip.Addr{}, fmt.Errorf(
			"unsupported integration network %q",
			networkSuffix,
		)
	}

	output, err := commandexec.CombinedOutput(
		ctx,
		1<<20,
		nil,
		"docker",
		"inspect",
		"--format",
		"{{json .NetworkSettings.Networks}}",
		containerName,
	)
	if err != nil {
		return netip.Addr{}, fmt.Errorf(
			"inspect %s: %w: %s",
			containerName,
			err,
			redact.Text(strings.TrimSpace(string(output))),
		)
	}

	var networks map[string]struct {
		IPAddress         string `json:"IPAddress"`
		GlobalIPv6Address string `json:"GlobalIPv6Address"`
	}
	if err := json.Unmarshal(output, &networks); err != nil {
		return netip.Addr{}, fmt.Errorf(
			"decode Docker networks for %s: %w",
			containerName,
			err,
		)
	}

	names := make([]string, 0, len(networks))
	for name := range networks {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !strings.HasSuffix(name, networkSuffix) {
			continue
		}
		network := networks[name]
		for _, value := range []string{
			network.IPAddress,
			network.GlobalIPv6Address,
		} {
			address, parseErr := netip.ParseAddr(value)
			if parseErr != nil ||
				!address.IsValid() ||
				address.IsUnspecified() ||
				address.IsLoopback() {
				continue
			}
			return address.Unmap(), nil
		}
	}

	return netip.Addr{}, fmt.Errorf(
		"%s has no usable address on the %s network",
		containerName,
		strings.TrimPrefix(networkSuffix, "_"),
	)
}

// ResolveHostServiceEndpoints assigns host-reachable control URLs for
// verified internal Docker-DNS endpoints. The stable service-to-service URL
// remains unchanged so generated application settings never persist an
// ephemeral bridge address.
func ResolveHostServiceEndpoints(
	ctx context.Context,
	cfg *config.Config,
	services map[string]*ServiceConfig,
	resolver ContainerAddressResolver,
) error {
	if cfg == nil {
		return fmt.Errorf("project configuration is required")
	}
	if resolver == nil {
		return fmt.Errorf("container address resolver is required")
	}

	names := make([]string, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		service := services[name]
		if service == nil || !service.Enabled {
			continue
		}
		parsed, err := url.Parse(service.URL)
		if err != nil {
			return fmt.Errorf("parse %s integration endpoint: %w", name, err)
		}
		if parsed.Scheme != "http" || parsed.Hostname() == "" {
			return fmt.Errorf(
				"%s integration endpoint must use an internal HTTP URL",
				name,
			)
		}
		containerName := parsed.Hostname()
		if !strings.HasPrefix(containerName, "sdbx-") {
			return fmt.Errorf(
				"%s integration endpoint has unexpected host %q",
				name,
				containerName,
			)
		}

		networkSuffix := "_app"
		if name == "qbittorrent" || name == "qui" {
			networkSuffix = "_download"
		}
		address, err := resolver.Resolve(
			ctx,
			containerName,
			networkSuffix,
		)
		if err != nil {
			return fmt.Errorf(
				"resolve host endpoint for %s: %w",
				name,
				err,
			)
		}

		port := parsed.Port()
		if port == "" {
			port = "80"
		}
		parsed.Host = net.JoinHostPort(address.String(), port)
		service.ControlURL = parsed.String()
	}
	return nil
}
