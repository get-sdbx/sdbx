package integrate

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
)

type fakeContainerAddressResolver struct {
	addresses map[string]netip.Addr
	calls     []string
	err       error
}

func (f *fakeContainerAddressResolver) Resolve(
	_ context.Context,
	containerName string,
	networkSuffix string,
) (netip.Addr, error) {
	f.calls = append(f.calls, containerName+networkSuffix)
	if f.err != nil {
		return netip.Addr{}, f.err
	}
	address, ok := f.addresses[containerName+networkSuffix]
	if !ok {
		return netip.Addr{}, errors.New("missing address")
	}
	return address, nil
}

func TestResolveHostServiceEndpointsPreservesStableDockerURLs(t *testing.T) {
	resolver := &fakeContainerAddressResolver{
		addresses: map[string]netip.Addr{
			"sdbx-prowlarr_app":     netip.MustParseAddr("172.20.0.4"),
			"sdbx-sonarr_app":       netip.MustParseAddr("172.20.0.5"),
			"sdbx-gluetun_download": netip.MustParseAddr("172.21.0.2"),
		},
	}
	services := map[string]*ServiceConfig{
		"prowlarr": {
			Name:    "prowlarr",
			URL:     "http://sdbx-prowlarr:9696",
			Enabled: true,
		},
		"sonarr": {
			Name:    "sonarr",
			URL:     "http://sdbx-sonarr:8989/sonarr",
			Enabled: true,
		},
		"qbittorrent": {
			Name:    "qbittorrent",
			URL:     "http://sdbx-gluetun:8080",
			Enabled: true,
		},
	}

	if err := ResolveHostServiceEndpoints(
		context.Background(),
		config.DefaultConfig(),
		services,
		resolver,
	); err != nil {
		t.Fatal(err)
	}
	if got := services["prowlarr"].URL; got != "http://sdbx-prowlarr:9696" {
		t.Fatalf("Prowlarr stable URL = %q", got)
	}
	if got := services["prowlarr"].ControlURL; got != "http://172.20.0.4:9696" {
		t.Fatalf("Prowlarr control URL = %q", got)
	}
	if got := services["sonarr"].URL; got != "http://sdbx-sonarr:8989/sonarr" {
		t.Fatalf("Sonarr stable URL = %q", got)
	}
	if got := services["sonarr"].ControlURL; got != "http://172.20.0.5:8989/sonarr" {
		t.Fatalf("Sonarr control URL = %q", got)
	}
	if got := services["qbittorrent"].URL; got != "http://sdbx-gluetun:8080" {
		t.Fatalf("qBittorrent stable URL = %q", got)
	}
	if got := services["qbittorrent"].ControlURL; got != "http://172.21.0.2:8080" {
		t.Fatalf("qBittorrent control URL = %q", got)
	}
}

func TestResolveHostServiceEndpointsFormatsIPv6(t *testing.T) {
	resolver := &fakeContainerAddressResolver{
		addresses: map[string]netip.Addr{
			"sdbx-sonarr_app": netip.MustParseAddr("fd00::20"),
		},
	}
	services := map[string]*ServiceConfig{
		"sonarr": {
			Name:    "sonarr",
			URL:     "http://sdbx-sonarr:8989",
			Enabled: true,
		},
	}

	if err := ResolveHostServiceEndpoints(
		context.Background(),
		config.DefaultConfig(),
		services,
		resolver,
	); err != nil {
		t.Fatal(err)
	}
	if got := services["sonarr"].ControlURL; got != "http://[fd00::20]:8989" {
		t.Fatalf("Sonarr control URL = %q", got)
	}
}

func TestResolveHostServiceEndpointsRejectsUnexpectedHosts(t *testing.T) {
	services := map[string]*ServiceConfig{
		"sonarr": {
			Name:    "sonarr",
			URL:     "https://example.test:8989",
			Enabled: true,
		},
	}
	err := ResolveHostServiceEndpoints(
		context.Background(),
		config.DefaultConfig(),
		services,
		&fakeContainerAddressResolver{},
	)
	if err == nil {
		t.Fatal("external integration endpoint was accepted")
	}
}

func TestResolveHostServiceEndpointsReportsResolutionFailure(t *testing.T) {
	services := map[string]*ServiceConfig{
		"sonarr": {
			Name:    "sonarr",
			URL:     "http://sdbx-sonarr:8989",
			Enabled: true,
		},
	}
	err := ResolveHostServiceEndpoints(
		context.Background(),
		config.DefaultConfig(),
		services,
		&fakeContainerAddressResolver{err: errors.New("inspect failed")},
	)
	if err == nil {
		t.Fatal("resolution failure was ignored")
	}
}
