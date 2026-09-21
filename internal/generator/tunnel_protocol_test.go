package generator

import (
	"context"
	"reflect"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

func TestLockedTunnelProtocolsPreserveNetworkAndImagePolicy(t *testing.T) {
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		for _, protocol := range []string{"", "http2", "quic", "auto"} {
			t.Run(platform+"/"+protocol, func(t *testing.T) {
				cfg := config.DefaultConfig()
				cfg.Expose.Mode = config.ExposeModeCloudflared
				cfg.Expose.TunnelProtocol = protocol
				cfg.VPNEnabled = true
				cfg.VPNProvider = "custom"
				reg, err := registry.NewDefaultRegistry()
				if err != nil {
					t.Fatal(err)
				}
				lock, _, err := reg.GenerateLockFileWithOptions(context.Background(), cfg, registry.LockOptions{
					CLIVersion: "test", TargetPlatform: platform,
					ImageResolver: registry.NewOfficialImageDigestResolver(nil),
				})
				if err != nil {
					t.Fatal(err)
				}
				graph, err := reg.Resolve(context.Background(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				compose, err := NewComposeGeneratorWithLock(cfg, reg, lock).Generate(graph)
				if err != nil {
					t.Fatal(err)
				}
				connector := compose.Services["cloudflared"]
				if !contains(connector.Environment, "TUNNEL_TRANSPORT_PROTOCOL="+cfg.EffectiveTunnelProtocol()) {
					t.Fatalf("protocol missing from connector environment: %v", connector.Environment)
				}
				if !reflect.DeepEqual(connector.Networks, []string{registry.NetworkEdge}) || connector.NetworkMode != "" {
					t.Fatalf("connector network policy changed: %#v", connector)
				}
				if compose.Services["qbittorrent"].NetworkMode != "service:gluetun" {
					t.Fatal("tunnel protocol change removed VPN isolation")
				}
				lockedImage := lock.Services["cloudflared"].Image
				if lockedImage.Platform != platform || connector.Image != lockedImage.Repository+"@"+lockedImage.PlatformDigest {
					t.Fatalf("connector does not use locked platform/image: %#v", connector)
				}
			})
		}
	}
}
