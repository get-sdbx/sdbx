package routing

import (
	"context"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

func TestPlexAdvertiseURLs(t *testing.T) {
	def, err := registry.NewEmbeddedSource().LoadService(context.Background(), "plex")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Domain = "media.example.test"
	if got := PlexAdvertiseURLs(cfg, def); got != "" {
		t.Fatalf("default LAN project advertised an unbound listener: %q", got)
	}
	cfg.Plex.LANAddress = "fd00::20"
	cfg.Plex.LANPort = 32401
	if got := PlexAdvertiseURLs(cfg, def); got != "http://[fd00::20]:32401/" {
		t.Fatalf("private IPv6 URL = %q", got)
	}
	cfg.Expose.Mode = config.ExposeModeCloudflared
	cfg.Services["plex"] = config.ServiceOverride{Subdomain: "watch"}
	want := "http://[fd00::20]:32401/,https://watch.media.example.test:443/"
	if got := PlexAdvertiseURLs(cfg, def); got != want {
		t.Fatalf("advertised URLs = %q, want %q", got, want)
	}
	cfg.Plex.LANAddress = ""
	if got := PlexAdvertiseURLs(cfg, def); got != "https://watch.media.example.test:443/" {
		t.Fatalf("disabled private listener is still advertised: %q", got)
	}
}
