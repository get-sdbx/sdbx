package generator

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

func TestLockedPlexOptionalGPUAndPrivateListener(t *testing.T) {
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		for _, mode := range []string{"lan", "direct", "cloudflared"} {
			for _, address := range []string{"", "10.0.0.10", "fd00::10"} {
				t.Run(platform+"/"+mode+"/"+address, func(t *testing.T) {
					cfg := config.DefaultConfig()
					cfg.PlexEnabled = true
					cfg.SetExposureMode(mode)
					if mode == config.ExposeModeDirect {
						cfg.Expose.TLS.Email = "ops@example.test"
					}
					cfg.VPNEnabled = true
					cfg.VPNProvider = "custom"
					cfg.Plex.LANAddress = address
					if address != "" {
						cfg.Plex.HardwareDevice = "/dev/dri/renderD128"
						cfg.Plex.LANPort = 32401
					}
					reg, err := registry.NewDefaultRegistry()
					if err != nil {
						t.Fatal(err)
					}
					lock, _, err := reg.GenerateLockFileWithOptions(context.Background(), cfg, registry.LockOptions{
						CLIVersion: "test", TargetPlatform: platform, ImageResolver: registry.NewOfficialImageDigestResolver(nil),
					})
					if err != nil {
						t.Fatal(err)
					}
					graph, err := reg.Resolve(context.Background(), cfg)
					if err != nil {
						t.Fatal(err)
					}
					g := NewComposeGeneratorWithLock(cfg, reg, lock)
					compose, err := g.Generate(graph)
					if err != nil {
						t.Fatal(err)
					}
					plex := compose.Services["plex"]
					if address == "" {
						if len(plex.Devices) != 0 || len(plex.Ports) != 0 {
							t.Fatal("default Plex acquired host devices or a listener")
						}
					} else {
						if !reflect.DeepEqual(plex.Devices, []string{"/dev/dri/renderD128:/dev/dri/renderD128"}) ||
							!reflect.DeepEqual(plex.Ports, []string{cfg.Plex.LANBinding() + ":32400/tcp"}) ||
							!contains(plex.Environment, "ATTACHED_DEVICES_PERMS=/dev/dri/renderD128") {
							t.Fatalf("Plex host access was not generated: %#v", plex)
						}
					}
					for _, env := range plex.Environment {
						if strings.HasPrefix(env, "DOCKER_MODS=") {
							t.Fatal("AMD compatibility package was enabled without opt-in")
						}
					}
					if !reflect.DeepEqual(plex.Networks, []string{registry.NetworkApplication}) || plex.NetworkMode != "" {
						t.Fatal("Plex GPU access changed network placement")
					}
					if compose.Services["qbittorrent"].NetworkMode != "service:gluetun" || len(compose.Services["qbittorrent"].Ports) != 0 {
						t.Fatal("Plex host access changed the torrent VPN boundary")
					}
					if mode == "cloudflared" && len(compose.Services["traefik"].Ports) != 0 {
						t.Fatal("Plex listener exposed the tunnel ingress")
					}
					image := lock.Services["plex"].Image
					if plex.Image != image.Repository+"@"+image.PlatformDigest {
						t.Fatal("Plex image is not pinned to the target platform")
					}
					cfg.Plex.HardwareDevice = "/dev/dri/renderD128"
					cfg.Plex.AMDVAAPI = true
					updated, err := g.Generate(graph)
					if platform == "linux/arm64" {
						if err == nil || !strings.Contains(err.Error(), "only linux/amd64") {
							t.Fatalf("AMD compatibility platform boundary: %v", err)
						}
					} else {
						if err != nil {
							t.Fatal(err)
						}
						mods := ""
						for _, env := range updated.Services["plex"].Environment {
							if strings.HasPrefix(env, "DOCKER_MODS=") {
								mods = env
								break
							}
						}
						if !strings.Contains(mods, "@sha256:") || strings.Contains(mods, ":latest") {
							t.Fatalf("AMD package is not immutable: %q", mods)
						}
					}
				})
			}
		}
	}
}

func TestPrivatePlexListenerCannotBroadenOtherTunnelBindings(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Expose.Mode = config.ExposeModeCloudflared
	cfg.Plex.LANAddress = "10.0.0.10"
	g := NewComposeGenerator(cfg, nil)
	def, err := registry.NewEmbeddedSource().LoadService(context.Background(), "plex")
	if err != nil {
		t.Fatal(err)
	}
	port := "10.0.0.10:32400:32400/tcp"
	for _, change := range []func(*registry.ServiceDefinition){
		func(d *registry.ServiceDefinition) { d.Metadata.Name = "sonarr" },
		func(d *registry.ServiceDefinition) { d.Routing.Auth.Mode = registry.AuthModeProtected },
		func(d *registry.ServiceDefinition) { d.Permissions = nil },
	} {
		copy := *def
		change(&copy)
		if _, err := g.normalizePortBinding(&copy, port); err == nil {
			t.Fatal("private Plex exception broadened a different security boundary")
		}
	}
	for _, bad := range []string{"10.0.0.10:32400:8989/tcp", "10.0.0.11:32400:32400/tcp", "0.0.0.0:32400:32400/tcp"} {
		if _, err := g.normalizePortBinding(def, bad); err == nil {
			t.Fatalf("accepted unconfigured tunnel port %q", bad)
		}
	}
}

func TestConditionalDeviceRenderingFailsClosed(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Plex.HardwareDevice = "/dev/dri/renderD128"
	def, err := registry.NewEmbeddedSource().LoadService(context.Background(), "plex")
	if err != nil {
		t.Fatal(err)
	}
	g := NewComposeGenerator(cfg, nil)
	ctx := TemplateContext{Config: catalogTemplateConfig(cfg, def), Name: "plex"}
	for _, value := range []string{"/dev/mem:/dev/null", "/etc/passwd:/dev/null", "/dev/dri/../mem:/dev/null", "/dev/dri/renderD128:/dev/null:invalid", "/dev/dri/renderD128\n:/dev/null", "{{ .Config.Unknown }}"} {
		def.Spec.Container.ConditionalDevices[0].Device = value
		if _, err := g.buildDevices(def, ctx); err == nil {
			t.Fatalf("accepted invalid conditional device %q", value)
		}
	}
}
