package generator

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

func TestMergedCatalogGeneratesUsableCoreCompose(t *testing.T) {
	reg, err := registry.New(&registry.SourceConfig{
		APIVersion: registry.APIVersion,
		Kind:       registry.KindSourceConfig,
	})
	if err != nil {
		t.Fatalf("New registry failed: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.Domain = "sdbx.one"
	cfg.Expose.Mode = config.ExposeModeCloudflared
	cfg.Routing.Strategy = config.RoutingStrategyPath
	cfg.VPNEnabled = false
	cfg.PlexEnabled = true

	graph, err := reg.Resolve(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(graph.Errors) > 0 {
		t.Fatalf("Resolve produced errors: %#v", graph.Errors)
	}
	autheliaDefinition := graph.Services["authelia"].FinalDefinition
	if autheliaDefinition == nil {
		t.Fatal("resolved Authelia definition is missing")
	}
	autheliaChownVolumes := map[string]bool{}
	for _, volume := range autheliaDefinition.Spec.Volumes {
		autheliaChownVolumes[volume.ContainerPath] = volume.Chown
	}
	for _, path := range []string{"/config", "/data"} {
		if !autheliaChownVolumes[path] {
			t.Fatalf("authelia volume %s must opt in to PUID:PGID ownership", path)
		}
	}

	compose, err := NewComposeGenerator(cfg, reg).Generate(graph)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if len(compose.Services) == 0 {
		t.Fatal("Generate produced no services")
	}

	qbit := compose.Services["qbittorrent"]
	if qbit.NetworkMode != "" {
		t.Fatalf("qBittorrent NetworkMode = %q, want empty bridge networks", qbit.NetworkMode)
	}
	if !contains(qbit.Networks, registry.NetworkDownload) {
		t.Fatalf("qBittorrent Networks = %#v, want download network", qbit.Networks)
	}

	cloudflared := compose.Services["cloudflared"]
	if cloudflared.Command != "tunnel run" {
		t.Fatalf("cloudflared Command = %q, want tunnel run", cloudflared.Command)
	}
	expectedCloudflaredHealthcheck := []string{
		"CMD",
		"/usr/local/bin/cloudflared",
		"tunnel",
		"--metrics",
		"127.0.0.1:2000",
		"ready",
	}
	if cloudflared.HealthCheck == nil ||
		!slices.Equal(
			cloudflared.HealthCheck.Test,
			expectedCloudflaredHealthcheck,
		) {
		t.Fatalf(
			"cloudflared healthcheck = %#v, want %#v",
			cloudflared.HealthCheck,
			expectedCloudflaredHealthcheck,
		)
	}
	if !contains(cloudflared.Environment, "TUNNEL_TOKEN_FILE=/run/secrets/cloudflared_tunnel_token") {
		t.Fatalf("cloudflared Environment = %#v, want file-backed tunnel token", cloudflared.Environment)
	}
	if !contains(cloudflared.Environment, "TUNNEL_METRICS=127.0.0.1:2000") {
		t.Fatalf(
			"cloudflared Environment = %#v, want loopback readiness endpoint",
			cloudflared.Environment,
		)
	}
	if !contains(cloudflared.Environment, "TUNNEL_TRANSPORT_PROTOCOL=http2") {
		t.Fatal("Cloudflared must default to HTTP/2")
	}
	for _, mount := range cloudflared.Volumes {
		if strings.Contains(mount, "/etc/cloudflared") {
			t.Fatalf(
				"cloudflared Volumes = %#v, remote tunnel must not mount local config",
				cloudflared.Volumes,
			)
		}
	}
	if !contains(cloudflared.Secrets, "cloudflared_tunnel_token") {
		t.Fatalf("cloudflared Secrets = %#v, want tunnel token mount", cloudflared.Secrets)
	}
	if cloudflared.DependsOn["traefik"].Condition == "" {
		t.Fatalf("cloudflared depends_on.traefik missing condition: %#v", cloudflared.DependsOn)
	}

	authelia := compose.Services["authelia"]
	if !contains(authelia.CapDrop, "ALL") {
		t.Fatalf("authelia CapDrop = %#v, want ALL", authelia.CapDrop)
	}
	for _, capability := range []string{"CHOWN", "SETGID", "SETUID"} {
		if !contains(authelia.CapAdd, capability) {
			t.Fatalf(
				"authelia CapAdd = %#v, want entrypoint capability %s",
				authelia.CapAdd,
				capability,
			)
		}
	}
	for _, variable := range []string{"PUID=1000", "PGID=1000", "UMASK=002"} {
		if !contains(authelia.Environment, variable) {
			t.Fatalf(
				"authelia Environment = %#v, want privilege-drop variable %q",
				authelia.Environment,
				variable,
			)
		}
	}
	configMountFound := false
	for _, mount := range authelia.Volumes {
		if strings.HasSuffix(mount, ":/config:ro") {
			t.Fatalf("authelia config mount is read-only: %q", mount)
		}
		if strings.HasSuffix(mount, ":/config") {
			configMountFound = true
		}
	}
	if !configMountFound {
		t.Fatalf("authelia Volumes = %#v, want writable /config mount", authelia.Volumes)
	}

	plex := compose.Services["plex"]
	if plex.ShmSize != "2g" {
		t.Fatalf("plex ShmSize = %q, want 2g", plex.ShmSize)
	}
	if !contains(plex.Environment, "FILE__PLEX_CLAIM=/run/secrets/plex_claim_token") {
		t.Fatalf("plex Environment = %#v, want file-backed claim token", plex.Environment)
	}
	if !contains(plex.Secrets, "plex_claim_token") {
		t.Fatalf("plex Secrets = %#v, want claim token mount", plex.Secrets)
	}
	if plex.HealthCheck == nil || len(plex.HealthCheck.Test) == 0 {
		t.Fatal("plex healthcheck was not generated")
	}
}

func TestEvalConditionTrimsSupportedInputAndFailsClosed(t *testing.T) {
	ctx := TemplateContext{
		Config: CatalogTemplateConfig{VPNEnabled: true},
	}
	matches, err := evalCatalogCondition(" \n{{ .Config.VPNEnabled }}\t", ctx)
	if err != nil {
		t.Fatalf("supported condition failed: %v", err)
	}
	if !matches {
		t.Fatal("supported condition with surrounding whitespace evaluated false")
	}
	if _, err := evalCatalogCondition("{{ .Config.Unknown }}", ctx); err == nil {
		t.Fatal("unknown condition did not fail closed")
	}
	if _, err := evalCatalogCondition("enabled", ctx); err == nil {
		t.Fatal("non-boolean condition did not fail closed")
	}
	if _, err := evalCatalogCondition("{{", ctx); err == nil {
		t.Fatal("malformed condition did not fail closed")
	}
}

func TestGenerateServiceRejectsInvalidCatalogRendering(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*registry.ServiceDefinition)
		wantError string
	}{
		{
			name: "container name",
			mutate: func(def *registry.ServiceDefinition) {
				def.Spec.Container.NameTemplate = "{{ .Config.Unknown }}"
			},
			wantError: "render container name",
		},
		{
			name: "container command",
			mutate: func(def *registry.ServiceDefinition) {
				def.Spec.Container.Command = "{{ .Config.Unknown }}"
			},
			wantError: "render container command",
		},
		{
			name: "working directory",
			mutate: func(def *registry.ServiceDefinition) {
				def.Spec.Container.WorkingDir = "{{ .Config.Unknown }}"
			},
			wantError: "render container working directory",
		},
		{
			name: "static environment value",
			mutate: func(def *registry.ServiceDefinition) {
				def.Spec.Environment.Static = []registry.EnvVar{{
					Name:  "EXAMPLE",
					Value: "{{ .Config.Unknown }}",
				}}
			},
			wantError: "render static environment variable 0 (EXAMPLE)",
		},
		{
			name: "conditional environment condition",
			mutate: func(def *registry.ServiceDefinition) {
				def.Spec.Environment.Conditional = []registry.ConditionalEnvVar{{
					EnvVar: registry.EnvVar{Name: "EXAMPLE", Value: "value"},
					When:   "enabled",
				}}
			},
			wantError: "evaluate conditional environment variable 0 (EXAMPLE)",
		},
		{
			name: "conditional environment value",
			mutate: func(def *registry.ServiceDefinition) {
				def.Spec.Environment.Conditional = []registry.ConditionalEnvVar{{
					EnvVar: registry.EnvVar{
						Name:  "EXAMPLE",
						Value: "{{ .Config.Unknown }}",
					},
					When: "true",
				}}
			},
			wantError: "render conditional environment variable 0 (EXAMPLE)",
		},
		{
			name: "volume condition",
			mutate: func(def *registry.ServiceDefinition) {
				def.Spec.Volumes = []registry.VolumeMount{{
					HostPath:      "/tmp/example",
					ContainerPath: "/example",
					When:          "enabled",
				}}
			},
			wantError: "evaluate volume 0 condition",
		},
		{
			name: "volume path",
			mutate: func(def *registry.ServiceDefinition) {
				def.Spec.Volumes = []registry.VolumeMount{{
					HostPath:      "{{ .Config.Unknown }}",
					ContainerPath: "/example",
				}}
			},
			wantError: "render volume 0 host path",
		},
		{
			name: "static port",
			mutate: func(def *registry.ServiceDefinition) {
				def.Spec.Ports.Static = []string{"{{ .Config.Unknown }}"}
			},
			wantError: "render static port 0",
		},
		{
			name: "conditional port condition",
			mutate: func(def *registry.ServiceDefinition) {
				def.Spec.Ports.Conditional = []registry.ConditionalPort{{
					Port: "8080:8080",
					When: "enabled",
				}}
			},
			wantError: "evaluate conditional port 0",
		},
		{
			name: "network mode",
			mutate: func(def *registry.ServiceDefinition) {
				def.Spec.Networking.ModeTemplate = "{{ .Config.Unknown }}"
			},
			wantError: "render network mode",
		},
		{
			name: "network condition",
			mutate: func(def *registry.ServiceDefinition) {
				def.Permissions = []string{"network:" + registry.NetworkApplication}
				def.Spec.Networking.Networks = []registry.NetworkRef{{
					Name: registry.NetworkApplication,
					When: "enabled",
				}}
			},
			wantError: "evaluate network 0 (app) condition",
		},
		{
			name: "dependency condition",
			mutate: func(def *registry.ServiceDefinition) {
				def.Spec.Dependencies.Conditional = []registry.ConditionalDependency{{
					Name: "dependency",
					When: "enabled",
				}}
			},
			wantError: "evaluate conditional dependency 0 (dependency)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			def := strictTemplateTestDefinition()
			test.mutate(def)

			_, err := NewComposeGenerator(config.DefaultConfig(), nil).
				generateService(def)
			if err == nil {
				t.Fatal("generateService accepted invalid catalog rendering")
			}
			if !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %q, want %q", err, test.wantError)
			}
		})
	}
}

func strictTemplateTestDefinition() *registry.ServiceDefinition {
	return &registry.ServiceDefinition{
		Metadata: registry.ServiceMetadata{Name: "test"},
		Spec: registry.ServiceSpec{
			Image: registry.ImageSpec{
				Repository: "alpine",
				Tag:        "latest",
			},
			Container: registry.ContainerSpec{
				NameTemplate: "sdbx-{{ .Name }}",
			},
		},
	}
}

func TestCatalogWebPortsFollowExposureContract(t *testing.T) {
	reg, err := registry.New(&registry.SourceConfig{
		APIVersion: registry.APIVersion,
		Kind:       registry.KindSourceConfig,
	})
	if err != nil {
		t.Fatalf("New registry failed: %v", err)
	}

	for _, mode := range []string{
		config.ExposeModeLAN,
		config.ExposeModeDirect,
		config.ExposeModeCloudflared,
	} {
		for _, strategy := range []string{
			config.RoutingStrategySubdomain,
			config.RoutingStrategyPath,
		} {
			for _, vpnEnabled := range []bool{false, true} {
				testName := mode + "/" + strategy
				if vpnEnabled {
					testName += "/vpn"
				} else {
					testName += "/no-vpn"
				}
				t.Run(testName, func(t *testing.T) {
					cfg := config.DefaultConfig()
					cfg.Domain = "media.example.test"
					cfg.Expose.Mode = mode
					cfg.Routing.Strategy = strategy
					cfg.Routing.BaseDomain = "box"
					cfg.PlexEnabled = true
					cfg.JellyfinEnabled = true
					cfg.Addons = []string{
						"filebrowser",
						"nzbhydra2",
						"prowlarr",
						"sonarr",
					}
					cfg.VPNEnabled = vpnEnabled
					cfg.VPNProvider = "mullvad"
					cfg.TorrentPort = 51413
					if mode == config.ExposeModeDirect {
						cfg.Expose.TLS.Provider = "acme"
						cfg.Expose.TLS.Email = "ops@example.test"
					}

					graph, err := reg.Resolve(context.Background(), cfg)
					if err != nil {
						t.Fatal(err)
					}
					if len(graph.Errors) > 0 {
						t.Fatalf("Resolve produced errors: %#v", graph.Errors)
					}
					compose, err := NewComposeGenerator(cfg, reg).Generate(graph)
					if err != nil {
						t.Fatal(err)
					}

					for _, serviceName := range []string{
						"authelia",
						"cloudflared",
						"filebrowser",
						"jellyfin",
						"nzbhydra2",
						"plex",
						"prowlarr",
						"sonarr",
					} {
						service, exists := compose.Services[serviceName]
						if !exists {
							continue
						}
						if len(service.Ports) != 0 {
							t.Fatalf(
								"%s publishes a Traefik-bypassing Web port in %s: %#v",
								serviceName,
								testName,
								service.Ports,
							)
						}
					}

					wantTraefikPorts := []string(nil)
					if mode != config.ExposeModeCloudflared {
						wantTraefikPorts = []string{"80:80", "443:443"}
					}
					if !slices.Equal(
						compose.Services["traefik"].Ports,
						wantTraefikPorts,
					) {
						t.Fatalf(
							"Traefik ports in %s = %#v, want %#v",
							testName,
							compose.Services["traefik"].Ports,
							wantTraefikPorts,
						)
					}

					for _, owner := range []string{"gluetun", "qbittorrent"} {
						service, exists := compose.Services[owner]
						if !exists {
							continue
						}
						for _, port := range service.Ports {
							if strings.HasSuffix(port, ":8080") &&
								!strings.HasPrefix(port, "127.0.0.1:") {
								t.Fatalf(
									"%s Web UI is not loopback-only in %s: %q",
									owner,
									testName,
									port,
								)
							}
						}
					}
				})
			}
		}
	}
}

func TestComposeGeneratorRejectsResolutionErrors(t *testing.T) {
	cfg := config.DefaultConfig()
	_, err := NewComposeGenerator(cfg, nil).Generate(&registry.ResolutionGraph{
		Services: map[string]*registry.ResolvedService{},
		Errors: []registry.ResolutionError{
			{
				Service: "sonarr",
				Message: "failed to resolve",
			},
		},
	})
	if err == nil {
		t.Fatal("Generate succeeded with resolution errors")
	}
}

func TestComposeGeneratorEmitsOnlyLockedImageDigest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	def := &registry.ServiceDefinition{
		Metadata: registry.ServiceMetadata{Name: "test", Version: "1.0.0"},
		Spec: registry.ServiceSpec{
			Image: registry.ImageSpec{
				Registry:   "docker.io",
				Repository: "alpine",
				Tag:        "3.23",
			},
			Container: registry.ContainerSpec{NameTemplate: "sdbx-{{ .Name }}"},
		},
		Conditions: registry.Conditions{Always: true},
	}
	graph := &registry.ResolutionGraph{
		Services: map[string]*registry.ResolvedService{
			"test": {
				Name:            "test",
				FinalDefinition: def,
				Enabled:         true,
			},
		},
		Order: []string{"test"},
	}
	lock := &registry.LockFile{
		APIVersion: registry.APIVersion,
		Kind:       registry.KindLockFile,
		Metadata: registry.LockFileMetadata{
			Version:        2,
			GeneratedAt:    time.Now().UTC(),
			CLIVersion:     "test",
			CatalogVersion: digest,
			ConfigDigest:   digest,
			CatalogDigest:  digest,
		},
		Sources: map[string]registry.LockedSource{
			"embedded": {
				Type:     "embedded",
				Ref:      digest,
				Commit:   digest,
				Digest:   digest,
				Verified: true,
			},
		},
		Services: map[string]registry.LockedService{
			"test": {
				Source:            "embedded",
				DefinitionVersion: "1.0.0",
				DefinitionDigest:  digest,
				Image: registry.LockedImage{
					Registry:       "docker.io",
					Repository:     "alpine",
					Tag:            "3.23",
					Digest:         digest,
					Platform:       "linux/arm64",
					PlatformDigest: digest,
					PlatformDigests: map[string]string{
						"linux/arm64": digest,
					},
				},
				ResolvedFrom: "embedded://services/test/service.yaml",
			},
		},
		InstallOrder: []string{"test"},
	}

	compose, err := NewComposeGeneratorWithLock(
		config.DefaultConfig(),
		nil,
		lock,
	).Generate(graph)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if got := compose.Services["test"].Image; got != "alpine@"+digest {
		t.Fatalf("image = %q, want digest pin", got)
	}
}

func TestEveryEmbeddedAddonGeneratesCompose(t *testing.T) {
	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	addons, err := registry.NewEmbeddedSource().GetAddonServices()
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.Domain = "example.test"
	cfg.Expose.Mode = config.ExposeModeLAN
	cfg.Routing.Strategy = config.RoutingStrategySubdomain
	cfg.PlexEnabled = true
	cfg.JellyfinEnabled = true
	cfg.Addons = make([]string, 0, len(addons))
	for _, addon := range addons {
		cfg.Addons = append(cfg.Addons, addon.Metadata.Name)
	}
	slices.Sort(cfg.Addons)

	graph, err := reg.Resolve(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Errors) > 0 {
		t.Fatalf("Resolve produced errors: %#v", graph.Errors)
	}
	compose, err := NewComposeGenerator(cfg, reg).Generate(graph)
	if err != nil {
		t.Fatal(err)
	}
	for _, addon := range addons {
		if _, exists := compose.Services[addon.Metadata.Name]; !exists {
			t.Errorf("enabled addon %s is absent from generated Compose", addon.Metadata.Name)
		}
	}

	notifiarr := compose.Services["notifiarr"]
	if notifiarr.Hostname != "notifiarr" {
		t.Errorf("Notifiarr hostname = %q, want notifiarr", notifiarr.Hostname)
	}
	seerr := compose.Services["seerr"]
	if !seerr.Init {
		t.Error("Seerr must run with an init process")
	}
	janitorrDefinition := graph.Services["janitorr"].FinalDefinition
	if janitorrDefinition == nil {
		t.Fatal("resolved Janitorr definition is missing")
	}
	janitorrConfigVolumeFound := false
	janitorrLogVolumeFound := false
	for _, volume := range janitorrDefinition.Spec.Volumes {
		if volume.ContainerPath == "/config" {
			janitorrConfigVolumeFound = true
			if !volume.Chown || volume.ChownUID != 1002 || volume.ChownGID != 1001 {
				t.Fatalf("Janitorr config volume ownership = %#v", volume)
			}
		}
		if volume.ContainerPath != "/logs" {
			continue
		}
		janitorrLogVolumeFound = true
		if !volume.Chown || volume.ChownUID != 1002 || volume.ChownGID != 1001 {
			t.Fatalf("Janitorr log volume ownership = %#v", volume)
		}
	}
	if !janitorrConfigVolumeFound {
		t.Fatal("Janitorr /config volume is missing")
	}
	if !janitorrLogVolumeFound {
		t.Fatal("Janitorr /logs volume is missing")
	}
	if seerr.HealthCheck == nil ||
		len(seerr.HealthCheck.Test) != 2 ||
		!strings.Contains(seerr.HealthCheck.Test[1], "http://127.0.0.1:5055/") {
		t.Fatalf(
			"Seerr healthcheck = %#v, want an IPv4 loopback probe",
			seerr.HealthCheck,
		)
	}
	tdarr := compose.Services["tdarr"]
	if len(tdarr.Devices) != 0 || len(tdarr.CapAdd) != 0 {
		t.Fatalf("Tdarr CPU baseline has unexpected host access: %#v", tdarr)
	}
	if _, exists := compose.Services["homepage"]; exists {
		t.Fatal("retired Homepage addon is present in generated Compose")
	}
}

func TestComposeGenerationIsByteIdenticalWithSameConfigAndLock(t *testing.T) {
	cfg := config.DefaultConfig()
	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	graph, err := reg.Resolve(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	lock, _, err := reg.GenerateLockFileWithOptions(
		context.Background(),
		cfg,
		registry.LockOptions{
			CLIVersion:     "test",
			TargetPlatform: "linux/amd64",
			ImageResolver:  deterministicImageResolver{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	first, err := NewComposeGeneratorWithLock(cfg, reg, lock).Generate(graph)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewComposeGeneratorWithLock(cfg, reg, lock).Generate(graph)
	if err != nil {
		t.Fatal(err)
	}
	firstYAML, err := first.ToYAML()
	if err != nil {
		t.Fatal(err)
	}
	secondYAML, err := second.ToYAML()
	if err != nil {
		t.Fatal(err)
	}
	if string(firstYAML) != string(secondYAML) {
		t.Fatal("same config and lock produced different compose.yaml bytes")
	}
}

type deterministicImageResolver struct{}

func (deterministicImageResolver) Resolve(
	_ context.Context,
	repository, tag string,
) (registry.ResolvedImage, error) {
	digest := "sha256:" + strings.Repeat("b", 64)
	return registry.ResolvedImage{
		Digest: digest,
		PlatformDigests: map[string]string{
			"linux/amd64": digest,
		},
	}, nil
}

func TestComposeGeneratorAppliesNoNewPrivileges(t *testing.T) {
	cfg := config.DefaultConfig()
	def := &registry.ServiceDefinition{
		Metadata: registry.ServiceMetadata{
			Name: "test",
		},
		Permissions: []string{registry.PermissionHostPort},
		Spec: registry.ServiceSpec{
			Image: registry.ImageSpec{
				Repository: "alpine",
				Tag:        "latest",
			},
			Container: registry.ContainerSpec{
				NameTemplate: "sdbx-{{ .Name }}",
			},
		},
	}

	service, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err != nil {
		t.Fatalf("generateService failed: %v", err)
	}
	if !contains(service.SecurityOpt, "no-new-privileges:true") {
		t.Fatalf("SecurityOpt = %#v, want no-new-privileges:true", service.SecurityOpt)
	}
	if service.PidsLimit != 512 {
		t.Fatalf("PidsLimit = %d, want 512", service.PidsLimit)
	}
	if service.StopGrace != "30s" {
		t.Fatalf("StopGrace = %q, want 30s", service.StopGrace)
	}
	if service.Logging == nil ||
		service.Logging.Driver != "local" ||
		service.Logging.Options["max-size"] != "10m" ||
		service.Logging.Options["max-file"] != "3" {
		t.Fatalf("Logging = %#v, want bounded local logs", service.Logging)
	}
}

func TestComposeGeneratorRendersNonRootContainerUser(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.PUID = 1200
	cfg.PGID = 1300
	def := &registry.ServiceDefinition{
		Metadata: registry.ServiceMetadata{Name: "test"},
		Spec: registry.ServiceSpec{
			Image: registry.ImageSpec{Repository: "example/test", Tag: "latest"},
			Container: registry.ContainerSpec{
				NameTemplate: "sdbx-{{ .Name }}",
				User:         "{{ .Config.PUID }}:{{ .Config.PGID }}",
			},
		},
	}

	service, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err != nil {
		t.Fatal(err)
	}
	if service.User != "1200:1300" {
		t.Fatalf("container user = %q, want 1200:1300", service.User)
	}

	for _, unsafe := range []string{"0", "0:1000", "1000:0", "root", "1000:1000:1000"} {
		def.Spec.Container.User = unsafe
		if _, err := NewComposeGenerator(cfg, nil).generateService(def); err == nil {
			t.Fatalf("accepted unsafe container user %q", unsafe)
		}
	}
}

func TestComposeGeneratorRendersStableContainerHostname(t *testing.T) {
	cfg := config.DefaultConfig()
	def := &registry.ServiceDefinition{
		Metadata: registry.ServiceMetadata{Name: "test"},
		Spec: registry.ServiceSpec{
			Image: registry.ImageSpec{Repository: "example/test", Tag: "latest"},
			Container: registry.ContainerSpec{
				NameTemplate: "sdbx-{{ .Name }}",
				Hostname:     "notifiarr",
			},
		},
	}

	service, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err != nil {
		t.Fatal(err)
	}
	if service.Hostname != "notifiarr" {
		t.Fatalf("container hostname = %q, want notifiarr", service.Hostname)
	}

	for _, unsafe := range []string{"Notifiarr", "-notifiarr", "notifiarr-", "notifiarr.local"} {
		def.Spec.Container.Hostname = unsafe
		if _, err := NewComposeGenerator(cfg, nil).generateService(def); err == nil {
			t.Fatalf("accepted unsafe container hostname %q", unsafe)
		}
	}
}

func TestComposeGeneratorBindsCloudflaredPortsToLoopback(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Expose.Mode = config.ExposeModeCloudflared
	def := &registry.ServiceDefinition{
		Metadata: registry.ServiceMetadata{
			Name: "test",
		},
		Permissions: []string{registry.PermissionHostPort},
		Spec: registry.ServiceSpec{
			Image: registry.ImageSpec{
				Repository: "alpine",
				Tag:        "latest",
			},
			Container: registry.ContainerSpec{
				NameTemplate: "sdbx-{{ .Name }}",
			},
			Ports: registry.PortSpec{
				Static: []string{
					"32400:32400",
					"6881:6881/udp",
					"127.0.0.1:9000:9000",
				},
			},
		},
	}

	service, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err != nil {
		t.Fatalf("generateService failed: %v", err)
	}
	want := []string{
		"127.0.0.1:32400:32400",
		"127.0.0.1:6881:6881/udp",
		"127.0.0.1:9000:9000",
	}
	for _, port := range want {
		if !contains(service.Ports, port) {
			t.Fatalf("Ports = %#v, want %s", service.Ports, port)
		}
	}
}

func TestComposeGeneratorRejectsExplicitPublicBindingInCloudflaredMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Expose.Mode = config.ExposeModeCloudflared
	def := &registry.ServiceDefinition{
		Metadata:    registry.ServiceMetadata{Name: "test"},
		Permissions: []string{registry.PermissionHostPort},
		Spec: registry.ServiceSpec{
			Image: registry.ImageSpec{
				Repository: "alpine",
				Tag:        "latest",
			},
			Container: registry.ContainerSpec{
				NameTemplate: "sdbx-{{ .Name }}",
			},
			Ports: registry.PortSpec{
				Static: []string{"0.0.0.0:8080:8080"},
			},
		},
	}

	_, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("generateService() error = %v, want non-loopback rejection", err)
	}
}

func TestComposeGeneratorKeepsDirectPortsPublic(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Expose.Mode = config.ExposeModeDirect
	cfg.Expose.TLS.Provider = "acme"
	cfg.Expose.TLS.Email = "ops@example.test"
	def := &registry.ServiceDefinition{
		Metadata: registry.ServiceMetadata{
			Name: "test",
		},
		Permissions: []string{registry.PermissionHostPort},
		Spec: registry.ServiceSpec{
			Image: registry.ImageSpec{
				Repository: "alpine",
				Tag:        "latest",
			},
			Container: registry.ContainerSpec{
				NameTemplate: "sdbx-{{ .Name }}",
			},
			Ports: registry.PortSpec{
				Static: []string{"80:80"},
			},
		},
	}

	service, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err != nil {
		t.Fatalf("generateService failed: %v", err)
	}
	if !contains(service.Ports, "80:80") {
		t.Fatalf("Ports = %#v, want public direct-mode binding", service.Ports)
	}
}

func TestQBTWebUIAlwaysBindsToLoopback(t *testing.T) {
	for _, vpnEnabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "without-vpn", true: "with-vpn"}[vpnEnabled], func(t *testing.T) {
			reg, err := registry.NewDefaultRegistry()
			if err != nil {
				t.Fatal(err)
			}
			cfg := config.DefaultConfig()
			cfg.Domain = "media.example.test"
			cfg.Expose.Mode = config.ExposeModeDirect
			cfg.Expose.TLS.Provider = "acme"
			cfg.Expose.TLS.Email = "ops@example.test"
			cfg.VPNEnabled = vpnEnabled

			graph, err := reg.Resolve(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			if len(graph.Errors) > 0 {
				t.Fatalf("Resolve produced errors: %#v", graph.Errors)
			}
			compose, err := NewComposeGenerator(cfg, reg).Generate(graph)
			if err != nil {
				t.Fatal(err)
			}

			serviceName := "qbittorrent"
			if vpnEnabled {
				serviceName = "gluetun"
			}
			service := compose.Services[serviceName]
			if !contains(service.Ports, "127.0.0.1:8080:8080") {
				t.Fatalf("%s Ports = %#v, want loopback-only qBittorrent UI", serviceName, service.Ports)
			}
			for _, port := range service.Ports {
				if port == "8080:8080" || port == "0.0.0.0:8080:8080" {
					t.Fatalf("%s exposes qBittorrent UI publicly: %#v", serviceName, service.Ports)
				}
			}
		})
	}
}

func TestQBTKillSwitchTopologyAndPeerPort(t *testing.T) {
	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name       string
		vpnEnabled bool
	}{
		{name: "vpn-protected", vpnEnabled: true},
		{name: "explicitly-unprotected", vpnEnabled: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Domain = "media.example.test"
			cfg.Expose.Mode = config.ExposeModeDirect
			cfg.Expose.TLS.Provider = "acme"
			cfg.Expose.TLS.Email = "ops@example.test"
			cfg.VPNEnabled = test.vpnEnabled
			cfg.VPNProvider = "custom"
			cfg.TorrentPort = 51413

			graph, err := reg.Resolve(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			if len(graph.Errors) > 0 {
				t.Fatalf("Resolve produced errors: %#v", graph.Errors)
			}
			compose, err := NewComposeGenerator(cfg, reg).Generate(graph)
			if err != nil {
				t.Fatal(err)
			}

			qbt := compose.Services["qbittorrent"]
			peerPorts := []string{"51413:51413", "51413:51413/udp"}
			if test.vpnEnabled {
				if qbt.NetworkMode != "service:gluetun" {
					t.Fatalf("qBittorrent NetworkMode = %q, want service:gluetun", qbt.NetworkMode)
				}
				if len(qbt.Networks) != 0 || len(qbt.Ports) != 0 {
					t.Fatalf(
						"VPN qBittorrent owns network or host ports: networks=%#v ports=%#v",
						qbt.Networks,
						qbt.Ports,
					)
				}
				if qbt.DependsOn["gluetun"].Condition != "service_healthy" {
					t.Fatalf("qBittorrent DependsOn = %#v, want healthy Gluetun", qbt.DependsOn)
				}
				gluetun := compose.Services["gluetun"]
				if !contains(gluetun.Networks, registry.NetworkDownload) {
					t.Fatalf("Gluetun Networks = %#v, want download", gluetun.Networks)
				}
				for _, port := range append(
					[]string{"127.0.0.1:8080:8080"},
					peerPorts...,
				) {
					if !contains(gluetun.Ports, port) {
						t.Fatalf("Gluetun Ports = %#v, missing %q", gluetun.Ports, port)
					}
				}
				return
			}

			if qbt.NetworkMode != "" {
				t.Fatalf("unprotected qBittorrent NetworkMode = %q, want bridge", qbt.NetworkMode)
			}
			if !contains(qbt.Networks, registry.NetworkDownload) {
				t.Fatalf("qBittorrent Networks = %#v, want download", qbt.Networks)
			}
			if _, exists := qbt.DependsOn["gluetun"]; exists {
				t.Fatalf("unprotected qBittorrent depends on Gluetun: %#v", qbt.DependsOn)
			}
			for _, port := range peerPorts {
				if !contains(qbt.Ports, port) {
					t.Fatalf("qBittorrent Ports = %#v, missing %q", qbt.Ports, port)
				}
			}
			if _, exists := compose.Services["gluetun"]; exists {
				t.Fatal("Gluetun generated while VPN is disabled")
			}
		})
	}
}

func TestComposeGeneratorRejectsCatalogVPNBoundaryBypass(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*registry.ResolutionGraph)
		want   string
	}{
		{
			name: "qbittorrent bridge mode",
			mutate: func(graph *registry.ResolutionGraph) {
				definition := *graph.Services["qbittorrent"].FinalDefinition
				definition.Spec.Networking.ModeTemplate = ""
				definition.Spec.Networking.Mode = "bridge"
				graph.Services["qbittorrent"].FinalDefinition = &definition
			},
			want: "network_mode service:gluetun",
		},
		{
			name: "gluetun leaves download network",
			mutate: func(graph *registry.ResolutionGraph) {
				definition := *graph.Services["gluetun"].FinalDefinition
				definition.Spec.Networking.Networks = []registry.NetworkRef{{
					Name: registry.NetworkApplication,
				}}
				definition.Permissions = append(
					append([]string(nil), definition.Permissions...),
					"network:"+registry.NetworkApplication,
				)
				graph.Services["gluetun"].FinalDefinition = &definition
			},
			want: `gluetun on the "download" network`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reg, err := registry.NewDefaultRegistry()
			if err != nil {
				t.Fatal(err)
			}
			cfg := config.DefaultConfig()
			cfg.VPNEnabled = true
			cfg.VPNProvider = "custom"
			graph, err := reg.Resolve(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(graph)

			_, err = NewComposeGenerator(cfg, reg).Generate(graph)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Generate() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestComposeSegmentsServiceTrustBoundaries(t *testing.T) {
	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Domain = "media.example.test"
	cfg.Expose.Mode = config.ExposeModeCloudflared
	cfg.Addons = []string{
		"filebrowser",
		"sonarr",
		"prowlarr",
	}

	graph, err := reg.Resolve(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Errors) > 0 {
		t.Fatalf("Resolve produced errors: %#v", graph.Errors)
	}
	compose, err := NewComposeGenerator(cfg, reg).Generate(graph)
	if err != nil {
		t.Fatal(err)
	}

	wantNetworks := map[string]string{
		registry.NetworkEdge:        "sdbx_edge",
		registry.NetworkApplication: "sdbx_app",
		registry.NetworkDownload:    "sdbx_download",
		registry.NetworkManagement:  "sdbx_management",
	}
	if len(compose.Networks) != len(wantNetworks) {
		t.Fatalf("Compose networks = %#v", compose.Networks)
	}
	for key, name := range wantNetworks {
		if compose.Networks[key].Name != name {
			t.Errorf("network %s = %#v, want %s", key, compose.Networks[key], name)
		}
	}
	if _, present := compose.Networks["docker-api"]; present {
		t.Fatal("Docker API network survived after file-provider routing")
	}
	assertNetworks(t, compose.Services["cloudflared"], registry.NetworkEdge)
	assertNetworks(
		t,
		compose.Services["traefik"],
		registry.NetworkEdge,
		registry.NetworkApplication,
		registry.NetworkDownload,
		registry.NetworkManagement,
	)
	assertNetworks(t, compose.Services["authelia"], registry.NetworkApplication)
	assertNetworks(t, compose.Services["filebrowser"], registry.NetworkManagement)
	assertNetworks(t, compose.Services["prowlarr"], registry.NetworkApplication)
	assertNetworks(
		t,
		compose.Services["sonarr"],
		registry.NetworkApplication,
		registry.NetworkDownload,
	)
	assertNetworks(t, compose.Services["qbittorrent"], registry.NetworkDownload)

	if _, present := compose.Services["docker-socket-proxy"]; present {
		t.Fatal("Docker socket proxy survived after file-provider routing")
	}
	for _, serviceName := range []string{
		"authelia",
		"cloudflared",
		"traefik",
	} {
		service := compose.Services[serviceName]
		if !service.ReadOnly || !contains(service.CapDrop, "ALL") {
			t.Errorf(
				"%s hardening = readOnly:%t capDrop:%#v",
				serviceName,
				service.ReadOnly,
				service.CapDrop,
			)
		}
	}
	for serviceName, service := range compose.Services {
		if service.PidsLimit <= 0 ||
			service.Logging == nil ||
			service.Logging.Driver != "local" {
			t.Errorf(
				"%s runtime bounds = pids:%d logging:%#v",
				serviceName,
				service.PidsLimit,
				service.Logging,
			)
		}
		for _, volume := range service.Volumes {
			if strings.Contains(volume, "/var/run/docker.sock") {
				t.Errorf("%s mounts the Docker socket directly: %s", serviceName, volume)
			}
		}
	}

	for serviceName, service := range compose.Services {
		for _, label := range service.Labels {
			if strings.HasPrefix(label, "traefik.") {
				t.Errorf("%s retained Docker-provider label %q", serviceName, label)
			}
		}
	}
}

func assertNetworks(t *testing.T, service ComposeService, expected ...string) {
	t.Helper()
	if len(service.Networks) != len(expected) {
		t.Fatalf("Networks = %#v, want %#v", service.Networks, expected)
	}
	for _, network := range expected {
		if !contains(service.Networks, network) {
			t.Fatalf("Networks = %#v, missing %s", service.Networks, network)
		}
	}
}

func TestComposeGeneratorRejectsValueFromEnvironment(t *testing.T) {
	cfg := config.DefaultConfig()
	def := &registry.ServiceDefinition{
		Metadata: registry.ServiceMetadata{Name: "test"},
		Spec: registry.ServiceSpec{
			Image: registry.ImageSpec{Repository: "alpine", Tag: "latest"},
			Container: registry.ContainerSpec{
				NameTemplate: "sdbx-{{ .Name }}",
			},
			Environment: registry.EnvironmentSpec{
				Static: []registry.EnvVar{{
					Name: "LEAK_ME",
					ValueFrom: &registry.ValueSource{
						SecretRef: "credential",
					},
				}},
			},
		},
	}

	_, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err == nil {
		t.Fatal("generateService accepted an inline secret environment value")
	}
	if !strings.Contains(err.Error(), "file-backed secret") {
		t.Fatalf("error = %q, want file-backed secret guidance", err)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
