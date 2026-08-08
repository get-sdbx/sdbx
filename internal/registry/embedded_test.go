package registry

import (
	"context"
	"strings"
	"testing"
)

func TestEmbeddedSourceLoad(t *testing.T) {
	src := NewEmbeddedSource()

	ctx := context.Background()
	services, err := src.ListServices(ctx)
	if err != nil {
		t.Fatalf("failed to list services: %v", err)
	}

	if len(services) == 0 {
		t.Fatal("no services loaded from embedded source")
	}

	// The full canonical catalog must be available offline.
	if len(services) != 40 {
		t.Errorf("expected 40 services in embedded catalog, got %d", len(services))
	}

	t.Logf("Loaded %d services from embedded source", len(services))

	// Verify all expected core services are present.
	expectedCore := []string{
		"traefik",
		"authelia",
		"qbittorrent",
		"plex",
		"gluetun",
		"cloudflared",
		"jellyfin",
	}
	for _, name := range expectedCore {
		def, err := src.LoadService(ctx, name)
		if err != nil {
			t.Errorf("failed to load core service %s: %v", name, err)
			continue
		}
		if def.Conditions.RequireAddon {
			t.Errorf("core service %s should not require addon", name)
		}
	}

	// Verify representative addons are embedded for offline use.
	addonExamples := []string{
		"autobrr",
		"bazarr",
		"calibre-web",
		"cobalt",
		"cross-seed",
		"decluttarr",
		"audiobookshelf",
		"filebrowser",
		"flaresolverr",
		"janitorr",
		"kometa",
		"komga",
		"lidarr",
		"maintainerr",
		"navidrome",
		"notifiarr",
		"nzbhydra2",
		"profilarr",
		"prowlarr",
		"pyload",
		"qbit-manage",
		"qui",
		"radarr",
		"recyclarr",
		"sabnzbd",
		"seerr",
		"sonarr",
		"stash",
		"tautulli",
		"tdarr",
		"unpackerr",
		"whisparr",
		"wizarr",
	}
	for _, name := range addonExamples {
		def, err := src.LoadService(ctx, name)
		if err != nil {
			t.Errorf("failed to load embedded addon %s: %v", name, err)
			continue
		}
		if !def.Conditions.RequireAddon {
			t.Errorf("embedded addon %s should require explicit enablement", name)
		}
	}
}

func TestEmbeddedSourceCategories(t *testing.T) {
	src := NewEmbeddedSource()

	categories, err := src.GetServiceCategories()
	if err != nil {
		t.Fatalf("failed to get categories: %v", err)
	}

	if len(categories) == 0 {
		t.Fatal("no categories found")
	}

	t.Logf("Found %d categories: %v", len(categories), categories)
}

func TestEmbeddedSourceCoreAddons(t *testing.T) {
	src := NewEmbeddedSource()

	core, err := src.GetCoreServices()
	if err != nil {
		t.Fatalf("failed to get core services: %v", err)
	}

	addons, err := src.GetAddonServices()
	if err != nil {
		t.Fatalf("failed to get addon services: %v", err)
	}

	t.Logf("Core services: %d, Addon services: %d", len(core), len(addons))

	// Embedded source contains the canonical core and addon definitions.
	if len(core) != 7 {
		t.Errorf("expected 7 core services in embedded, got %d", len(core))
	}

	if len(addons) != 33 {
		t.Errorf("expected 33 addon services in embedded, got %d", len(addons))
	}
}

func TestServiceDefinitionValidation(t *testing.T) {
	src := NewEmbeddedSource()
	validator := NewValidator()

	ctx := context.Background()
	services, err := src.Load(ctx)
	if err != nil {
		t.Fatalf("failed to load services: %v", err)
	}

	for _, def := range services {
		errors := validator.Validate(def)
		errorCount := 0
		for _, e := range errors {
			if e.Severity == "error" {
				errorCount++
				t.Errorf("validation error in %s: %s - %s", def.Metadata.Name, e.Field, e.Message)
			}
		}
	}
}

func TestEmbeddedRouteAuthOwnershipIsExplicit(t *testing.T) {
	definitions, err := NewEmbeddedSource().Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	counts := map[AuthMode]int{}
	routed := 0
	for _, definition := range definitions {
		if !definition.Routing.Enabled {
			continue
		}
		routed++
		mode := definition.Routing.Auth.Mode
		if mode == "" {
			t.Errorf("routed service %s has no auth ownership", definition.Metadata.Name)
			continue
		}
		counts[mode]++
	}

	if routed != 30 {
		t.Fatalf("routed service count = %d, want 30", routed)
	}
	want := map[AuthMode]int{
		AuthModeAdminOnly: 22,
		AuthModeProtected: 0,
		AuthModeNative:    7,
		AuthModePublic:    1,
	}
	for mode, expected := range want {
		if counts[mode] != expected {
			t.Errorf("%s route count = %d, want %d", mode, counts[mode], expected)
		}
	}
}

func TestEmbeddedApplicationAuthOwnershipIsExplicit(t *testing.T) {
	definitions, err := NewEmbeddedSource().Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	counts := map[ApplicationAuthMode]int{}
	for _, definition := range definitions {
		if definition.ApplicationAuth.Mode == "" {
			t.Errorf(
				"service %s has no application auth ownership",
				definition.Metadata.Name,
			)
			continue
		}
		counts[definition.ApplicationAuth.Mode]++
	}
	wantCounts := map[ApplicationAuthMode]int{
		ApplicationAuthNone:                23,
		ApplicationAuthIdentityProvider:    1,
		ApplicationAuthSDBXManagedForms:    5,
		ApplicationAuthSDBXManagedPassword: 2,
		ApplicationAuthSDBXManagedAPIKey:   1,
		ApplicationAuthServiceManaged:      6,
		ApplicationAuthUpstreamDefault:     2,
	}
	for mode, expected := range wantCounts {
		if counts[mode] != expected {
			t.Errorf(
				"%s application auth count = %d, want %d",
				mode,
				counts[mode],
				expected,
			)
		}
	}

	for service, expected := range map[string]ApplicationAuthMode{
		"qbittorrent": ApplicationAuthSDBXManagedPassword,
		"filebrowser": ApplicationAuthSDBXManagedPassword,
		"lidarr":      ApplicationAuthSDBXManagedForms,
		"cobalt":      ApplicationAuthSDBXManagedAPIKey,
		"calibre-web": ApplicationAuthUpstreamDefault,
	} {
		var definition *ServiceDefinition
		for _, candidate := range definitions {
			if candidate.Metadata.Name == service {
				definition = candidate
				break
			}
		}
		if definition == nil {
			t.Errorf("service %s is missing", service)
			continue
		}
		if definition.ApplicationAuth.Mode != expected {
			t.Errorf(
				"%s application auth = %q, want %q",
				service,
				definition.ApplicationAuth.Mode,
				expected,
			)
		}
	}
}

func TestEmbeddedCatalogDoesNotExposePrivateServiceState(t *testing.T) {
	definitions, err := NewEmbeddedSource().Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	for _, definition := range definitions {
		for _, volume := range definition.Spec.Volumes {
			if strings.Contains(volume.HostPath, ".Config.DataPath") &&
				definition.Metadata.Name != "authelia" &&
				definition.Metadata.Name != "gluetun" {
				t.Errorf(
					"%s mounts the private service-data root: %s",
					definition.Metadata.Name,
					volume.HostPath,
				)
			}
		}
	}

	filebrowser, err := NewEmbeddedSource().LoadService(context.Background(), "filebrowser")
	if err != nil {
		t.Fatal(err)
	}
	mounts := make(map[string]VolumeMount, len(filebrowser.Spec.Volumes))
	for _, volume := range filebrowser.Spec.Volumes {
		mounts[volume.Name] = volume
	}
	if !strings.Contains(mounts["downloads"].HostPath, ".Config.DownloadsPath") ||
		!strings.Contains(mounts["media"].HostPath, ".Config.MediaPath") {
		t.Fatalf("File Browser mount boundary = %#v", filebrowser.Spec.Volumes)
	}
}

func TestProductionCompatibilityCatalogLayouts(t *testing.T) {
	source := NewEmbeddedSource()
	ctx := context.Background()
	routedLaunchers := map[string]bool{
		"autobrr":     true,
		"komga":       true,
		"maintainerr": true,
		"profilarr":   true,
		"qbit-manage": true,
		"qui":         true,
		"decluttarr":  false,
		"janitorr":    false,
	}
	for name, routed := range routedLaunchers {
		definition, err := source.LoadService(ctx, name)
		if err != nil {
			t.Fatalf("load %s: %v", name, err)
		}
		if definition.Routing.Enabled != routed {
			t.Errorf("%s routed = %t, want %t", name, definition.Routing.Enabled, routed)
		}
		launcherEnabled := definition.Presentation.Launcher != nil &&
			definition.Presentation.Launcher.Enabled
		if launcherEnabled != routed {
			t.Errorf("%s launcher = %t, want %t", name, launcherEnabled, routed)
		}
		if routed && definition.Routing.Auth.Mode != AuthModeAdminOnly {
			t.Errorf(
				"%s auth = %q, want %q",
				name,
				definition.Routing.Auth.Mode,
				AuthModeAdminOnly,
			)
		}
	}

	assertMount := func(
		service, mount, hostPath, containerPath string,
	) {
		t.Helper()
		definition, err := source.LoadService(ctx, service)
		if err != nil {
			t.Fatalf("load %s: %v", service, err)
		}
		for _, volume := range definition.Spec.Volumes {
			if volume.Name != mount {
				continue
			}
			if volume.HostPath != hostPath || volume.ContainerPath != containerPath {
				t.Errorf(
					"%s.%s = %s:%s, want %s:%s",
					service,
					mount,
					volume.HostPath,
					volume.ContainerPath,
					hostPath,
					containerPath,
				)
			}
			return
		}
		t.Errorf("%s mount %s is missing", service, mount)
	}
	assertMount(
		"stash",
		"config",
		"{{ .Config.ConfigPath }}/stash",
		"/root/.stash",
	)
	assertMount(
		"stash",
		"media",
		"{{ .Config.MediaPath }}/stash",
		"/data",
	)
	assertMount(
		"whisparr",
		"stash",
		"{{ .Config.MediaPath }}/stash",
		"/adult",
	)
	assertMount(
		"stash",
		"cache",
		"{{ .Config.ConfigPath }}/stash/cache",
		"/cache",
	)
	assertMount(
		"komga",
		"media",
		"{{ .Config.MediaPath }}",
		"/data/media",
	)
	for _, mount := range []string{"movies", "tv", "music", "concerts"} {
		assertMount(
			"janitorr",
			mount,
			"{{ .Config.MediaPath }}/"+mount,
			"/data/media/"+mount,
		)
	}
	maintainerr, err := source.LoadService(ctx, "maintainerr")
	if err != nil {
		t.Fatal(err)
	}
	networks := map[string]bool{}
	for _, network := range maintainerr.Spec.Networking.Networks {
		networks[network.Name] = true
	}
	if !networks["app"] || !networks["download"] {
		t.Fatalf(
			"Maintainerr networks = %#v, want app and download",
			maintainerr.Spec.Networking.Networks,
		)
	}
	assertMount(
		"qbit-manage",
		"downloads",
		"{{ .Config.DownloadsPath }}",
		"/data/downloads",
	)
	assertMount(
		"filebrowser",
		"media",
		"{{ .Config.MediaPath }}",
		"/srv/media",
	)
	assertMount(
		"filebrowser",
		"downloads",
		"{{ .Config.DownloadsPath }}",
		"/srv/downloads",
	)
}

func TestTraefikServiceDefinition(t *testing.T) {
	src := NewEmbeddedSource()
	ctx := context.Background()

	def, err := src.LoadService(ctx, "traefik")
	if err != nil {
		t.Fatalf("failed to load traefik: %v", err)
	}

	// Verify metadata
	if def.Metadata.Name != "traefik" {
		t.Errorf("expected name traefik, got %s", def.Metadata.Name)
	}
	if def.Metadata.Category != CategoryNetworking {
		t.Errorf("expected category networking, got %s", def.Metadata.Category)
	}

	// Verify traefik is core (not addon)
	if def.Conditions.RequireAddon {
		t.Error("expected traefik to be core (always enabled)")
	}
	if !def.Conditions.Always {
		t.Error("expected traefik to have always condition set")
	}

	// Verify routing (traefik itself doesn't need routing - it IS the reverse proxy)
	if def.Routing.Enabled {
		t.Error("expected traefik routing to be disabled (it's the reverse proxy)")
	}

}
