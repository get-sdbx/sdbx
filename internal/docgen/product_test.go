package docgen

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProductManifestMatchesReleaseContract(t *testing.T) {
	content, err := generateProductManifest()
	if err != nil {
		t.Fatal(err)
	}
	var manifest productManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatalf("product manifest is not valid JSON: %v", err)
	}

	if manifest.SchemaVersion != 1 {
		t.Fatalf("schema version = %d, want 1", manifest.SchemaVersion)
	}
	if manifest.Release.Version != "1.0.0-RC1" ||
		manifest.Release.Tag != "v1.0.0-RC1" ||
		manifest.Release.Level != "release-candidate" {
		t.Fatalf("unexpected release contract: %+v", manifest.Release)
	}

	if len(manifest.Platforms) != 2 ||
		manifest.Platforms[0].OS != "linux" ||
		manifest.Platforms[0].Architecture != "amd64" ||
		manifest.Platforms[0].HostSupport != "supported" ||
		manifest.Platforms[1].OS != "linux" ||
		manifest.Platforms[1].Architecture != "arm64" ||
		manifest.Platforms[1].HostSupport != "compatibility" {
		t.Fatalf("unexpected platform contract: %+v", manifest.Platforms)
	}
	if manifest.Catalog.ServiceCount != 40 ||
		manifest.Catalog.CoreCount != 7 ||
		manifest.Catalog.AddonCount != 33 {
		t.Fatalf("unexpected catalog counts: %+v", manifest.Catalog)
	}
	if manifest.Presets.Count != 4 {
		t.Fatalf("preset count = %d, want 4", manifest.Presets.Count)
	}
	for _, service := range manifest.Catalog.Services {
		switch service.Name {
		case "sonarr", "prowlarr", "radarr", "lidarr", "whisparr":
			if service.RouteAuth != "admin-only" ||
				service.ApplicationAuth != "sdbx-managed-forms" {
				t.Fatalf("layered auth contract for %s = %+v", service.Name, service)
			}
		case "plex", "jellyfin", "audiobookshelf", "navidrome", "notifiarr", "seerr":
			if service.ApplicationAuth != "service-managed" {
				t.Fatalf("native auth contract for %s = %+v", service.Name, service)
			}
		case "profilarr", "wizarr":
			if service.RouteAuth != "admin-only" || service.ApplicationAuth != "none" {
				t.Fatalf("Authelia-owned auth contract for %s = %+v", service.Name, service)
			}
		}
	}
	byName := make(map[string]productService, len(manifest.Catalog.Services))
	for _, service := range manifest.Catalog.Services {
		byName[service.Name] = service
	}
	if byName["homepage"].Name != "" {
		t.Fatal("retired Homepage addon remains in product manifest")
	}
	for _, name := range []string{
		"autobrr",
		"calibre-web",
		"cobalt",
		"decluttarr",
		"janitorr",
		"komga",
		"maintainerr",
		"profilarr",
		"pyload",
		"qbit-manage",
		"qui",
		"unpackerr",
		"whisparr",
	} {
		if byName[name].Name == "" {
			t.Errorf("admitted service %s is missing", name)
		}
	}
	if launcher := byName["sonarr"].Launcher; launcher == nil ||
		launcher.Group != "media" ||
		launcher.Icon != "sonarr" ||
		launcher.Subtitle != "TV shows" {
		t.Fatalf("Sonarr launcher contract = %+v", launcher)
	}
	if byName["unpackerr"].Launcher != nil {
		t.Fatal("internal-only Unpackerr received a launcher")
	}

	commandFound := false
	for _, command := range manifest.CLI.Commands {
		if command.Path == "sdbx vpn status" && command.SupportsJSON {
			commandFound = true
			break
		}
	}
	if !commandFound {
		t.Fatal("product manifest omits JSON-capable sdbx vpn status")
	}

	rendered := string(content)
	for _, retired := range []string{
		"SDBX-Services",
		"forgejo.cloud.",
		"darwin_amd64",
		"darwin_arm64",
		"external taps",
	} {
		if strings.Contains(rendered, retired) {
			t.Errorf("product manifest contains retired or unsupported claim %q", retired)
		}
	}
}
