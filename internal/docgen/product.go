package docgen

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	sdbxcmd "github.com/get-sdbx/sdbx/cmd/sdbx/cmd"
	"github.com/get-sdbx/sdbx/internal/registry"
	"github.com/get-sdbx/sdbx/internal/registry/presets"
)

const (
	productManifestSchemaVersion = 1
	releaseVersion               = "1.0.0-RC1"
	releaseTag                   = "v1.0.0-RC1"
)

type productManifest struct {
	SchemaVersion int                 `json:"schemaVersion"`
	GeneratedBy   string              `json:"generatedBy"`
	Product       productIdentity     `json:"product"`
	Release       productRelease      `json:"release"`
	Platforms     []productPlatform   `json:"platforms"`
	Artifacts     productArtifacts    `json:"artifacts"`
	CLI           productCLI          `json:"cli"`
	Catalog       productCatalog      `json:"catalog"`
	Presets       productPresets      `json:"presets"`
	Capabilities  []productCapability `json:"capabilities"`
	Boundaries    []productBoundary   `json:"securityBoundaries"`
}

type productIdentity struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	License       string `json:"license"`
	RepositoryURL string `json:"repositoryUrl"`
	WebsiteURL    string `json:"websiteUrl"`
}

type productRelease struct {
	Version string `json:"version"`
	Tag     string `json:"tag"`
	Level   string `json:"level"`
}

type productPlatform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	HostSupport  string `json:"hostSupport"`
}

type productArtifacts struct {
	ArchiveNameTemplate string   `json:"archiveNameTemplate"`
	Archives            []string `json:"archives"`
	Checksums           string   `json:"checksums"`
	ChecksumSignature   string   `json:"checksumSignature"`
	SBOMSuffix          string   `json:"sbomSuffix"`
	Provenance          string   `json:"provenance"`
}

type productCLI struct {
	CommandCount     int              `json:"commandCount"`
	RunnableCount    int              `json:"runnableCount"`
	JSONCommandCount int              `json:"jsonCommandCount"`
	Commands         []productCommand `json:"commands"`
}

type productCommand struct {
	Path         string `json:"path"`
	Summary      string `json:"summary"`
	Runnable     bool   `json:"runnable"`
	SupportsJSON bool   `json:"supportsJson"`
}

type productCatalog struct {
	ServiceCount int              `json:"serviceCount"`
	CoreCount    int              `json:"coreCount"`
	AddonCount   int              `json:"addonCount"`
	Services     []productService `json:"services"`
}

type productService struct {
	Name            string                  `json:"name"`
	Category        string                  `json:"category"`
	Description     string                  `json:"description"`
	Kind            string                  `json:"kind"`
	AlwaysEnabled   bool                    `json:"alwaysEnabled"`
	RouteAuth       string                  `json:"routeAuth"`
	ApplicationAuth string                  `json:"applicationAuth"`
	Launcher        *productServiceLauncher `json:"launcher,omitempty"`
}

type productServiceLauncher struct {
	Group    string `json:"group"`
	Icon     string `json:"icon,omitempty"`
	Subtitle string `json:"subtitle,omitempty"`
}

type productPresets struct {
	Count int             `json:"count"`
	Items []productPreset `json:"items"`
}

type productPreset struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Addons      []string `json:"addons"`
}

type productCapability struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
}

type productBoundary struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

func generateProductManifest() ([]byte, error) {
	cliReference := sdbxcmd.DocumentationCLIReference()
	if len(cliReference.Commands) == 0 {
		return nil, fmt.Errorf("Cobra command metadata is empty")
	}
	manifestCLI := productCLI{
		CommandCount: len(cliReference.Commands),
		Commands:     make([]productCommand, 0, len(cliReference.Commands)),
	}
	for _, command := range cliReference.Commands {
		manifestCLI.Commands = append(manifestCLI.Commands, productCommand{
			Path:         command.Path,
			Summary:      command.Short,
			Runnable:     command.Runnable,
			SupportsJSON: command.SupportsJSON,
		})
		if command.Runnable {
			manifestCLI.RunnableCount++
		}
		if command.SupportsJSON {
			manifestCLI.JSONCommandCount++
		}
	}

	embedded := registry.NewEmbeddedSource()
	definitions, err := embedded.Load(context.Background())
	if err != nil {
		return nil, fmt.Errorf("load embedded service catalog: %w", err)
	}
	manifestCatalog := productCatalog{
		ServiceCount: len(definitions),
		Services:     make([]productService, 0, len(definitions)),
	}
	for _, definition := range definitions {
		kind := "core"
		if definition.Conditions.RequireAddon {
			kind = "addon"
			manifestCatalog.AddonCount++
		} else {
			manifestCatalog.CoreCount++
		}
		routeAuth := "not-routed"
		if definition.Routing.Enabled {
			routeAuth = string(definition.Routing.Auth.Mode)
		}
		service := productService{
			Name:            definition.Metadata.Name,
			Category:        string(definition.Metadata.Category),
			Description:     definition.Metadata.Description,
			Kind:            kind,
			AlwaysEnabled:   definition.Conditions.Always,
			RouteAuth:       routeAuth,
			ApplicationAuth: serviceApplicationAuth(definition),
		}
		if launcher := definition.Presentation.Launcher; launcher != nil &&
			launcher.Enabled {
			service.Launcher = &productServiceLauncher{
				Group:    launcher.Group,
				Icon:     launcher.Icon,
				Subtitle: launcher.Subtitle,
			}
		}
		manifestCatalog.Services = append(manifestCatalog.Services, service)
	}
	sort.Slice(manifestCatalog.Services, func(i, j int) bool {
		return manifestCatalog.Services[i].Name < manifestCatalog.Services[j].Name
	})

	builtinPresets, err := presets.LoadBuiltin()
	if err != nil {
		return nil, fmt.Errorf("load built-in presets: %w", err)
	}
	manifestPresets := productPresets{
		Count: len(builtinPresets.Presets),
		Items: make([]productPreset, 0, len(builtinPresets.Presets)),
	}
	for _, preset := range builtinPresets.Presets {
		addons := append([]string(nil), preset.Addons...)
		sort.Strings(addons)
		manifestPresets.Items = append(manifestPresets.Items, productPreset{
			Name:        preset.Name,
			Title:       preset.Title,
			Description: strings.Join(strings.Fields(preset.Description), " "),
			Addons:      addons,
		})
	}
	sort.Slice(manifestPresets.Items, func(i, j int) bool {
		return manifestPresets.Items[i].Name < manifestPresets.Items[j].Name
	})

	manifest := productManifest{
		SchemaVersion: productManifestSchemaVersion,
		GeneratedBy:   "go run ./cmd/sdbx-docgen --write",
		Product: productIdentity{
			Name: "SDBX",
			Description: "Build and operate a self-hosted seedbox " +
				"from one reproducible project.",
			License:       "MIT",
			RepositoryURL: "https://github.com/get-sdbx/sdbx",
			WebsiteURL:    "https://sdbx.one",
		},
		Release: productRelease{
			Version: releaseVersion,
			Tag:     releaseTag,
			Level:   "release-candidate",
		},
		Platforms: []productPlatform{
			{OS: "linux", Architecture: "amd64", HostSupport: "supported"},
			{OS: "linux", Architecture: "arm64", HostSupport: "compatibility"},
		},
		Artifacts: productArtifacts{
			ArchiveNameTemplate: "sdbx_{version}_linux_{architecture}.tar.gz",
			Archives: []string{
				"sdbx_1.0.0-RC1_linux_amd64.tar.gz",
				"sdbx_1.0.0-RC1_linux_arm64.tar.gz",
			},
			Checksums:         "checksums.txt",
			ChecksumSignature: "checksums.txt.sigstore.json",
			SBOMSuffix:        ".spdx.json",
			Provenance:        "github-artifact-attestation",
		},
		CLI:     manifestCLI,
		Catalog: manifestCatalog,
		Presets: manifestPresets,
		Capabilities: []productCapability{
			{
				ID:      "guided-setup",
				Title:   "Guided, previewable setup",
				Summary: "LAN-safe defaults, named presets, preflight checks, and a dry-run graph preview.",
			},
			{
				ID:      "embedded-catalog",
				Title:   "Complete embedded catalog",
				Summary: "Official service definitions and presets ship in the binary; external sources are optional.",
			},
			{
				ID:      "digest-lock",
				Title:   "Digest-locked runtime",
				Summary: "Official first-run locks use release-reviewed embedded OCI pins; explicit updates create new platform-specific locks.",
			},
			{
				ID:      "encrypted-recovery",
				Title:   "Encrypted recovery",
				Summary: "Backups use authenticated age encryption and restore through bounded transactional validation.",
			},
			{
				ID:      "vpn-enforcement",
				Title:   "VPN-enforced downloads",
				Summary: "qBittorrent shares Gluetun's network namespace and exposes no independent Web UI port.",
			},
			{
				ID:      "remote-console",
				Title:   "Authenticated management console",
				Summary: "The full Dashboard is remote-accessible through Authelia admins and a private Traefik mTLS transport, while the Web process stays unprivileged behind a typed project broker.",
			},
		},
		Boundaries: []productBoundary{
			{
				ID:      "linux-host-only",
				Summary: "v1 first-class host support is Linux amd64; Linux arm64 is a compatibility build, and macOS is development-only.",
			},
			{
				ID:      "docker-root-equivalent",
				Summary: "Docker access and the root broker are host-privileged trust boundaries.",
			},
			{
				ID:      "authenticated-console",
				Summary: "The management console is public only through the generated Authelia admins route and private Traefik mTLS backend transport; direct proxy-port access fails closed.",
			},
			{
				ID:      "optional-vpn",
				Summary: "VPN enforcement applies only when enabled; unprotected download traffic requires explicit confirmation.",
			},
			{
				ID:      "remote-managed-tunnel",
				Summary: "A Cloudflare connector token cannot manage Published application routes; SDBX lists and probes the required remote mappings.",
			},
			{
				ID:      "no-controller-image",
				Summary: "v1 publishes native binaries only; there is no supported SDBX controller container image.",
			},
		},
	}

	output, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal product manifest: %w", err)
	}
	return append(output, '\n'), nil
}

func serviceApplicationAuth(
	definition *registry.ServiceDefinition,
) string {
	if definition == nil {
		return "none"
	}
	return string(definition.ApplicationAuth.Mode)
}
