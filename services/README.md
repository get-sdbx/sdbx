# SDBX Service Catalog

This directory is the canonical official catalog. `services/embed.go` embeds
every `core/*/service.yaml` and `addons/*/service.yaml` definition into both
native binaries; a separate services repository is not required at install or
runtime.

The Go types and semantic validator are authoritative:

- `internal/registry/types.go` defines the accepted fields;
- `internal/registry/loader.go` rejects unknown YAML fields, multiple
  documents, symlinks, non-regular files, and definitions larger than 1 MiB;
- `internal/registry/validator.go` enforces routing, network, registry,
  template, permission, and Docker-boundary policy;
- `services/schemas/service-v1.json` supports editor validation but does not
  replace the Go validator.

## Layout

```text
services/
├── core/
│   └── NAME/service.yaml
├── addons/
│   └── NAME/service.yaml
├── schemas/
│   └── service-v1.json
└── embed.go
```

Core definitions represent infrastructure or explicitly selected platform
components. Their `conditions` use `always` or a supported configuration
predicate. Addons use `conditions.requireAddon: true` and are enabled by name,
directly or through an embedded preset.

Do not maintain a catalog count or service list in prose. The executable view
is:

```bash
sdbx addon list --all
sdbx preset list
```

## Minimal addon

This example shows the smallest useful routed addon:

```yaml
apiVersion: sdbx.one/v1
kind: Service
applicationAuth:
  mode: none
metadata:
  name: whoami
  version: 1.0.0
  category: utility
  description: "Synthetic request-inspection service"
  homepage: https://github.com/traefik/whoami
  documentation: https://github.com/traefik/whoami#readme
  maintainer: example-maintainer
  tags:
    - diagnostics
permissions:
  - network:app
  - route:admin-only
spec:
  image:
    repository: traefik/whoami
    tag: v1.11.0
    registry: docker.io
  container:
    name_template: "sdbx-{{ .Name }}"
    restart: unless-stopped
    readOnlyRootFilesystem: true
    pidsLimit: 64
    capabilities:
      drop:
        - ALL
  networking:
    networks:
      - name: app
routing:
  enabled: true
  port: 80
  subdomain: whoami
  path: /whoami
  pathRouting:
    strategy: stripPrefix
  auth:
    mode: admin-only
  traefik:
    network: app
conditions:
  requireAddon: true
```

The example declares its `app` trust-zone membership explicitly. It has no
host mount, published host port, secret, device, added capability, privileged
mode, or host networking. Real definitions should copy the closest current
service and delete every field that is not required.

## Required identity and image fields

Every definition has:

- `apiVersion: sdbx.one/v1`;
- `kind: Service`;
- one explicit `applicationAuth.mode` identifying who owns any native
  application credential;
- a lowercase service name matching its directory;
- a definition version;
- one of `media`, `downloads`, `management`, `utility`, `networking`, or
  `auth`;
- an image repository, tag, and matching registry;
- a templated container name;
- at least one explicit trust-boundary network unless host networking is
  deliberately declared and granted.

Image tags are authoring and update-discovery inputs, not runtime mutability.
The binary also embeds a reviewed OCI snapshot for every official service.
First-run and newly enabled official services use those exact platform
digests; external-source images use their explicit resolver. Only the
preview/apply `sdbx update` workflow deliberately refreshes authoring
tags.
Plain `sdbx lock` preserves existing project pins. Generated Compose always
uses the resulting exact platform digest.

## Trust-zone networks

Use the narrowest required network:

| Network | Purpose |
| --- | --- |
| `edge` | Traefik and Cloudflared ingress only |
| `app` | media and automation applications |
| `download` | download clients and services that must reach them |
| `management` | administrative applications |

A routed service declares its Traefik network both in
`spec.networking.networks` and `routing.traefik.network`. Normal services may
not join `edge`. Traefik uses generated file-provider routes and joins the
route-bearing networks directly; it does not inspect Docker metadata.

qBittorrent's VPN path is a special case: the generator assigns
`network_mode: service:gluetun` from project policy. Do not recreate that
boundary in an addon.

## Route authentication ownership

Every enabled route declares exactly one mode:

| Mode | Owner |
| --- | --- |
| `admin-only` | Authelia ForwardAuth plus the `admins` group |
| `protected` | Authelia ForwardAuth for any authenticated user |
| `native-auth` | The application; Authelia is not inserted |
| `public` | Deliberately unauthenticated |

Choose from the application's real authentication behavior. `public` requires
an explicit security justification. An `admin-only` or `protected` route may
also enforce application authentication as defense in depth; Sonarr, Radarr,
Lidarr, Prowlarr, and Whisparr use SDBX-managed Forms credentials for this
purpose. That does not
change the route owner. Do not put Authelia in front of a `native-auth`
application merely to conceal weak application credentials; fix the
application credential flow.

`applicationAuth.mode` is independent from route authentication. It must be
one of `none`, `identity-provider`, `sdbx-managed-forms`,
`sdbx-managed-password`, `sdbx-managed-api-key`, `service-managed`, or
`upstream-default`. Generated product metadata uses this field directly; it
does not infer credential ownership from tags or route mode.

Path routing uses:

- `stripPrefix` when Traefik removes the route prefix;
- `urlBase` when the application owns its base path;
- `none` when a separate environment variable or command configures the base
  path.

Use `forceSubdomain` only when the application cannot work correctly behind a
path.

## Host access and permissions

The top-level `permissions` list must exactly match the sensitive behavior
derived from the definition. Missing, unknown, duplicate, and unused
permissions are errors.

Permission classes include:

- managed roots: `config-path`, `data-path`, `downloads-path`, `media-path`,
  `project-path`, and `secrets-path`;
- host effects: `host-mount`, `host-chown`, `host-network`, `device`,
  `host-port`, and `privileged`;
- trust zones and shared namespaces: `network:NAME` and
  `service-network:NAME`;
- browser exposure and authentication ownership:
  `route:admin-only`, `route:protected`, `route:native-auth`, or
  `route:public`;
- embedded identity replacement: `service-override:NAME`;
- Linux capabilities: `capability:NAME`;
- declared secrets: `secret:NAME`.

Environment-file paths use the same managed-root authorization as bind mounts.
Published ports require `host-port`; Cloudflare Tunnel mode additionally
rejects explicit non-loopback host bindings. Permission declaration is not
approval. An external source must also receive the exact grant from the
operator. A route grant is especially sensitive: browsers send cookies scoped
to the shared SDBX domain to the routed application, including the Authelia
session cookie where applicable. Grant routes only to images and definitions
trusted to receive that traffic. Docker-socket mounts are unsupported and
rejected even when a source is otherwise trusted.

Prefer:

- read-only root filesystems and explicit `tmpfs` mounts;
- `capabilities.drop: [ALL]`;
- bounded PID counts and health checks;
- read-only configuration mounts;
- application-supported file-backed secrets.

Do not use inline secret environment values. Catalog templates cannot read
secret values.

## Template surface

Templates receive a read-only non-secret configuration view. Common fields
include:

```text
.Name
.Config.Domain
.Config.Timezone
.Config.ConfigPath
.Config.DataPath
.Config.DownloadsPath
.Config.MediaPath
.Config.ProjectDir
.Config.PUID
.Config.PGID
.Config.Umask
.Config.VPNEnabled
.Config.VPNProvider
.Config.VPNCountry
.Config.TorrentPort
.Config.Expose
.Config.Routing
```

Templates are supported only where the generator renders them:

- `spec.container.name_template`, `command`, and `working_dir`;
- static and conditional environment values plus conditional `when`;
- `spec.environment.envFile`;
- volume host paths, container paths, and `when`;
- static port values plus conditional port values and `when`;
- `spec.networking.modeTemplate` and network-membership `when`; and
- conditional dependency `when`.

Every other field is literal. Templates in metadata, image identity, variable
names, labels, sysctls, tmpfs mounts, devices, health checks, routing identity,
secret metadata, integration metadata, dependency names, or readiness policy
are rejected instead of being emitted unrendered.

Unknown configuration fields and `.Secrets` access are rejected. Keep
conditional expressions within the explicit v1 set:

```text
{{ .Config.VPNEnabled }}
{{ not .Config.VPNEnabled }}
{{ eq .Config.Expose.Mode "lan" }}
{{ ne .Config.Expose.Mode "lan" }}
{{ eq .Config.Expose.Mode "direct" }}
{{ ne .Config.Expose.Mode "direct" }}
{{ eq .Config.Expose.Mode "cloudflared" }}
{{ ne .Config.Expose.Mode "cloudflared" }}
{{ or (eq .Config.Expose.Mode "lan") (eq .Config.Expose.Mode "direct") }}
{{ eq .Config.Routing.Strategy "path" }}
{{ eq .Config.Routing.Strategy "subdomain" }}
```

Dependency `when` expressions cannot depend on per-service routing because the
dependency graph is resolved before rendering. They use only the VPN and
exposure expressions above. Dependency readiness is omitted for
`service_started` or set to `service_started`, `service_healthy`, or
`service_completed_successfully`.

Every definition declares exactly one activation selector: `always`,
`requireAddon`, or one of `vpn_enabled`, `cloudflared`, `plex_enabled`, and
`jellyfin_enabled` through `requireConfig`. Unknown expressions, selectors,
dependency names, duplicate/self dependencies, and the retired
`requireFeature` or `dependencies.optional` fields fail closed. All
user-controlled values still pass configuration validation before rendering.
Malformed templates, unknown template roots or configuration fields, template
execution errors, and conditions that do not render exactly `true` or `false`
stop generation; SDBX never emits the unrendered catalog input as a fallback.

## Secrets

Declare a generated or operator-supplied secret at the top level:

```yaml
permissions:
  - secret:example_api_key
secrets:
  - name: example_api_key
    type: manual
    description: "API key obtained from the service owner"
```

Then mount it through the service's supported file-backed mechanism. If the
upstream application has no file-backed secret support, the integration layer
may write a restricted application-owned config; do not fall back to a
plaintext Compose environment variable.

## Validate an official change

Add or update the definition, then run:

```bash
go test ./internal/registry/... ./internal/generator/...
make build
./bin/sdbx addon list --all
git diff --check
```

Also generate and validate every affected exposure/routing profile with
`docker compose config --quiet`. Add tests for new permissions, routes,
conditions, networks, integrations, path behavior, and expected inventory.

The pull request must explain:

- why the image and registry are trustworthy;
- update and rollback behavior;
- every host, device, capability, path, network, and secret requirement;
- authentication ownership;
- data persistence and backup implications;
- upstream maintenance status and licensing.

## External catalogs

External Git catalogs are opt-in extensions, not part of the official catalog.
They may place definitions at the repository root or under `core/` and
`addons/`. SDBX accepts only HTTPS or SSH sources pinned to an exact 40- or
64-character commit whose OpenPGP or SSH signature matches the configured
fingerprint.

The configured fingerprint does not install trust material. OpenPGP operators
must import the reviewed public key into the `GNUPGHOME` used for the refresh.
SSH-signature operators must configure a protected
`gpg.ssh.allowedSignersFile` in the `GIT_CONFIG_GLOBAL` used for the refresh.
Keep those files separate from personal mutable keyrings and Git
configuration. See [External source trust](../docs/external-sources.md#configure-signature-verification)
for the exact fail-closed setup and verification commands.

Example:

```bash
sdbx source add community https://code.example.test/community/services.git \
  --ref FULL_SIGNED_COMMIT \
  --signing-key FULL_SIGNER_FINGERPRINT \
  --allow-registry ghcr.io \
  --allow-permission config-path

sdbx source update community
sdbx source info community
```

Grant only the registries and permissions the reviewed commit requires.
Higher-priority complete service definitions can replace an embedded name only when the
definition declares `service-override:NAME` and the source receives the exact
matching grant. The declaration and grant make that supply-chain decision
visible in the lock. Local sources are development-only and release locks
reject them unless the operator explicitly opts into the non-reproducible
override.

## License

Catalog definitions are distributed under the repository's MIT license. Image
and application licenses remain those of their respective upstream projects.
The root license preserves the historical SDBX catalog attribution; this
directory intentionally has no competing license file.
