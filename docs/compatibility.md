# Compatibility

This matrix defines the upcoming `v1.0.0-RC2` product contract; RC2 acceptance
is still in progress. Linux amd64 is the
supported clean-host runtime target; arm64 remains a build and installer
compatibility target.

## Host platform

| Host | Architecture | RC2 status | Notes |
| --- | --- | --- | --- |
| Linux | amd64 | Supported, first class | Full native `sdbx`/`sdbxd`, Docker Engine, destructive recovery, and runtime acceptance matrix |
| Linux | arm64 | Compatibility build | Native archives, installer checks, static validation, and immutable upstream image coverage; no full v1 host-runtime guarantee |
| macOS | amd64, arm64 | Development only | Not a supported media-stack or root-daemon host |
| Windows | any | Unsupported | No v1 host contract |

SDBX is distribution-neutral at the CLI layer. The packaged optional daemon
units require systemd. Alternative service managers may be used only when they
preserve the same root broker, unprivileged Web account, group-restricted
socket/token, remote mTLS listener, loopback recovery listener, restart, and
audit boundaries.

## Required host components

| Component | Enforced minimum | Purpose |
| --- | --- | --- |
| Docker Engine | 24.0 | Container runtime and Compose backend |
| Docker Compose plugin | 5.0 | Locked project convergence and structured status |
| Docker Buildx | 0.10 | Initialization preflight and platform tooling |
| Go | 1.26.8 | Source builds only |

Initialization refuses older or unrecognized Docker, Compose, and Buildx
versions. `sdbx doctor` verifies Docker 24 and Compose 5.0 during day-two
operation.

Docker-compatible replacements are not part of the v1 contract. Rootless
Docker, Podman Compose, Kubernetes, NAS application stores, and Docker Desktop
host deployment require separate validation.

## Exposure and routing

| Exposure | Subdomain routing | Path routing | Host ingress | TLS owner |
| --- | --- | --- | --- | --- |
| `lan` | Supported | Supported where the selected service definition declares a path strategy | 80/443 | Traefik local/default certificate |
| `direct` | Supported | Supported where the selected service definition declares a path strategy | 80/443 | Traefik ACME |
| `cloudflared` | Supported | Supported where the selected service definition declares a path strategy | No Traefik host ingress | Cloudflare public edge |

`forceSubdomain` definitions remain on a subdomain even when the project
default is path routing. A catalog definition must describe how an application
receives its URL base; SDBX does not claim universal path support for arbitrary
external services.

Direct mode requires public DNS, reachable ACME challenge ports, and a contact
email. Cloudflare mode supports remotely managed tunnels: it requires a
connector token plus one Cloudflare Published application mapping per hostname
shown by `sdbx tunnel routes`. Every mapping targets
`http://traefik:8081`. The token cannot manage those routes, and locally managed
credentials-JSON tunnels are outside the v1 contract. Cloudflare remains a
third-party trust, route-control, and availability dependency. LAN mode
encrypts traffic but does not automatically establish client trust in the local
certificate.

## Catalog and images

The official definitions, presets, and reviewed image-digest snapshot are
available offline from the binary. Project initialization and official addon
selection use the embedded platform pins; they need registry access to pull the
selected image layers, not to discover a mutable digest. Explicit
`sdbx update` operations query authoring tags for newer upstream manifests,
preview exact digest changes, and require an explicit apply acknowledgement.
External-source images use the source's explicit registry resolver because
they are outside the official snapshot.

An addon can be valid in the catalog but unavailable on one CPU architecture
when its upstream image lacks that platform. Digest resolution must fail
instead of silently selecting another architecture or mutable tag.

External Git catalogs require Git plus the configured OpenPGP or SSH signing
verification setup. Local catalogs are development inputs, not signed release
inputs.

## Filesystem expectations

SDBX expects Linux ownership and permission semantics, regular files,
directories, atomic rename within each managed filesystem, and reliable
`fsync`. Managed roots may not be filesystem roots or symlinks.

Network filesystems, unusual FUSE implementations, case-insensitive
filesystems, and storage that does not honor Unix modes or atomic replacement
are not validated v1 targets. Media may live on separately managed storage,
but project, configuration, secret, backup, and application consistency remain
the operator's responsibility.

## Browser console

The Web console is a remote-first operator tool with a local recovery path:

- public access: canonical SDBX root behind Authelia `admins`;
- proxy-to-console transport: private CA, mutual TLS, TLS 1.3;
- local recovery: fragment-token flow through the packaged loopback-only
  listener on port `18778`, normally reached through SSH forwarding;
- browser support: current standards-based desktop and mobile browsers;
- arbitrary reverse-proxy exposure: unsupported; the generated Traefik and
  Authelia boundary is required;
- browser authorization owner: Authelia groups, with full management available
  only to `admins`.

Keyboard navigation, visible focus, screen-reader names and announcements,
mobile layout, contrast, and reduced-motion behavior are release gates.

## Release acceptance matrix

RC2 qualification requires the following evidence before publication:

- Linux amd64 archive installation plus the complete clean-host runtime matrix;
- Linux arm64 archive build, installer contract, binary metadata, and selected
  image-manifest compatibility;
- both binaries reporting the same version;
- all six exposure/routing generation profiles;
- representative minimal, media-server, preset, VPN, and explicitly
  unprotected graphs;
- `docker compose config` for every generated profile;
- route-auth and TLS behavior;
- remote Cloudflare route-plan reconciliation and public-route probes;
- VPN host/tunnel egress proof;
- encrypted backup and separate-host restore;
- image-update success, induced failure, and rollback;
- systemd root/unprivileged boundary on Linux amd64;
- desktop/mobile accessibility and failure states.

Raw QA, deployment, and recovery evidence is retained privately and is not part
of the public product documentation.
