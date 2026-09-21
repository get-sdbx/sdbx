# Changelog

This repository begins with the first public SDBX release candidate. Private
development builds and internal dogfood revisions are intentionally absent
from the public history.

## [1.0.0-RC2]

### Added

- Opt-in Plex DRM render-device access and a private native listener through
  `plex.hardware_device`, `plex.lan_address`, and `plex.lan_port`, with CLI and
  Dashboard controls, lock verification, and an optional digest-pinned AMD
  VA-API compatibility package (`plex.amd_vaapi`, Linux amd64 only).
- Configure Cloudflare Tunnel transport with `expose.tunnel_protocol` in the
  CLI and Dashboard: `http2`, `quic`, or `auto`.
- Update selected services with `sdbx update --service NAME` while preserving
  all other verified image pins.

### Security

- Build with Go 1.26.8 to include the standard-library security fixes missing
  from Go 1.26.5.
- Update age to 1.3.2, go-oidc to 3.21.0, and the Go cryptography, system,
  terminal, and text modules to their reviewed maintenance releases.

### Fixed

- Require Docker Compose 5.0 or newer. Staged initialization validates with
  `docker compose config --no-env-resolution` so a project whose `config_path`
  is absolute is checked before its env files are promoted. Older releases
  either reject that flag (2.34.0 and earlier) or still open the not-yet-staged
  absolute env file (2.35.0 through 2.40.3), so `sdbx init` preflight,
  `sdbx doctor`, the README and the documentation now report the real minimum
  instead of claiming 2.20 support and failing at generation time.
- Default generated Cloudflare Tunnel connectors to HTTP/2 over TCP so degraded
  QUIC/UDP paths do not leave otherwise responsive HTTP services transferring
  pages slowly. Existing projects adopt the default when regenerated.
- Escape terminal controls in human-readable lock differences and registry
  warnings while preserving structured JSON diagnostics.
- Reject empty service selections and require services sharing an image to be
  selected together, so scoped updates cannot change unselected services.

- Include dependency patent grants in generated third-party notices and accept
  the Go patent grant's explicit license identifier in dependency review.

## [1.0.0-RC1]

### Added

- Native `sdbx` CLI and root-owned, project-scoped `sdbxd` management broker.
- Embedded official catalog with 7 core services and 33 optional addons.
- Lock schema v2 with catalog, definition, dependency, platform, OCI image,
  configuration, and generated-file provenance.
- Transactional initialization, runtime generation, updates, and restore.
- Guided setup with explicit media-server, addon-preset, routing, exposure,
  storage, VPN, and authentication choices.
- Digest-pinned Docker Compose generation with separate edge, application,
  download, and management networks.
- Authelia-owned route policy plus explicit native application credential
  ownership in every service definition.
- VPN-enforced qBittorrent networking through Gluetun, including bounded
  fail-closed posture diagnostics.
- Idempotent integrations for supported Arr, download, request, library,
  subtitle, monitoring, invitation, profile, and worker services.
- Authenticated age-encrypted backup and constrained transactional restore.
- Remote SDBX Dashboard protected by Authelia administrators, private Traefik
  mTLS, browser authentication, and the typed broker boundary.
- Separate loopback-only Dashboard recovery listener for SSH forwarding.
- Immutable image update previews with dependency-ordered health verification
  and restoration of the previous locked runtime on failure.
- Signed Linux amd64 and arm64 archives, SHA-256 checksums, SPDX SBOMs,
  keyless Sigstore verification, and GitHub build provenance.

### Security

- No generated container receives the Docker socket.
- Catalog definitions must declare exact permissions, network placement, route
  authentication, native application credential ownership, health policy, and
  immutable image evidence.
- Secret-bearing files require private regular files and bounded reads.
- CLI, broker, integration, Dashboard, and audit errors are redacted before
  reaching untrusted callers.
- Backups reject traversal, external or broken symlinks, devices, FIFOs, and
  unexpected special files. Safe in-root links and Unix sockets are recorded
  as encrypted omissions and are never recreated.
- External catalog sources require an immutable signed commit, exact signing
  identity, registry allowlist, and explicit permission grants.
- Browser operations cannot request arbitrary commands, paths, mounts, Docker
  APIs, or container execution.

### Operational boundaries

- Linux amd64 is the supported RC1 host target. Linux arm64 is published as a
  compatibility build; macOS remains development-only.
- Torrent traffic uses the host network only after explicit acknowledgement
  that VPN protection is disabled.
- Cloudflare Tunnel is remote-managed: SDBX outputs and probes the required
  route plan but never mutates Cloudflare account state.
- SDBX backups exclude media, downloads, external Docker volumes, and
  `data_path`, including Authelia's database and TOTP enrollments.
- Destructive automation workers retain conservative defaults and require
  explicit operator review before data-deleting behavior is enabled.

### Removed from the public product

- Mutable unattended updates and Watchtower.
- Homepage and the separate in-cluster controller UI.
- Raw Docker socket mounts and generic privileged helper execution.
- qBittorrent private-network authentication bypasses.
- Plaintext backup archives.
- Runtime dependency on a separate service-catalog repository.
