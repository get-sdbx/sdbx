# SDBX

SDBX installs and operates a reproducible, security-focused media automation
stack from one typed project configuration.

It generates Docker Compose runtime files, resolves every active image to an
immutable OCI digest, derives routing and authentication policy from the
official catalog, enforces VPN isolation for torrent traffic, and records the
complete deployment in `.sdbx.lock`.

> [!IMPORTANT]
> SDBX is intended for media and sources you are legally permitted to access.
> You remain responsible for the services, indexers, and content configured on
> your server.

## Release status

`v1.0.0-RC1` is the first public SDBX release candidate. It is published for
real-world validation before the stable v1 release. Use it on a reviewed host,
keep independent backups of application state and media, and report defects
through the public repository.

The supported release-candidate host is Linux amd64. Linux arm64 artifacts are
published as a compatibility target, without the complete clean-host runtime
acceptance guarantee. macOS is supported only for development and CLI tests.

## Product guarantees

- **Offline official catalog** — 7 core services and 33 addons are embedded in
  both binaries. Normal operation requires no companion catalog repository.
- **Immutable runtime** — `.sdbx.lock` records catalog, definition, dependency,
  platform, image, configuration, and generated-file provenance.
- **Transactional project changes** — initialization, generation, updates, and
  restore stage and validate changes before promotion.
- **Explicit choices** — the setup workflow does not silently enable a media
  server, addon preset, or unprotected torrent traffic.
- **VPN-enforced downloads** — qBittorrent shares Gluetun's network namespace
  when VPN protection is enabled. Disabling it requires explicit confirmation.
- **Policy-owned authentication** — every public route declares whether
  Authelia, the application, or an explicit public policy owns access. Native
  application credentials are separately classified in the service catalog.
- **TLS in every exposure mode** — LAN uses a local certificate, direct mode
  uses ACME, and Cloudflare Tunnel uses a container-only Traefik entrypoint.
- **No Docker socket in containers** — Traefik uses generated file-provider
  routes. Only the host CLI and the bounded `sdbxd` broker operate Docker.
- **Encrypted recovery** — SDBX backups are authenticated age-encrypted. There
  is no plaintext archive mode.
- **Remote management with layered trust** — the Dashboard is restricted by
  Authelia administrators, a private Traefik-to-host mTLS connection, a browser
  credential, and the typed project-scoped broker API.

## Requirements

- Linux amd64 for the supported RC1 host contract
- Docker Engine 24.0 or newer
- Docker Compose plugin 2.20 or newer
- Docker Buildx 0.10 or newer
- a user with Docker access
- a domain name for generated routes
- Cosign v3 for the signed installer
- a Gluetun-supported VPN provider when VPN enforcement is enabled

Docker access is root-equivalent. Keep Docker and SDBX management groups small.

## Install RC1

The installer must be downloaded and reviewed; SDBX does not recommend a
`curl | sh` pipeline.

```bash
version=v1.0.0-RC1
installer="$(mktemp)"
curl --fail --show-error --location \
  --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --output "$installer" \
  "https://raw.githubusercontent.com/get-sdbx/sdbx/$version/install.sh"
less "$installer"
bash "$installer" \
  --version "$version" \
  --install-dir "$HOME/.local/bin"
rm -f "$installer"
```

The installer verifies the keyless Sigstore identity of the release workflow,
the signed checksum manifest, the selected archive, its exact contents, and
both embedded binary versions before replacing an existing binary pair.

To build the same tag from source:

```bash
version=v1.0.0-RC1
git clone --branch "$version" --depth 1 https://github.com/get-sdbx/sdbx.git
cd sdbx
test "$(git describe --tags --exact-match)" = "$version"
go mod verify
make build
```

## Create and verify a project

```bash
mkdir -p "$HOME/sdbx-project"
cd "$HOME/sdbx-project"
sdbx init
sdbx lock verify
sdbx up
sdbx status
sdbx doctor
sdbx vpn status
```

The guided initializer collects the domain, exposure mode, routing strategy,
storage paths, media server, addon preset, VPN policy, and initial Authelia
administrator credential. Before writing anything, it previews the selected
services, routes, authentication modes, networks, and host-path effects.

For automation, preview the exact operation first:

```bash
sdbx init \
  --skip-wizard \
  --dry-run \
  --domain media.example.test \
  --expose lan \
  --routing subdomain \
  --media-server jellyfin \
  --preset none \
  --allow-unprotected-downloads \
  --admin-password-file /secure/admin-password
```

Remove `--dry-run` and add `--yes` only after reviewing the preview. Secret
files must be private regular files and are never copied into project intent.

After the stack is healthy:

```bash
sdbx integrate --dry-run
sdbx integrate
sdbx open
```

Integration reconciles supported native credentials, download clients,
categories, Arr connections, notifications, and marked worker configuration.
It does not add indexers or third-party account credentials on your behalf.

## Dashboard

The generated root route exposes the SDBX Dashboard after Authelia authorizes
an administrator. Traefik then reaches the unprivileged host process through a
private TLS 1.3 client-certificate connection. The Dashboard can request only
the typed operations exposed by `sdbxd`; it has no generic shell, filesystem,
Docker API, mount, or container-exec primitive.

The packaged service also exposes a separate HTTP recovery listener on host
loopback. To use it through SSH:

```bash
ssh -L 18778:127.0.0.1:18778 operator@your-sdbx-host
sdbx console --addr 127.0.0.1:18778
```

Open the printed fragment-authenticated URL locally. Port `18777` is the mTLS
backend and is not the SSH recovery endpoint.

## Recovery boundary

```bash
sdbx backup --recipient age1...
sdbx backup list
sdbx backup restore BACKUP_NAME \
  --identity-file /secure/age-identity.txt \
  --confirm restore
```

SDBX backups cover project configuration, secrets, managed application
configuration, Compose runtime, and the lock. They intentionally exclude
media, downloads, external Docker volumes, and `data_path`, including
Authelia's database and TOTP enrollments. Snapshot or back up those separately.

## Documentation

- [Installation](docs/installation.md)
- [Getting started](docs/getting-started.md)
- [Operations](docs/operations.md)
- [Backup and restore](docs/backup-restore.md)
- [Updates and rollback](docs/upgrade.md)
- [Compatibility](docs/compatibility.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [CLI reference](docs/reference/cli.md)
- [Configuration reference](docs/configuration.md)
- [Service reference](docs/reference/services.md)
- [External catalog trust](docs/external-sources.md)
- [Security policy](SECURITY.md)
- [Support](SUPPORT.md)
- [Contributing](CONTRIBUTING.md)

## License

SDBX and its official service catalog are licensed under the [MIT License](LICENSE).
Release archives include generated third-party notices in
[THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).
