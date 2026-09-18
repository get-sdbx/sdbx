# Getting Started

This guide takes a new Linux host from a trusted SDBX checkout to one verified
deployment. It uses the interactive setup because that path shows the complete
service, route, authentication, network, mount, and secret plan before writing
anything.

SDBX `v1.0.0-RC1` supports Linux amd64 hosts. Linux arm64 is published as a compatibility
build without the full clean-host runtime guarantee. macOS and Windows are
useful development clients, not supported deployment hosts.

## 1. Prepare the host

You need:

- Docker Engine 24.0 or newer;
- Docker Compose plugin 2.20 or newer;
- Docker Buildx 0.10 or newer;
- a user that can reach the Docker daemon;
- a domain you control, including local DNS for LAN-only deployments;
- a Gluetun-supported VPN provider if torrent traffic must be VPN-protected.

Docker access is root-equivalent. Use a dedicated Linux host or VM and limit
membership of the Docker group.

Verify the required Docker components:

```bash
docker version
docker compose version
docker buildx version
```

When building from source, install Go 1.26.8 or newer and Make. Signed-release
installation additionally requires Cosign v3.

## 2. Install SDBX

Use the signed release procedure in [Installation and host
services](installation.md#install-a-signed-release). For an independent rebuild,
build both native binaries from a trusted checkout:

```bash
git clone https://github.com/get-sdbx/sdbx.git
cd SDBX
make build

sudo install -m 0755 bin/sdbx /usr/local/bin/sdbx
sudo install -m 0755 bin/sdbxd /usr/local/bin/sdbxd

sdbx version
sdbxd -version
```

Do not substitute an unreviewed `curl | sh` installer.

## 3. Choose the exposure model

The setup wizard asks how browser traffic reaches Traefik:

| Mode | Host web ports | Certificate behavior | Use when |
| --- | --- | --- | --- |
| `lan` | `80`, `443` | HTTPS with Traefik's local/default certificate | Access stays on a trusted LAN or private overlay |
| `direct` | `80`, `443` | HTTPS with ACME certificates | The host is intentionally reachable from the Internet |
| `cloudflared` | none | HTTPS terminates at a remote-managed Cloudflare Tunnel | You accept Cloudflare as an external trust, route-control, and availability dependency |

HTTP redirects to HTTPS in LAN and direct modes. LAN traffic is encrypted, but
clients will not trust the default certificate automatically. Install a trusted
local certificate or explicitly manage trust on each client before treating
browser warnings as resolved.

Subdomain routing needs DNS records such as
`jellyfin.media.example.net`. Path routing shares one hostname such as
`media.example.net/jellyfin`. Configure DNS before judging route health.
For Cloudflare mode, SDBX derives the exact Published application mappings but
does not mutate your Cloudflare account.

## 4. Initialize a project

Create a directory that will own the project intent and generated runtime:

```bash
mkdir -p "$HOME/sdbx-project"
cd "$HOME/sdbx-project"
sdbx init
```

Use an empty directory. SDBX recognizes an existing project by its
`.sdbx.yaml`. In an interactive terminal, an unrelated non-empty directory
requires an exact confirmation after the dry-run preview. Non-interactive and
JSON operation fails closed unless you review the dry-run and explicitly pass
`--allow-nonempty-directory`.

The wizard requires explicit choices for:

- domain, exposure mode, and subdomain or path routing;
- the initial Authelia administrator credential;
- Plex, Jellyfin, both, or no media server;
- media, download, and service-configuration paths;
- VPN protection and provider, or acknowledgement of unprotected torrent
  traffic;
- timezone;
- a named automation preset or `none`.

SDBX resolves the embedded catalog and immutable image digests, checks Docker
and Compose versions, validates managed paths and published ports, and displays
the exact deployment plan. It stages and validates all output before atomically
promoting the project.

The resulting project includes:

- `.sdbx.yaml` — operator-owned project intent;
- `.sdbx.lock` — catalog, definition, platform, image digest, and generated-file
  provenance;
- `compose.yaml` and `.env` — generated runtime;
- `configs/` — managed policy plus service-owned configuration;
- `secrets/` — private credentials and keys.

Do not edit lock-recorded generated files. Change `.sdbx.yaml` or a supported
configuration key, then update the lock and runtime through the corresponding
typed command or a reviewed `sdbx lock`.

### Non-interactive preview

Automation must preview before it writes. Use a private regular password file:

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

Remove `--dry-run` and add `--yes` only after reviewing the complete plan.
Use `--vpn --vpn-provider PROVIDER` instead of
`--allow-unprotected-downloads` when downloads require VPN protection. See the
[generated init reference](reference/cli.md#sdbx-init) for the complete
automation contract.

## 5. Add provider-owned credentials

The success screen lists only the credentials required by the selected graph.
Configure them before the first start:

- VPN credentials:
  `configs/gluetun/gluetun.env`;
- Cloudflare Tunnel token:
  `secrets/cloudflared_tunnel_token.txt`;
- fresh Plex claim token:
  `secrets/plex_claim_token.txt`.

Cloudflare mode uses a remotely managed tunnel. Reconcile its account-side
Published application routes before deployment:

```bash
sdbx tunnel routes
```

Create one mapping per displayed hostname and use the displayed private origin,
`http://traefik:8081`, for every mapping. The route list comes from the active
locked graph, so rerun it after changing the domain, routing strategy, media
servers, or addons. A tunnel token only authenticates the connector; it cannot
create these mappings. SDBX v1 does not support locally managed
credentials-JSON tunnels.

The Gluetun file contains provider-specific placeholders and links to the
upstream provider instructions. Replace the relevant placeholders and keep the
file mode at `0600`. Do not place VPN credentials in `.sdbx.yaml`.

Write manual secret values through private mode-`0600` input files. On
`sdbx up`, SDBX keeps the `secrets/` directory mode `0700` and normalizes only
the Authelia and Cloudflared files mounted into non-root containers to mode
`0644` inside that untraversable directory. Docker Compose implements
file-backed secrets as bind mounts, so this constrained exception lets those
containers read their individual read-only mounts without exposing the files
to other host users or putting values in container environment metadata. Use
`sdbx up`, not a raw Compose start, so runtime ownership and secret modes are
repaired first.

Direct mode requires one plain ACME contact email. The interactive wizard
collects it. Non-interactive setup must pass it explicitly:

```bash
sdbx init \
  --skip-wizard \
  --dry-run \
  --domain media.example.test \
  --expose direct \
  --acme-email ops@example.test \
  --routing subdomain \
  --media-server jellyfin \
  --preset none \
  --allow-unprotected-downloads \
  --admin-password-file /secure/admin-password
```

Review the complete plan, then remove `--dry-run` and add `--yes`.

## 6. Start the locked deployment

From the project directory:

```bash
sdbx lock verify
sdbx up
sdbx status
sdbx doctor
```

`sdbx up` refuses a stale lock or a modified lock-recorded runtime file. A
healthy first deployment has:

- a valid lock;
- every expected service present and running;
- no failed doctor checks;
- the expected HTTPS routes listed by `sdbx open`;
- proven VPN isolation when VPN protection is configured.

For a VPN-protected project, verify the host and tunnel paths:

```bash
sdbx vpn status
```

The command succeeds only when VPN protection is configured, Gluetun is
healthy, and the tunnel egress differs from the host egress. The locked Compose
model routes qBittorrent through Gluetun's network namespace.

## 7. Apply supported integrations

After the containers settle, preview host-safe initialization and supported
service integrations:

```bash
sdbx integrate --dry-run
sdbx integrate
```

The host command initializes supported local configuration, including
permanent qBittorrent and File Browser authentication plus layered native Forms
credentials for Sonarr, Radarr, Lidarr, Prowlarr, and Whisparr v3. It also
connects the enabled supported Arr applications to Prowlarr and qBittorrent.
New qBittorrent transfers use the managed Arr category paths; existing
torrents are never relocated implicitly. Enabled Arr services notify Plex
through its stable internal endpoint after an import, upgrade, or rename.
On Linux it resolves only the verified SDBX containers through Docker inspect
and calls their authenticated APIs over the local bridge. It does not launch a
helper or mount the Docker socket inside a container. If an unusual host
firewall or rootless Docker setup blocks bridge access, `--in-cluster` is
available only for an operator-supplied trusted runner already attached to both
project networks.

List active routes:

```bash
sdbx open
```

Open the reported HTTPS URL and sign in with the Authelia administrator created
during setup. Supported Arr services then require their application-native
`sdbx-admin` account as a second boundary; native-auth services may require
their own upstream account. Retrieve supported SDBX-managed recovery
credentials with `sdbx secrets show SERVICE --confirm reveal` in a private
terminal session, without pasting them into logs or issues. See
[Addons and Presets](addons.md#v1-service-notes) for Calibre-Web, pyLoad,
Cobalt, Unpackerr, Notifiarr, and Tdarr first-run boundaries.

## 8. Preserve recovery material

Create an authenticated encrypted backup after the first verified setup:

```bash
sdbx backup
sdbx backup list
```

Store the backup passphrase off-host. For unattended operation, use an age
recipient and preserve its private identity separately. Backups cover SDBX
intent, locks, secrets, and managed configuration; they do not include any
part of `data_path`—including Authelia's database and TOTP enrollments—media,
downloads, or external Docker volumes.

## Next

- [Installation and host services](installation.md)
- [Operations](operations.md)
- [Backup and restore](backup-restore.md)
- [Upgrade and rollback](upgrade.md)
- [CLI reference](reference/cli.md)
- [Troubleshooting](troubleshooting.md)
- [Security model](../SECURITY.md)
- [Architecture](architecture.md)
