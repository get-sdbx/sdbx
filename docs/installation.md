# Installation and host services

SDBX `v1.0.0-RC1` first-class host support targets Linux amd64. The release also carries
Linux arm64 compatibility artifacts, but arm64 does not have the complete RC1
clean-host runtime guarantee. Each archive contains two native binaries:

- `sdbx` is the operator CLI and host Dashboard;
- `sdbxd` is the root-owned, project-scoped management broker used by the
  console.

Docker Engine 24 or newer and Docker Compose 2.20 or newer are required.
Docker access is root-equivalent; use a dedicated host or VM and keep the
Docker and SDBX management groups small.

## Install a signed release

Install and verify
[Cosign v3](https://docs.sigstore.dev/cosign/system_config/installation/),
then download the installer from the exact release tag:

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
"$HOME/.local/bin/sdbx" version
"$HOME/.local/bin/sdbxd" -version
```

Pinning `--version` binds all three downloads to one immutable release. The
installer:

1. accepts the supported Linux amd64 artifact or Linux arm64 compatibility
   artifact, plus Cosign major version 3;
2. downloads the normalized archive, checksum manifest, and Sigstore bundle
   over HTTPS with retry and size bounds;
3. verifies that the checksum manifest was signed by the SDBX release workflow
   for the exact requested tag;
4. requires one matching SHA-256 checksum entry;
5. rejects links, special files, or any archive member outside the release
   allowlist;
6. runs both extracted binaries and requires their embedded version to match
   the requested tag;
7. replaces both binaries through same-directory staging and restores the
   previous pair if either commit fails; and
8. when `--systemd-assets-dir` is provided, installs the three verified,
   version-matched systemd files in the same rollback-capable transaction.

Omitting `--version` follows GitHub's latest stable release redirect. Prefer an
explicit version in automation. `--install-dir` defaults to `/usr/local/bin`
only when it is already writable; otherwise it uses `$HOME/.local/bin`.

The release also publishes per-archive SPDX JSON SBOMs and GitHub build
provenance. The installer verifies the signed checksum set; inspect the
release's attestations independently when provenance policy requires it.

Do not pipe a downloaded installer directly into a shell. Saving it first
allows review and keeps an exact incident artifact if verification fails.

## Install from a trusted checkout

For an independent release rebuild, use Go 1.26.5 or newer and pin the exact tag plus
the commit recorded in the signed release provenance:

```bash
version=v1.0.0-RC1
expected_commit=REPLACE_WITH_COMMIT_FROM_SIGNED_PROVENANCE
git clone https://github.com/get-sdbx/sdbx.git
cd SDBX
git checkout --detach "$version"
test "$(git describe --tags --exact-match)" = "$version"
test "$(git rev-parse HEAD)" = "$expected_commit"
go mod verify
make build

sudo install -m 0755 bin/sdbx /usr/local/bin/sdbx
sudo install -m 0755 bin/sdbxd /usr/local/bin/sdbxd

sdbx version
sdbxd -version
```

Do not substitute an unreviewed `curl | sh` pipeline.

## CLI-only operation

The smallest deployment does not need either systemd service. Initialize and
operate one project as the Linux account that owns its directory:

```bash
mkdir -p "$HOME/sdbx-project"
cd "$HOME/sdbx-project"
sdbx init
sdbx lock verify
sdbx up
sdbx doctor
```

Initialize in an empty directory. In a terminal, a non-empty directory without
`.sdbx.yaml` requires a reviewed dry-run and an exact interactive confirmation.
Non-interactive and JSON operation additionally requires the explicit
`--allow-nonempty-directory` acknowledgement.

That account must be able to reach Docker. Membership in the Docker group
confers root-equivalent host control.

## Install the optional management console

The Web console is not a setup tool. Initialize the project and verify its
lock from the CLI before registering it with `sdbxd`. The packaged units
execute `/usr/local/bin/sdbx` and `/usr/local/bin/sdbxd`; a user-local CLI
installation is therefore insufficient for this optional host service.

The packaged units establish this boundary:

- `sdbxd` runs as root, registers one absolute project path, and owns Docker
  and managed-file mutations;
- `sdbx-web` runs as the unprivileged `sdbx-web` account;
- both communicate only through `/run/sdbx/sdbxd.sock`;
- `/run/sdbx/client.token` grants administrative access to the typed broker
  API and is readable only by root and the `sdbx` group;
- `/run/sdbx/console.token` is a distinct local-browser credential, also
  restricted to root and the `sdbx` group;
- both token files are root-provisioned `root:sdbx`, mode `0640` files
  containing one canonical 256-bit base64url value. On startup, `sdbxd`
  repairs a changed numeric `sdbx` group through the already pinned file
  descriptor without rotating either credential. Do not hand-edit,
  concatenate, pad, or weaken them; malformed or permissive files make both
  units fail closed;
- the browser listener accepts TLS 1.3 only and requires the generated Traefik
  client certificate before reading any HTTP request;
- Traefik applies Authelia ForwardAuth and copies the verified identity, while
  the Web process independently requires a non-empty user, membership in
  `admins`, the canonical public Host, and the verified client certificate;
- only `/`, `/api/*`, and `/static/*` are assigned to the Dashboard. Existing
  service subpaths stay unchanged;
- privileged mutations are recorded in `/var/log/sdbx/audit.jsonl`.

Install the exact release again as root, this time preserving its verified
systemd assets. The installer rewrites the two signed unit templates so their
`ExecStart` values use the exact `--install-dir` selected in the same
transaction; custom systemd binary paths must be absolute and contain no
whitespace, repeated separators, or dot segments. Review the installer before
invoking it:

```bash
version=v1.0.0-RC1
installer="$(mktemp)"
curl --fail --show-error --location \
  --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --output "$installer" \
  "https://raw.githubusercontent.com/get-sdbx/sdbx/$version/install.sh"
less "$installer"
sudo bash "$installer" \
  --version "$version" \
  --install-dir /usr/local/bin \
  --systemd-assets-dir /usr/local/share/sdbx/systemd
rm -f "$installer"
/usr/local/bin/sdbx version
/usr/local/bin/sdbxd -version
```

Create a dedicated operating-system group and Web account. Set `operator` to
an existing Linux account only if local fragment-token access is also needed:

```bash
operator=REPLACE_WITH_EXISTING_OPERATOR
getent passwd "$operator"
getent group sdbx >/dev/null || sudo groupadd --system sdbx
id sdbx-web >/dev/null 2>&1 || \
  sudo useradd --system --gid sdbx --home-dir /nonexistent \
    --shell /usr/sbin/nologin sdbx-web
sudo usermod -aG sdbx "$operator"
id sdbx-web
getent group sdbx
```

Only the Web account and explicitly trusted local administrators may belong to
the `sdbx` group. Any member can read the static token and invoke every typed
administrative operation exposed by the broker. The operator must fully log
out and back in after `usermod`; before enabling the console, verify from that
new session that `id -nG` contains `sdbx`. Do not use `newgrp` in a long-lived
automation or service session to hide stale group membership.

Install the unit files and environment template:

```bash
sudo install -d -m 0755 /etc/sdbx
sudo install -m 0644 /usr/local/share/sdbx/systemd/sdbxd.service \
  /etc/systemd/system/sdbxd.service
sudo install -m 0644 /usr/local/share/sdbx/systemd/sdbx-web.service \
  /etc/systemd/system/sdbx-web.service
sudo install -m 0640 /usr/local/share/sdbx/systemd/sdbxd.env.example \
  /etc/sdbx/sdbxd.env
sudoedit /etc/sdbx/sdbxd.env
```

Set `SDBX_PROJECT_DIR` to one initialized absolute project directory. Leave
`SDBX_SOURCES_FILE` empty to use only the embedded official catalog. If it is
set, it must be an absolute path to the same reviewed source configuration
used to create the project's lock.

OIDC is optional for direct broker clients. Set both `SDBX_OIDC_ISSUER` and
`SDBX_OIDC_CLIENT_ID`, or leave both empty. Remote browser authentication is
owned by the generated Authelia ForwardAuth route; the Web process uses the
broker token only for its protected Unix-socket hop.

Review the resolved units before enabling them:

```bash
sudo systemd-analyze verify \
  /etc/systemd/system/sdbxd.service \
  /etc/systemd/system/sdbx-web.service
sudo systemctl daemon-reload
sudo systemctl enable --now sdbxd.service sdbx-web.service
sudo systemctl status sdbxd.service sdbx-web.service
sudo journalctl -u sdbxd.service -u sdbx-web.service --since today
```

`sdbxd` refuses to start unless it runs as root, the project loads and
verifies, the `sdbx` group exists, and the socket, token, audit, source, and
project paths satisfy their safety checks.

## Ownership model

The project owner may use the CLI while `sdbxd` is enabled. Root broker
mutations preserve existing managed-file owners and make new managed files and
directories inherit the nearest real parent owner. Files consumed directly by
containers intentionally use the configured `PUID:PGID`; broker socket, token,
and audit files remain root-owned.

Encrypted restore is covered by the same owner-preservation contract. It
preserves existing owners, inherits the nearest destination
parent for new managed paths, and rolls back the complete managed file set
before reporting a failed restore. Still perform disaster recovery in a
reviewed maintenance session: application databases, media, downloads, and
external volumes are outside that transaction. The excluded `data_path`
contains Authelia's database and TOTP enrollments, so preserve and test a
separate application-consistent recovery copy.

Do not solve ownership errors with broad recursive `chown` or `chmod`.
Identify the exact file, stop the daemon if necessary, preserve a backup, and
repair only the reviewed target.

## Reach the console

For a remote installation, open the canonical SDBX root, for example
`https://sdbx.example.test/`. Authelia must authenticate a member of its
`admins` group before Traefik forwards the request. Do not create a separate
Dashboard tunnel route: the generated route uses the same canonical hostname
and Traefik origin as the application subpaths.

The listener on host port `18777` is not a public plaintext endpoint. A direct
client without the private Traefik certificate fails during the TLS handshake,
and a valid proxy connection still needs the Authelia admin identity headers.
The internal CA and leaf keys live under `secrets_path`, are included in
encrypted backups, and are copied into `/run/sdbx` only for the host process.

Local emergency access remains possible through the packaged recovery
listener and an SSH tunnel:

```bash
ssh -L 18778:127.0.0.1:18778 operator@sdbx-host
sdbx console --addr 127.0.0.1:18778
```

Run the `sdbx console` command on the host or another trusted context that can
read `/run/sdbx/console.token`, then open the printed URL in the browser using
the tunnel. The token is in the URL fragment, which is not sent in the HTTP
request and is removed from the address bar before management data loads. Port
`18777` remains TLS-only and accepts only Traefik's private client certificate;
the recovery HTTP listener binds only to `127.0.0.1:18778`.

## Stop or disable the console

Stopping the services does not stop the media stack:

```bash
sudo systemctl stop sdbx-web.service sdbxd.service
```

Disabling them prevents automatic startup without deleting project state,
tokens, logs, or backups:

```bash
sudo systemctl disable sdbx-web.service sdbxd.service
```

The packaged unit keeps the token in its systemd `RuntimeDirectory`; stopping
the broker removes that runtime state and the next start generates a new token.
To rotate it without touching project data:

```bash
sudo systemctl stop sdbx-web.service
sudo systemctl restart sdbxd.service
sudo systemctl start sdbx-web.service
```

This briefly interrupts the Dashboard. Preserve and review the audit log,
verify the new token and socket modes, and use the private reporting path in
[SECURITY.md](../SECURITY.md) if compromise is suspected. Do not remove a live
socket or token while either process is running.

## Recoverable uninstall

Uninstalling the controller is separate from deleting the Compose stack,
project, media, downloads, application data, backups, token, or audit log.
Preserve an off-host encrypted backup and record the exact paths before
changing anything.

Stop and disable only the optional management services:

```bash
sudo systemctl disable --now sdbx-web.service sdbxd.service
```

Move the installed artifacts to an explicit quarantine instead of deleting
them:

```bash
sudo install -d -m 0700 /var/backups/sdbx-uninstall-review
sudo mv -n /usr/local/bin/sdbx /var/backups/sdbx-uninstall-review/sdbx
sudo mv -n /usr/local/bin/sdbxd /var/backups/sdbx-uninstall-review/sdbxd
sudo mv -n /etc/systemd/system/sdbxd.service \
  /var/backups/sdbx-uninstall-review/sdbxd.service
sudo mv -n /etc/systemd/system/sdbx-web.service \
  /var/backups/sdbx-uninstall-review/sdbx-web.service
sudo mv -n /etc/sdbx/sdbxd.env \
  /var/backups/sdbx-uninstall-review/sdbxd.env
sudo systemctl daemon-reload
```

This leaves the registered project, Compose services, `/run/sdbx` runtime
state, `/var/log/sdbx/audit.jsonl`, and the `sdbx`/`sdbx-web` identities for
review. Runtime files under `/run` normally disappear after reboot once no
unit recreates them.

Deleting the project, media, downloads, container volumes, audit history,
management identities, or quarantine can cause irreversible data loss and is
not part of uninstall. Inventory each exact target, verify backups and
application exports, preview the impact, and obtain explicit operator
confirmation before any deletion.

## Verify after installation

For the registered project, prove both the product and broker boundaries:

```bash
cd /absolute/project/path
sdbx lock verify
sdbx status
sdbx doctor
if curl --insecure --fail --silent https://127.0.0.1:18777/ >/dev/null; then
  echo "console unexpectedly accepted a direct client" >&2
  exit 1
fi
```

Also inspect:

- ownership and modes of `/run/sdbx`, its socket, `client.token`, and
  `console.token`;
- recent broker start and mutation events;
- the active Dashboard route, Authelia admin policy, internal certificate
  names, and VPN posture;
- successful public login from a second machine and rejection of a non-admin;
- refusal of a non-loopback `sdbx serve --addr` value unless all remote TLS
  trust flags are provided.

Continue with [Getting Started](getting-started.md) for project initialization
and [Operations](operations.md) for day-two procedures.
