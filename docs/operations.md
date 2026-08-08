# Operations

Run operational commands from the project directory. `.sdbx.yaml` is intent;
`.sdbx.lock`, `compose.yaml`, `.env`, and lock-recorded policy files are
verified derived state.

## Routine health check

Use this sequence after host maintenance, configuration changes, and service
incidents:

```bash
sdbx lock verify
sdbx status
sdbx doctor
```

For a VPN-enabled project:

```bash
sdbx vpn status
```

`lock verify` checks intent, catalog and definition provenance, locked OCI
images, and generated-file digests. `status` compares the active locked graph
with Compose state. `doctor` checks host requirements, paths, ports, project
files, secrets, service health, and VPN posture.

Automation may use `sdbx --json status` and `sdbx --json doctor`. A failed
diagnostic or unproven VPN returns nonzero.

## Start, stop, and restart

```bash
sdbx up
sdbx down
sdbx restart SERVICE
```

`up` refuses an unverified project. `down` runs `docker compose down`, removing
the project's Compose containers and networks while preserving project files,
bind-mounted media, downloads, and persistent state. `restart` can target one
active service; a multi-service failure returns nonzero.

Stopping the optional `sdbxd` and `sdbx-web` host services does not stop the
Compose stack.

## Inspect logs and routes

```bash
sdbx logs --tail 200 SERVICE
sdbx open
sdbx status
```

Use `--follow` only in an attended terminal. SDBX redacts common credential
assignments, authorization and cookie headers, URL credentials, private keys,
and known first-launch password lines from both bounded and followed output.
That filter is defence in depth, not a proof that arbitrary upstream text is
safe: logs can still contain domains, usernames, media names, remote addresses,
and application data. Review every excerpt before sharing.

Broker/Web retained-log reads accept at most 1,000 lines and 2 MiB from either
Docker subprocess stream. The broker cancels the subprocess at the writer
boundary instead of buffering an oversized response and checking it afterward.

## Change one typed setting

Inspect the current value and the generated reference first:

```bash
sdbx config get expose.mode
sdbx config set expose.tls.email ops@example.test
sdbx config set expose.mode direct
sdbx lock verify
```

Each successful typed mutation validates the entire project, resolves a
coherent lock, and regenerates runtime files. Disabling VPN requires the
command's explicit unprotected-download acknowledgement.

When repointing several path roots, edit `.sdbx.yaml` once instead of applying
several intermediate `config set` operations:

```bash
sdbx lock diff
sdbx lock
sdbx lock verify
```

Review the YAML edit and diff before accepting the new lock. Do not hand-edit
the lock or generated runtime.

## Reconstruct generated files

Use `sdbx generate` only when project intent and the existing lock still agree
but a derived file is missing or damaged:

```bash
sdbx generate
sdbx lock verify
```

If intent, addon selection, catalog input, or image intent changed, use the
specific typed command or reviewed `sdbx lock` path instead.

## Addons and presets

```bash
sdbx addon list --all
sdbx addon info sonarr
sdbx addon enable sonarr
sdbx addon disable sonarr
sdbx preset list
sdbx preset show power-user
```

Official addon changes reuse the reviewed image snapshot embedded in the
binary and regenerate the locked graph. External-source images are resolved
through their explicit registry trust boundary. Disabling an addon removes it
from the generated runtime but does not promise deletion of its service-owned
data. Inspect paths before manually retiring data.

A preset is a reviewed group of addon choices, not an upstream credential or
indexer configuration.

Plain `sdbx lock` preserves valid image pins already present in the project and
uses the reviewed embedded snapshot only for newly introduced official
services. `sdbx update` is the only supported all-image upstream refresh: it
previews exact digest changes by default and requires
`--apply --confirm apply-upstream-images` before writing runtime or touching
containers. Do not bypass its health verification and container rollback with
manual lock edits or direct mutable-tag pulls.

## Integrations

After the affected services are healthy:

```bash
sdbx integrate --dry-run
sdbx integrate
```

Host-safe initialization is idempotent where supported. On Linux, HTTP
integration resolves only verified SDBX container addresses through Docker
inspect and uses their authenticated APIs over the local bridge. SDBX launches
no helper and does not mount the Docker socket inside a container. If a host
firewall or rootless Docker setup prevents bridge routing, `--in-cluster` is
an explicit fallback only for an operator-supplied trusted runner already
attached to the app and download networks. SDBX does not invent indexers or
third-party credentials. For Sonarr, Radarr, Lidarr, Prowlarr, and Whisparr,
the same phase verifies or reconciles native Forms authentication with an
SDBX-managed administrator. The service stays fail-closed before that
reconciliation; its API key remains available to the authenticated integration
phase. Prowlarr and qBittorrent integration cover the enabled supported Arr
set, including Whisparr v3. SDBX enables automatic category paths only as the
default for newly added qBittorrent transfers. It never toggles automatic
management on an existing torrent, because that could relocate payloads and
invalidate operator-managed resume state.

When Plex is enabled, the same phase reconciles an SDBX-managed Plex
notification in every enabled Arr service. The notification uses the stable
container endpoint and the existing Plex application token, and refreshes the
library after imports, upgrades, and renames. Existing non-Plex notifications
are preserved.

When Decluttarr is enabled, this phase also reconciles
`configs/decluttarr/config.yaml` as a Decluttarr v2 document. SDBX keeps
`general.test_run: true`, refreshes the enabled Arr API keys, points
qBittorrent at its graph-derived internal endpoint, and writes the managed
credential without printing it. Existing jobs and tuning are preserved. The
file is owned by SDBX only while its first line is exactly
`# managed-by: sdbx`; removing that marker is an explicit opt-out and makes
future integration runs leave the file byte-for-byte unchanged.

## Authentication operations

Routes marked `native-auth` use the application's own accounts. Configure
those administrators through upstream-supported flows before exposure.

Sonarr, Radarr, Lidarr, Prowlarr, and Whisparr are layered `admin-only`
services rather than `native-auth` routes. Authelia performs the outer
administrator authorization; the application also requires the SDBX-managed
`sdbx-admin` Forms account from every address. Recover a password only in a
private terminal:

```bash
sdbx secrets show sonarr --confirm reveal
sdbx secrets show prowlarr --confirm reveal
sdbx secrets show radarr --confirm reveal
sdbx secrets show lidarr --confirm reveal
sdbx secrets show whisparr --confirm reveal
```

Do not change those passwords in the application UI. `sdbx integrate`
authoritatively repairs drift so the protected secret file remains a working
recovery credential.

Authelia route policy is generated and defaults to `one_factor` for initial
enrollment. Sign in to the Authelia portal, enroll and verify the administrator
TOTP device, then switch the complete ForwardAuth boundary:

```bash
sdbx config get auth.factor
sdbx config set auth.factor two_factor
sdbx lock verify
sdbx restart authelia
```

Sign out and prove in a fresh browser session that password-only
authentication no longer authorizes any protected or admin-only route. To
recover from a lost second factor, use a reviewed private maintenance session
and the separately backed-up Authelia identity state; do not weaken the
generated file by hand.

Do not rotate JWT, session, storage, API, or encryption secrets as generic
maintenance. Rotation may invalidate sessions or make data unreadable. Create
and test an encrypted backup, identify every consumer, then use a supported
service-specific procedure.

SDBX v1 deliberately has no generic `secrets rotate` command. In particular,
replacing an Authelia storage-encryption key is not a file-only operation, and
replacing a qBittorrent, File Browser, Sonarr, Radarr, Lidarr, Prowlarr, or
Whisparr password file alone would leave the application or one of its
consumers using the previous value.

SDBX owns the qBittorrent, File Browser, and supported Arr credentials created
by `sdbx integrate`. Do not change those passwords independently in an
application UI. Recover the current managed value only from a private terminal:

```bash
sdbx secrets show qbittorrent --confirm reveal
sdbx secrets show filebrowser --confirm reveal
sdbx secrets show sonarr --confirm reveal
sdbx secrets show prowlarr --confirm reveal
sdbx secrets show radarr --confirm reveal
sdbx secrets show lidarr --confirm reveal
sdbx secrets show whisparr --confirm reveal
```

If one of those managed secret files is missing or empty, preserve a verified
encrypted backup and run `sdbx integrate`. The initializer marks credential
recovery as pending before it creates and applies a replacement, so an
interrupted run retries instead of treating the old stamp as authoritative.
qBittorrent integration also compares the managed password with the persisted
PBKDF2 hash and reconciles a mismatch. Supported Arr services verify the real
Forms login before declaring the managed credential current and reconcile
drift through their API keys.

Cobalt API access uses a separate generated UUIDv4 key map. Recover the first
client key only in a private terminal, then configure the official frontend:

```bash
sdbx secrets show cobalt --confirm reveal
```

Use the endpoint from `sdbx open cobalt` at
<https://cobalt.tools/settings/instances>. Do not paste the complete key-map
file into a browser or issue.

File Browser does not expose an equivalent offline verifier to SDBX. If its
password was changed outside SDBX while the managed file still exists,
the recovery value may be stale. Restore from the encrypted backup or perform
an upstream-supported maintenance recovery with the service isolated. Never
place the replacement password in Docker arguments or shell history.

## VPN operations

Provider credentials live in `configs/gluetun/gluetun.env`, never in
`.sdbx.yaml`. Keep that file private and configure only the variables required
by the selected Gluetun provider.

After credential or provider changes:

```bash
sdbx restart gluetun
sdbx vpn status
sdbx doctor
```

Do not resume download automation until the protection check succeeds. A
healthy container alone does not prove different host and tunnel egress.

`sdbx vpn status` does not interrupt a live tunnel. Release qualification proves
fail-closed behavior only on a disposable QA host. Do not simulate tunnel loss
on a production host.

## Updates

`sdbx update` is the supported image refresh:

```bash
sdbx lock verify
sdbx backup --recipient age1...
sdbx update
sdbx update --apply --confirm apply-upstream-images
sdbx status
sdbx doctor
```

The first command is a non-mutating preview. Review its exact upstream digest
changes, release notes, and advisories before using the explicit apply and
confirmation command. Candidate images have not passed the SDBX release
catalog security review.

Apply stages the new lock and all generated runtime files, records old and new
SHA-256 digests, and promotes the set through one recoverable project
transaction. An interrupted promotion is rolled back before the next project
command loads configuration or lock intent. SDBX then pulls exact images,
converges the stack, and checks every service in dependency order. On failure
it restores the previous lock/runtime through the same transaction path and
reconverges the previous digests. It cannot roll back an incompatible
application database migration.

This command deliberately moves beyond the release-reviewed embedded image
snapshot. Review its exact lock diff and upstream release notes before
approval; the next project lock remains immutable but is not retroactively
covered by the release's catalog scan. Follow
[Upgrade and Rollback](upgrade.md).

## Backups

Create encrypted recovery material before changes and on a regular schedule:

```bash
sdbx backup --recipient age1...
sdbx backup list
```

Copy the archive off-host and keep the private identity separate. SDBX backups
exclude the complete `data_path`, including Authelia identity/TOTP state, plus
media, downloads, and external Docker volumes. Follow
[Backup and Restore](backup-restore.md) for custody, drills, limitations, and
exact confirmations.

## Management services

For a console-managed installation:

```bash
sudo systemctl status sdbxd.service sdbx-web.service
sudo journalctl -u sdbxd.service -u sdbx-web.service --since today
```

Broker mutation evidence is in `/var/log/sdbx/audit.jsonl`. Treat it as
sensitive deployment metadata. It is locally append-only during broker
operation, not cryptographically tamper-evident.

The generated Traefik route publishes only the Dashboard root, API, and static
namespaces behind Authelia `admins` and a private mTLS backend transport. Keep
the internal PKI files in encrypted recovery and verify both the public login
and direct-port TLS rejection after upgrades.

## Incident-safe evidence

Capture evidence before making a repair:

- exact SDBX version and command exit status;
- Linux, architecture, Docker, and Compose versions;
- redacted `lock verify`, `status`, and `doctor` output;
- only the relevant bounded service log;
- broker unit status and redacted audit events when involved;
- whether the last update reported successful or failed rollback.

Never post project YAML, locks, generated Compose, provider files, token files,
audit logs, age identities, or secrets without a field-by-field redaction
review. For suspected vulnerabilities, follow [SECURITY.md](../SECURITY.md)
instead of opening a public issue.

## Safe troubleshooting rule

Diagnose the exact path, container, or policy first. Do not use Docker-wide
pruning, broad recursive permission rewrites, or cache deletion as generic
repairs. Preview the impact, preserve a backup or host snapshot, and scope any
destructive action to a reviewed target.

See [Troubleshooting](troubleshooting.md) for condition-specific procedures.
