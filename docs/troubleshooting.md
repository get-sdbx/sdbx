# Troubleshooting

Diagnose from the verified project state before changing files or restarting
containers. SDBX returns nonzero on failed diagnostics, stale locks, partial
operations, and unproven VPN protection.

Run commands from the project directory or one of its descendants. SDBX locates
the nearest parent containing `.sdbx.yaml` or `compose.yaml`.

## Collect the first evidence

Start with:

```bash
sdbx lock verify
sdbx status
sdbx doctor
```

For automation or issue triage:

```bash
sdbx --json status
sdbx --json doctor
```

Then inspect only the affected service:

```bash
sdbx logs --tail 200 SERVICE
sdbx logs --follow SERVICE
```

Before sharing output, remove domains, public IP addresses, private registry
names, local paths, usernames, and other deployment identifiers. Never share
`.sdbx.yaml`, `.env`, `.sdbx.lock`, provider configuration, token files,
passwords, private keys, or the contents of `secrets/`.

## Project not found

Symptom:

```text
no SDBX project found
```

Change to the directory containing `.sdbx.yaml`:

```bash
cd /path/to/project
sdbx status
```

The global `--config` flag selects a configuration file after project
discovery; it does not turn an arbitrary working directory into that project's
root. Do not initialize a second project merely to make the error disappear.

## Missing or stale lock

Operational commands require a structurally valid schema-v2 `.sdbx.lock`.

If the lock is missing, review `.sdbx.yaml` and run `sdbx lock` to create one.
If the lock is present but stale, inspect the intended change:

```bash
sdbx lock diff
```

There are two distinct repair paths:

1. If `.sdbx.yaml`, enabled addons, catalog definitions, or locked image intent
   changed, review the diff and run `sdbx lock`. This explicitly resolves a new
   coherent lock and regenerates digest-pinned runtime files.
2. If the lock still matches project intent but a generated file was modified
   or lost, run `sdbx generate` to reconstruct runtime from the existing lock.

Verify again:

```bash
sdbx lock verify
```

Do not edit `.sdbx.lock`, `compose.yaml`, `.env`, generated Traefik policy, or
generated Authelia policy by hand.

## Service missing, stopped, or unhealthy

Use the graph-derived status and the specific container logs:

```bash
sdbx status
sdbx logs --tail 200 SERVICE
sdbx doctor
```

If the service is expected but missing, verify the lock, then converge the
active graph:

```bash
sdbx lock verify
sdbx up
```

If it is stopped or unhealthy, fix the reported configuration, credential,
storage, or dependency error first. Use `sdbx restart SERVICE` only after the
underlying condition is understood; a restart does not repair invalid state.

## Route unavailable

List the routes SDBX actually generated:

```bash
sdbx open
sdbx status
```

Check the relevant ingress components:

```bash
sdbx logs --tail 200 traefik
sdbx logs --tail 200 authelia
```

For `cloudflared` mode, also inspect:

```bash
sdbx tunnel routes
sdbx logs --tail 200 cloudflared
```

Then verify:

- the hostname resolves from the client;
- LAN and direct clients reach host ports 80 and 443;
- direct-mode DNS points at the host and inbound 80/443 reach Traefik;
- every hostname from `sdbx tunnel routes` exists as a remote Published
  application mapping to `http://traefik:8081`;
- Cloudflare Tunnel has a valid connector token and reports ready;
- the URL matches the active subdomain or path strategy;
- client time is correct for TLS and authentication.

A Cloudflare-fronted `404` on every SDBX hostname usually means the remote
tunnel configuration still points at an old origin or lacks the new hostname.
Tunnel-token mode ignores local ingress files by design. Reconcile the remote
route list; do not add an `/etc/cloudflared/config.yml` mount. `sdbx doctor`
fails closed on unreachable routes, Cloudflare catch-all `404` responses,
upstream `5xx` responses, or traffic that did not traverse the Cloudflare edge.
This is an edge-reachability heuristic, not origin ownership proof: an
unintended Cloudflare origin returning `200`, `302`, or `401` can pass. Compare
every hostname exactly with `sdbx tunnel routes`, require
`http://traefik:8081`, remove any Host-header override, keep a final catch-all
404 rule, and inspect the intended SDBX login or application response.

LAN mode uses HTTPS with Traefik's local/default certificate. A browser trust
warning is expected until the client trusts an operator-installed local
certificate. Do not disable TLS to hide the warning.

## Direct-mode certificate failure

Direct mode requires a valid ACME contact email. Inspect it:

```bash
sdbx config get expose.tls.email
```

For a supported typed correction:

```bash
sdbx config set expose.tls.email ops@example.test
sdbx lock verify
sdbx up
sdbx logs --tail 200 traefik
```

Interactive initialization collects the email; non-interactive direct setup
requires `--acme-email`. SDBX rejects direct mode without ACME and a plain
contact address.

## VPN protection is not proven

Run:

```bash
sdbx vpn status
sdbx logs --tail 200 gluetun
sdbx doctor
```

Provider credentials belong in `configs/gluetun/gluetun.env`. Generated values
such as `your_private_key` or `your_username` are placeholders. Replace only
the fields required by the selected provider and retain file mode `0600`.

`sdbx vpn status` fails when protection is disabled, Gluetun is unhealthy, an
egress probe fails, or host and tunnel egress are indistinguishable. Do not
disable the VPN to make downloads resume unless exposing torrent traffic
through the host public IP is intentional and explicitly acknowledged.

## Cloudflared cannot read its token

Start the project with `sdbx up`, not raw `docker compose up`. The SDBX
lifecycle repairs the runtime-readable modes required by Authelia and the
Cloudflared connector token, and verifies that the containing secrets directory
remains mode `0700`, each service-mounted file has one link, and the directory
and files share an owner. `sdbx doctor` fails if any part of that boundary is
wrong.

## Downloads are stalled

First prove the transport boundary:

```bash
sdbx vpn status
sdbx logs --tail 200 gluetun
sdbx logs --tail 200 qbittorrent
```

Then verify qBittorrent health and its configured peer port with
`sdbx status`. Do not use an image update as a generic repair. `sdbx update`
changes immutable image locks and should be run only when that change is
intended.

## Managed service login lost

SDBX can surface credentials it manages:

```bash
sdbx secrets show qbittorrent --confirm reveal
sdbx secrets show filebrowser --confirm reveal
sdbx secrets show sonarr --confirm reveal
sdbx secrets show radarr --confirm reveal
sdbx secrets show lidarr --confirm reveal
sdbx secrets show prowlarr --confirm reveal
sdbx secrets show whisparr --confirm reveal
```

Run `sdbx integrate` first if the service has not completed its idempotent
credential initialization. The command prints a secret to the terminal; avoid
shell capture, shared terminals, screenshots, and issue attachments.

There is no generic `sdbx secrets rotate` command in v1. A file-only change can
destroy Authelia access or desynchronize application credentials. If an
SDBX-managed qBittorrent, File Browser, Sonarr, Radarr, Lidarr, Prowlarr, or
Whisparr secret is missing,
preserve an encrypted backup and run `sdbx integrate`; see the
[credential recovery procedure](operations.md#authentication-operations).
Do not put replacement passwords in Docker arguments.

## Permission or path failure

Inspect SDBX intent before changing ownership:

```bash
sdbx config get puid
sdbx config get pgid
sdbx config get config_path
sdbx config get data_path
sdbx config get downloads_path
sdbx config get media_path
sdbx config get secrets_path
sdbx doctor
```

SDBX rejects symlinked managed roots and requires the configured roots to be
directories writable by the project owner. Check the exact path and its
ancestors with normal Linux inspection tools, then repair only the specific
owner or mode reported by `doctor`.

Do not apply recursive `chown` or `chmod` to an entire media tree as a generic
fix. That can destroy ACLs, shared-group policy, hard-link behavior, or access
expected by another service. Back up metadata and understand the storage
policy before any recursive change.

## Generated *arr authentication is inconsistent

The doctor reports this when an enabled *arr application has an API key or
authentication setting that would reject supported integrations.

```bash
sdbx generate
sdbx restart SERVICE
sdbx doctor
```

`generate` preserves existing API keys and repairs SDBX-managed authentication
settings. Restart only the applications named by the diagnostic.

## Update failed

`sdbx update` starts only from a verified baseline, resolves new image digests,
regenerates runtime, pulls, converges, and checks services in dependency order.

If a stage fails and rollback succeeds, the error ends with:

```text
previous locked stack restored
```

Verify the restored state:

```bash
sdbx lock verify
sdbx status
sdbx doctor
```

If the error says automatic rollback also failed, stop making changes. Preserve
the project, `.sdbx.lock`, and logs, verify that encrypted backups are
available, and investigate the named rollback stage before attempting another
update.

## Interrupted initialization

The next non-dry-run `sdbx init` detects and recovers an interrupted initializer
transaction before proceeding. A dry run intentionally refuses recovery
because recovery writes project state.

If an existing project is detected in non-interactive mode, use `--force` only
after reviewing a complete `--dry-run` regeneration plan.

## Reporting a bug or vulnerability

For a normal defect, follow the repository bug-report template and include:

- `sdbx version`;
- Linux distribution and architecture;
- Docker Engine and Compose versions;
- the failing command and exit status;
- redacted `status` and `doctor` output;
- the smallest relevant redacted log excerpt.

Security vulnerabilities do not belong in public issues. Follow
[SECURITY.md](../SECURITY.md) for private reporting.
