# Threat model

This document describes the security boundary SDBX v1 is designed to provide.
It is not a claim that third-party media applications, container images, the
Linux host, or the Docker daemon are free of vulnerabilities.

## Protected assets

SDBX must protect:

- the Linux host and every path mounted into a container;
- Docker control and the active Compose graph;
- project intent, locks, generated policy, and service configuration;
- VPN, Authelia, tunnel, claim, API, session, and backup credentials;
- media and download metadata;
- route authentication and TLS policy;
- encrypted backup availability and integrity;
- broker authorization and audit evidence.

Availability matters alongside confidentiality and integrity. A malicious
catalog, crafted archive, unbounded response, bad update, or compromised
management client must not receive an easy path to exhaust or overwrite the
host.

## Actors

The model distinguishes:

- an unauthenticated network client;
- an authenticated application user;
- an Authelia user without `sdbx-admin`;
- an authorized SDBX administrator;
- a local user without Docker or SDBX management-group access;
- a local user with the broker static token;
- a Docker administrator or root;
- a compromised browser-facing `sdbx serve` process;
- a compromised application container;
- a malicious external catalog author;
- a compromised upstream image registry or mutable image tag;
- an attacker supplying a crafted backup archive.

Root and Docker administrators are trusted host principals. SDBX limits
accidental and cross-boundary behavior but does not attempt to contain an
already malicious root account or Docker daemon.

## Trust boundaries

### Host and Docker

Docker control is root-equivalent. The CLI account and `sdbxd` can affect all
containers and mounted host paths. Do not expose the Docker socket over TCP.

Official containers receive neither the raw Docker socket nor a Docker API
proxy. Traefik consumes generated file-provider routes. Catalog validation
rejects Docker-socket paths both before and after template rendering. The host
CLI and `sdbxd` still operate Docker as trusted, root-equivalent principals.

### Internet, Traefik, and routed applications

Traefik is the edge boundary. Every routed definition must declare one
authentication owner:

- `admin-only` or `protected`: Traefik invokes Authelia ForwardAuth;
- `native-auth`: the application owns login and account security;
- `public`: the route intentionally has no user authentication.

SDBX does not silently layer Authelia over native-auth applications. Their
administrator accounts must be secured before exposure. Authelia rules use the
typed `auth.factor` setting, which defaults to `one_factor` for enrollment and
can regenerate the complete ForwardAuth boundary as `two_factor`.

The Authelia session cookie is domain-scoped so ForwardAuth can protect
multiple hosts. Consequently, every routed application covered by that domain
is a cookie-bearing trust principal: its server receives browser cookies for
the host even though the session cookie is `HttpOnly`. Traefik cannot
selectively strip only the Authelia request cookie while preserving each
application's own session cookies. External catalogs must declare and receive
an exact `route:AUTH-MODE` grant, but that grant is an explicit trust decision,
not isolation from a malicious application image.

Sonarr, Radarr, Lidarr, Prowlarr, and Whisparr are not classified as
`native-auth`: they remain `admin-only` routes and intentionally add an
application-native Forms boundary.
The SDBX-managed credential blocks anonymous lateral access from Docker peers,
while service integrations authenticate with per-application API keys.

LAN and direct modes publish host ports 80 and 443 and redirect HTTP to HTTPS.
Direct mode supports ACME in v1. Cloudflare Tunnel avoids host-published
Traefik ingress but introduces Cloudflare as a confidentiality, availability,
and routing dependency. SDBX uses the remote-managed tunnel model: the
connector token can attach a replica to the tunnel but does not authorize SDBX
to inspect or mutate Cloudflare's Published application routes. Operators must
reconcile the exact `sdbx tunnel routes` output in that separate control plane.
`sdbx doctor` proves Cloudflare-edge reachability and rejects common catch-all
or upstream failures; it cannot prove that a successful response came from the
intended SDBX origin.

### Network zones

Generated Compose uses separate edge, application, download, and management
networks. Segmentation limits default reachability; it is not a security
boundary against Docker administrators or a container with granted host
networking, a device, or a powerful capability.

When VPN protection is enabled, qBittorrent shares Gluetun's network namespace.
It does not receive an independent application-network path. `sdbx vpn status`
compares host and tunnel egress, but the VPN provider, tunnel protocol, DNS,
and upstream image remain dependencies.

### Management plane

`sdbx serve`:

- permits remote binding only with its server certificate, trusted client CA,
  and canonical public-host configuration;
- has no direct Docker or project-file operator;
- serves no credential or management data to an unauthenticated HTTP client;
- requires a verified Traefik client certificate plus an Authelia `admins`
  identity, or a distinct out-of-band local browser token, on every management
  API call;
- exposes the packaged HTTP recovery listener only on loopback, independently
  from the TLS-only remote listener;
- enforces Host and mutation-Origin checks, CSP, framing, referrer,
  permissions, and content-type controls;
- calls only the typed versioned API over a Unix socket.

`sdbxd`:

- must run as root;
- registers exactly one absolute project;
- verifies project intent, lock schema, active graph, and generated-file
  digests before privileged mutations;
- exposes no arbitrary command, Docker API, mount, path, or container-exec
  primitive;
- bounds request, response, log, audit, and execution time;
- requires exact confirmations for typed mutations;
- records start and completion audit events for mutations.

The static broker token is an administrator credential. It supplies the
`sdbx-admin` group and a fresh authentication time for every accepted request.
Anyone who can read it and reach the socket can invoke all supported typed
mutations. The bundled Web console uses that token only for its broker hop.
A distinct group-protected browser token authenticates local HTTP clients and
is delivered through the fragment URL printed by `sdbx console`. Optional OIDC
support is for direct broker clients. Remote Web authentication is handled by
the generated Authelia ForwardAuth policy; mTLS prevents a client from forging
the copied identity headers directly to the backend.

The packaged systemd units store both tokens and the server-side proxy trust
material in `/run`. The matching internal CA and Traefik client material live
under `secrets_path` and are protected by the encrypted-recovery contract.

OIDC tokens are accepted only after issuer discovery and token verification.
Mutations require the `sdbx-admin` group. Addon, setting, restore, delete, and
stack changes also require an `auth_time` no older than ten minutes.

The audit log is append-only through the running broker and is synced after
each record. It is not remotely anchored or cryptographically tamper-evident;
root can alter or remove it.

### Project and filesystem

`.sdbx.yaml` is operator intent. `.sdbx.lock` records catalog, definition,
platform, image, and generated-file provenance. Privileged operations refuse a
missing or stale lock and refuse modified lock-recorded runtime files.

Sensitive writes are atomic, permission-explicit, and reject symlinks or
special files at relevant boundaries. Relative managed paths may not escape
the project, and filesystem roots are rejected as managed targets.

The console daemon performs managed-file mutations as root. Setting, addon,
generation, encrypted-backup, and restore writes preserve the existing regular
file's owner or inherit the nearest real parent directory's owner. Direct
application-consumed configuration intentionally uses the configured
`PUID:PGID`. The same ownership contract therefore supports ordinary-user CLI
operation after a broker mutation without requiring a recursive ownership
repair.

### Catalog and supply chain

The official catalog and presets are embedded in both binaries. Runtime
operation does not require the retired private `SDBX-Services` repository.

External Git sources must:

- use HTTPS or SSH without embedded passwords;
- pin one exact 40- or 64-character commit;
- verify that commit's OpenPGP or SSH signature against one configured full
  fingerprint;
- declare every host-sensitive permission used by a definition;
- receive matching source-level permission grants;
- use only granted image registries.

Each Git refresh is time-, output-, object-, file-, and cache-bounded. It runs
in a private staging checkout, rejects symlinks and a dirty tree, and replaces
the active cache only after remote, commit, signer, and resource verification.
The previous verified checkout remains active if any gate fails.

The lock records source commit, signer, permissions, registries, and catalog
digest. Official first-run and newly enabled services use the release-reviewed
platform-specific OCI snapshot embedded in the binary. Explicit image updates
resolve authoring tags to newer digests and therefore cross a fresh upstream
supply-chain boundary. External-source images are outside the official
snapshot and use their configured registry resolver. The embedded source
identity includes the snapshot digest, preventing an image-pin change from
retaining the previous catalog provenance.

A valid signature identifies the configured signer; it does not prove that the
definition is safe. Broad grants such as `*`, `capability:*`, `secret:*`, or an
unreviewed registry wildcard deliberately weaken containment.

Local sources are developer inputs. They are neither signed nor equivalent to
a reproducible third-party release.

### Backups

Backups are authenticated age-encrypted with either a public recipient or a
passphrase. Plaintext archive bytes are streamed and are not persisted beside
the final archive.

Restore:

- requires the identity or passphrase and exact `restore` confirmation;
- validates the complete decrypted archive before writing;
- rejects traversal, noncanonical paths, duplicates, symlinks, special files,
  unsafe modes, unsupported metadata versions, and entries outside the
  allowlist;
- caps entries, per-file bytes, and total declared bytes;
- stages through fixed `os.Root` handles and revalidates the authenticated
  archive before promotion;
- journals each same-filesystem promotion and rolls the complete managed set
  back on failure;
- recovers an interrupted transaction before the next restore reads project
  intent;
- preserves existing owners and inherits the destination-parent owner for new
  managed paths created by root.

Every restore preserves the current target's independently verified intent,
lock, Compose, environment, and generated policy. Archive-supplied generated
files and their archive-supplied digests never authorize runtime. The reviewed
`--relocate-managed-roots` workflow permits only config and secret roots to
differ while restoring compatible application state. Follow the separate
restore runbook and keep a host snapshot because the complete `data_path`,
including Authelia identity and TOTP state, application databases, and
external volumes remain outside this transaction.

## Primary abuse cases and controls

| Abuse case | Primary controls | Residual risk |
| --- | --- | --- |
| Unauthenticated route access | Mandatory route-auth classification and route grant, duplicate-rule rejection, default-deny Authelia policy, TLS | Native/public route policy or upstream auth can be weak |
| Routed application steals a domain-scoped session cookie | Exact route permission/grant, signed and locked source, reviewed image digest | Every covered routed application remains trusted with browser cookies; v1 has no per-application cookie scrubber |
| Torrent traffic bypasses VPN | qBittorrent shares Gluetun namespace, explicit disable acknowledgement, live egress check | Provider or container compromise; operator misconfiguration |
| Browser client requests arbitrary root action | Typed broker API, one project, lock preflight, confirmations, bounds, audit | Static-token compromise grants every supported typed mutation |
| Malicious catalog mounts host or gains privilege | Exact permission derivation and declaration, source grants, registry allowlist, strict templates | A deliberately broad grant authorizes the requested power |
| Signed catalog exhausts local fetch resources | Private staging, fixed timeout/output/object/file/cache budgets, bounded Git process settings, atomic promotion | A hostile server can consume network bandwidth within the fixed time window |
| Mutable image changes unexpectedly | OCI digest lock and generated-file verification | A malicious image already approved at that digest remains malicious |
| Crafted backup escapes project or supplies a self-consistent privileged runtime | age authentication, two-pass validation, allowlisted paths, `os.Root`, bounded journal, complete-set rollback, verified target control plane always preserved | Root administrators and a compromised kernel remain trusted |
| Secret appears in logs or API errors | stable external errors, default log redaction at CLI/management/broker/Web boundaries, bounded responses, audit-field sanitization, canary tests, private files | Novel or unlabeled upstream formats may evade pattern redaction; operators must still review output |
| Compromised container emits hostile retained logs | tail cap, 2 MiB stdout/stderr writers, immediate Docker subprocess cancellation, response cap | Attended CLI follow mode intentionally streams until the operator cancels it |
| Compromised application reaches Docker | no container Docker API path; rendered socket mounts rejected | Host/Docker administrators and a compromised privileged broker remain trusted |
| Root edits audit history | synced append records and restrictive mode | No remote or cryptographic anchoring |

## Out of scope

SDBX v1 does not promise:

- containment of root, Docker administrators, or a compromised kernel;
- malware analysis of third-party images;
- anonymity from a VPN provider, indexer, application, or Cloudflare;
- protection of secrets from the service that consumes them;
- backup of media, downloads, or arbitrary Docker volumes;
- transactional rollback of application database migrations;
- safe use after the host, Docker daemon, broker token, or trusted Traefik
  client certificate is compromised;
- legal authorization for user-selected content or sources.

## Security verification

Before exposure:

```bash
sdbx lock verify
sdbx status
sdbx doctor
sdbx vpn status
```

Run the VPN command only for a VPN-enabled project. Review the generated
route/auth/network posture, create every native application administrator,
test required Authelia factors in a fresh session, preserve an encrypted
backup off-host, and inspect host firewall and DNS policy.

See the [Security Policy](../SECURITY.md) for private reporting and coordinated
handling.
