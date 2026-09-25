# Backup and restore

SDBX recovery archives are always authenticated age-encrypted and end in
`.tar.gz.age`. There is no plaintext mode.

Backup creation first verifies that `.sdbx.yaml`, `.sdbx.lock`, and every
lock-recorded generated runtime file still agree. It refuses a missing, stale,
or locally modified runtime instead of preserving an unexplained state as a
trusted recovery point.

## What is covered

An archive may contain:

- `.sdbx.yaml` and `.sdbx.lock` as restore-compatibility evidence;
- `compose.yaml` and the private generated `.env` as recovery evidence that is
  never promoted over the verified target runtime;
- the configured `configs` root;
- the configured `secrets` root;
- encrypted metadata describing the backup.

Before writing archive data, SDBX walks both managed roots without following
symlinks. A relative symlink is accepted only when its target is a regular
file inside the same managed root. The link itself is omitted, as are
ephemeral Unix sockets. Every omission is recorded by path, type, and reason
inside the encrypted metadata and is reported after creation in both human
and JSON output. Absolute, external, broken, and directory-target symlinks
remain fatal, as do FIFOs, devices, and every other special file.

An omitted link or socket is intentionally not a recovery object. Applications
must recreate their log links and runtime sockets after restore; SDBX never
recreates them from omission metadata.

It does not contain any part of the configured `data_path`, media, downloads,
or arbitrary external Docker volumes. This excludes application databases and
state, including Authelia's SQLite database, TOTP enrollments, and filesystem
notifications under `data_path/authelia`. The SDBX archive alone cannot restore
the identity state needed to satisfy `two_factor`. Back up `data_path` and
other stateful stores with an application-consistent procedure, keep that
snapshot bound to the encrypted SDBX archive, and prove both in the same
recovery drill.

## Choose a credential model

### Recipient mode

Recipient mode is preferred for automation:

```bash
sdbx backup --recipient age1...
```

SDBX needs only the public recipient and never stores its private identity.
Keep the identity off-host, private, tested, and available to the people
responsible for recovery.

### Passphrase mode

For an attended backup:

```bash
sdbx backup
```

The terminal prompts twice without echo. For non-interactive use, a passphrase
file must be a regular file with mode `0600` or stricter:

```bash
sdbx backup --passphrase-file /secure/backup-passphrase
```

SDBX does not store the passphrase. Losing it makes the archive intentionally
unrecoverable. Do not place it in shell history, environment variables,
project configuration, CI logs, or the backup directory.

## Verify custody

List filesystem-visible backups:

```bash
sdbx backup list
```

Listing does not decrypt metadata. It reports the filename, file size, and
filesystem modification time without requiring the identity or passphrase.

For every recovery point:

1. copy the encrypted archive to separate storage;
2. preserve the identity or passphrase separately;
3. record which project and application snapshots belong to it outside the
   archive;
4. verify file size and storage integrity;
5. run a restore drill on a separate host or snapshot.

An encrypted archive on the same disk is not a disaster-recovery copy.

## Restore preflight

Restore overwrites compatible application configuration and secrets. It never
replaces the target's project intent, lock, generated runtime, or policy.
Before continuing:

- identify the exact target project and archive;
- take a host or filesystem snapshot when available;
- create a new encrypted backup of the current project;
- stop the Compose stack so applications do not write configuration while it
  is being replaced;
- preserve the current SDBX binaries and lock;
- confirm the age identity or passphrase works in a separate drill.

```bash
sdbx backup --recipient age1...
sdbx down
sdbx backup list
```

Do not restore into an unrelated project merely because the archive filename
looks familiar. The archive metadata is encrypted and the CLI does not expose
a content-preview command.

## Restore with an identity

The identity file must be a private regular file:

```bash
sdbx backup restore BACKUP_NAME \
  --identity-file /secure/age-identity.txt \
  --confirm restore
```

## Restore with a passphrase

Attended:

```bash
sdbx backup restore BACKUP_NAME --confirm restore
```

Non-interactive:

```bash
sdbx backup restore BACKUP_NAME \
  --passphrase-file /secure/backup-passphrase \
  --confirm restore
```

Identity and passphrase-file options are mutually exclusive. JSON or
non-terminal operation requires an explicit credential file.

## What restore validates

Before the first managed target is promoted, SDBX decrypts and validates the
complete archive, decrypts it a second time into private root-scoped staging
areas, and revalidates every header and byte limit. It
rejects:

- invalid age authentication or compression;
- unsupported backup metadata;
- traversal, absolute, noncanonical, control-character, or backslash paths;
- entries outside the project/config/secrets allowlist;
- duplicate names, symlinks, devices, sockets, and other special files;
- group/world-writable, unreadable, or special permission modes;
- more than 200,000 entries;
- a file larger than 8 GiB;
- more than 64 GiB of declared restored file data.

Project intent and `.env` are capped at 1 MiB each; the lock and Compose file
are capped at 16 MiB each. Archive paths are capped individually and
collectively so the restore journal remains bounded.

Promotion uses fixed `os.Root` handles and same-filesystem stage/rollback
areas. SDBX syncs a durable event journal before each target mutation. A normal
failure, cancellation, or restored-project verification error rolls back the
complete managed set. If the process or host stops mid-restore, the next
restore recovers the interrupted transaction before reading project intent.

Existing file owners are preserved. Files and directories created by a root
broker inherit the nearest real destination-parent owner. Secrets and `.env`
are restored with mode `0600`; secret directories use `0700`.
Before the next `sdbx up`, SDBX reapplies service-required ownership and
normalizes the service-mounted Authelia, Cloudflared, Cobalt, Unpackerr, and
Traefik console files to mode `0644` inside that private directory. See the
[secret permission boundary](getting-started.md#5-add-provider-owned-credentials)
for the affected files. The host-only console server certificate and key remain
mode `0600`.

The archive's project intent and lock are compatibility evidence only. SDBX
compares them with the already verified target before promotion, but never
uses archive-supplied generated files or archive-supplied digests to authorize
runtime. The target lock and generated runtime are revalidated while the
transaction is still reversible. A mismatch fails the command and restores
the original application state.

## Cross-host custom-root relocation

The default state restore requires archived intent to match the target exactly,
including `config_path` and `secrets_path`. All project control-plane files are
preserved even when those fields match.

Use explicit state relocation on a separately initialized target when only
those two managed roots differ:

1. install the same SDBX CLI release on the destination;
2. initialize and verify a target project whose intent is identical except for
   `config_path` and `secrets_path`;
3. ensure its locked sources, definitions, image digests, platforms, and
   install order match the source project exactly;
4. stop the target stack and take a snapshot;
5. copy the encrypted archive into the target project's `backups` directory;
6. run:

```bash
sdbx backup restore BACKUP_NAME \
  --identity-file /secure/age-identity.txt \
  --relocate-managed-roots \
  --confirm restore
```

`--relocate-managed-roots` rejects any intent difference beyond `config_path`
and `secrets_path`, and rejects a different locked service graph. As in default
mode, it keeps the target `.sdbx.yaml`, `.sdbx.lock`, `compose.yaml`, `.env`,
and lock-covered generated policy files. It restores compatible application
configuration and secrets into the target's current roots as one transaction.

Neither mode translates application-internal absolute paths or promises data
compatibility between different application versions. A rejected compatibility
check is a stop condition, not a reason to overwrite the target lock.

## Important limitations

SDBX restore does not roll back application database schema migrations or
restore media, downloads, or external volumes.

## Validate the restored project

Do not start services immediately after the restore command:

```bash
sdbx lock verify
sdbx status
```

Review the preserved `.sdbx.yaml` paths, exposure mode, domain, provider files,
DNS, and host ports for the target host. If archived intent or locking does not
match, review the source project and initialize a compatible target; do not
overwrite the target lock to force state into a different service graph.
At this offline checkpoint, `sdbx status` should show the stack stopped.
`sdbx doctor` is intentionally deferred because its service checks require a
running stack and would report expected stopped or absent containers as
failures.

When the checks and application-specific data restore are complete:

```bash
sdbx up
sdbx status
sdbx doctor
```

For VPN-enabled deployments, also run `sdbx vpn status` before resuming
download automation.

## Delete an archive

Deletion is irreversible and requires exact confirmation:

```bash
sdbx backup delete BACKUP_NAME --confirm delete
```

First verify another usable off-host recovery copy and credential exist.
Deletion removes only the selected regular archive in the project's `backups`
directory.

## Restore drill acceptance

A recovery point is not accepted until a separate drill proves:

- decryption using the preserved credential;
- project and lock verification;
- correct custom root mapping;
- service startup and health;
- route authentication and native administrator access;
- VPN protection where configured;
- application-specific data consistency;
- no unexpected secret, token, or ownership exposure.
