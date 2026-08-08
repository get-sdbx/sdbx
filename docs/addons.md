# Addons and Presets

Addons are optional service definitions in the embedded catalog or an
explicitly configured external source. SDBX derives enabled services from
`.sdbx.yaml`, resolves dependencies, updates the lock, and regenerates runtime
files when addon state changes.

Do not use a documentation table as catalog truth. Inspect the binary you are
running:

```bash
sdbx addon list --all
sdbx preset list
```

Machine-readable inventory is available for automation:

```bash
sdbx --json addon list --all
sdbx --json preset list
```

## Inspect an addon

Search by name, description, or category:

```bash
sdbx addon search media
sdbx addon search --category utility
sdbx addon info NAME
```

`addon info` reports definition version, source, image tag input, route,
authentication ownership, and whether the addon is enabled. Runtime images are
resolved to immutable digests in `.sdbx.lock`; the displayed tag is catalog
intent, not proof of the deployed digest.

Before enabling a third-party definition, inspect its source, registries,
permissions, networks, mounts, devices, capabilities, secrets, authentication
mode, and update policy. A higher-priority source can replace an embedded name
only with a complete service definition and the exact declared/granted
`service-override:NAME` permission.

## v1 service notes

The generated [service reference](reference/services.md) is the complete
inventory. These notes cover addons whose first-run or integration behavior
needs operator context.

### Calibre-Web

Calibre-Web mounts `media_path/books` at `/books` and preserves the selected
LinuxServer.io image's upstream first-login behavior. On a new database, sign
in with the documented `admin` / `admin123` default, change it immediately,
then select the Calibre database stored under `/books`.

SDBX places the route behind its `admin-only` Authelia boundary, but the
application credential is still a separate control. SDBX does not rewrite it,
and the optional x86-only full-Calibre Docker mod is deliberately not enabled
so the baseline remains portable to amd64 and arm64. See the
[LinuxServer.io Calibre-Web image documentation](https://docs.linuxserver.io/images/docker-calibre-web/).

### pyLoad

pyLoad mounts the shared downloads root at `/downloads` and preserves the
selected LinuxServer.io image's upstream first-login behavior. On a new
database, sign in with the documented `pyload` / `pyload` default and change
it immediately.

The Web UI is behind the SDBX `admin-only` boundary. The optional Click'n'Load
port is not published by v1; enabling a second host-facing protocol needs its
own reviewed route and authentication contract. See the
[LinuxServer.io pyLoad-ng image documentation](https://docs.linuxserver.io/images/docker-pyload-ng/).

### Cobalt

The official addon is the Cobalt API, not a second copy of the cobalt.tools
frontend. SDBX generates a rate-limited UUIDv4 API key map and serves the API
on the addon route. Recover the client key from a private terminal:

```bash
sdbx secrets show cobalt --confirm reveal
```

Open [cobalt.tools instance settings](https://cobalt.tools/settings/instances),
add the HTTPS URL reported by `sdbx open cobalt`, and paste the recovered key.
The public frontend then uses the self-hosted API. SDBX does not maintain an
upstream fork or claim that the API container includes a native browser UI.

### Whisparr v3 and Unpackerr

Whisparr is pinned to the selected publisher's `v3` stable line. SDBX manages
its Forms credential like the other supported Arr applications and connects
it to Prowlarr and qBittorrent during `sdbx integrate`.

Unpackerr is an internal worker with no browser route. During generation, SDBX
derives enabled Sonarr, Radarr, Lidarr, and Whisparr URLs from the verified
graph, copies only their API keys into file-backed container secrets, and
writes a non-secret environment file. Disabling an Arr integration truncates
its derived secret copy; the source Arr configuration remains untouched.

### Notifiarr and Tdarr

Notifiarr keeps a low-friction Web UI and persistent config directory. The
default contract supports application notifications, webhooks, and
service-level monitoring without a Docker socket, host filesystem mount, or
privileged telemetry. Features that require raw Docker or host control are
outside the official baseline.

Tdarr ships with its internal CPU node enabled so it works on amd64 and arm64
without assuming a GPU device. This is a portable default, not a permanent
product ceiling. Hardware acceleration remains an explicit post-v1 host
capability because Intel, AMD, and NVIDIA devices need different mounts,
groups, drivers, Compose resources, and verification.

## Enable one addon

From a verified project:

```bash
sdbx addon enable NAME
sdbx lock verify
sdbx up
sdbx status
```

Enabling:

1. verifies the current project lock;
2. confirms the selected definition is an addon;
3. adds the name to project intent;
4. resolves an immutable image digest if the service is new;
5. regenerates runtime files and saves the updated lock.

`sdbx up` converges the new locked graph. Run `sdbx integrate --dry-run` after
the service is healthy to see whether supported credentials or connections
remain to be configured.

## Apply a preset

Presets are visible bundles of addon names. Media-server selection remains
separate; a preset does not silently enable Plex or Jellyfin.

Inspect before applying:

```bash
sdbx preset show NAME
sdbx preset apply NAME
sdbx lock verify
sdbx up
sdbx integrate --dry-run
```

Applying a preset is idempotent. Already-enabled addons are retained, missing
definitions are reported, and runtime regeneration happens once for the batch.
If regeneration fails, the in-memory addon selection is rolled back and the
command returns nonzero; inspect project and lock state before retrying.

Operators can define local preset overlays in
`~/.config/sdbx/presets.yaml`. A matching name replaces the embedded preset for
that user. Review local presets like code because they can select any available
external definition.

## Disable an addon

Preview operational impact from its details and current status, then:

```bash
sdbx addon disable NAME
sdbx lock verify
sdbx up
sdbx status
```

`sdbx up` uses Compose orphan removal to retire the removed container while
converging the remaining graph. Disabling an addon does not delete its
configuration, database, downloads, media, or external volumes.

SDBX intentionally has no generic purge command. Before manually deleting
retained state:

- create and verify an encrypted SDBX backup;
- identify every configured path and Docker volume used by that service;
- confirm no remaining service shares the data;
- follow the upstream application's export or migration procedure.

Data deletion is outside the addon-disable operation and may be irreversible.

## Change several addons

Prefer a preset when it represents the desired stack. If several independent
changes are needed, apply them one at a time and review the lock after each, or
edit the `addons` list in `.sdbx.yaml`, inspect `sdbx lock diff`, and explicitly
run:

```bash
sdbx lock
sdbx lock verify
sdbx up
```

Manual intent changes use `sdbx lock`, not `sdbx generate`, because the config
digest and active service graph changed.

## Author or distribute an addon

Official catalog changes live under `services/addons/NAME/service.yaml` and are
embedded at build time. Third-party catalogs must be immutable signed Git
sources with explicit permission and registry grants.

See [services/README.md](../services/README.md) for the strict schema, route
authentication modes, trust-zone networks, permission model, test commands, and
external source requirements.
