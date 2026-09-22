# Update and rollback

`v1.0.0-RC1` is the current published SDBX release candidate. RC2 acceptance is
still in progress; wait for its signed release before upgrading a deployed
RC1 project. The planned RC2 upgrade records the new Cloudflare Tunnel
transport binding in the lock diff, and its Plex GPU and private-listener
settings stay opt-in. There is no legacy configuration compatibility contract
beyond the documented RC1 upgrade path. Attach only the persistent paths you
have explicitly reviewed.

SDBX separates changes that have different rollback boundaries:

- replacing `sdbx` and `sdbxd` changes the controller version;
- `sdbx update` changes pinned container image digests;
- changing project intent or addons changes the resolved lock and generated
  runtime;
- third-party applications may migrate their own databases when a new image
  starts.

No SDBX command can guarantee rollback of an upstream application's database
schema. Preserve application-consistent state separately.

## Before any change

Record and verify the baseline:

```bash
sdbx version
sdbxd -version
sdbx lock verify
sdbx status
sdbx doctor
sdbx backup --recipient age1...
```

For VPN-enabled projects, also run `sdbx vpn status`. Copy the encrypted archive
off-host, keep its age identity separately, and capture snapshots for state that
the native backup excludes, including the configured `data_path`, media,
downloads, and external Docker volumes.

Preserve the matching binary pair, lock, generated runtime, exact release
checksums, image digests, and application-specific rollback instructions.

## Refresh container images

The default command is a non-mutating preview:

```bash
sdbx update
```

Review every repository and digest change plus the upstream release notes. To
apply the reviewed set:

```bash
sdbx update --apply --confirm apply-upstream-images
sdbx lock verify
sdbx status
sdbx doctor
```

SDBX verifies the current project, resolves platform-specific digests, writes
the candidate lock and runtime, pulls exact digests, converges services in
dependency order, and checks their health. If that sequence fails, it restores
the previous lock and runtime and reconverges the previous digests.

An error ending in `previous locked stack restored` means the automated
software-state rollback completed; verify it. If automatic rollback also
failed, stop changing the host and preserve the evidence.

## Change intent or addons

Prefer typed commands such as `sdbx addon enable`, `sdbx addon disable`, and
`sdbx config set`. For a reviewed manual `.sdbx.yaml` change:

```bash
sdbx lock diff
sdbx lock
sdbx lock verify
sdbx up
```

Review every source, definition, service, permission, route, image, platform,
and generated-file effect. Do not use `sdbx generate` to hide a stale lock; it
only reconstructs derived files when intent and lock already agree.

## Upgrade from RC1 to a later release

Use only the exact signed artifacts and version-specific release notes for the
target release. Replace `sdbx` and `sdbxd` as one pair; never mix versions.
Before accepting a new lock:

```bash
sdbx version
sdbxd -version
sdbx lock diff
```

A controller version change may change the locked deployment identity. Accept
the diff only when every change is documented by the target release. Then run:

```bash
sdbx lock
sdbx lock verify
sdbx up
sdbx restart traefik
```

Restarting Traefik briefly interrupts routed applications and reloads its
configuration and mounted console certificates. This also applies RC2's
certificate-permission repair to a proxy created by an earlier version.

Reload the enabled Arr services before checking health. Generation can update
their managed `config.xml` authentication settings or insert a missing API key,
while an already-running process keeps its previous in-memory configuration.
`sdbx up` does not guarantee a restart when only a bind-mounted file changes.
This can leave clients receiving `401 Unauthorized` until the services reload.

Use `sdbx status` to identify the enabled Arr services, then restart all of
them during the maintenance window. For example, a TV automation project may
enable Sonarr and Prowlarr; include Radarr, Lidarr, and Whisparr in the same
command when enabled. Skip the Arr restart when no Arr service is enabled:

```bash
sdbx status
sdbx restart sonarr prowlarr
sdbx integrate --dry-run
sdbx integrate
sdbx lock verify
sdbx status
sdbx doctor
```

The restart briefly interrupts those services. Wait for them to become ready
before integration. Use the dry-run to review planned changes; it does not
verify Arr native authentication. The real `sdbx integrate` pass must succeed:
it authenticates to each enabled Arr API, verifies or reconciles its managed
Forms credential, and applies the configured cross-service integrations. This
real pass is required even when no cross-service integration applies. Apply
the same reload procedure after any `sdbx lock` or `sdbx generate` operation
that changes managed Arr authentication files. SDBX preserves existing API
keys; this procedure does not call for rotating them.

When host services are installed:

```bash
sudo systemctl restart sdbxd.service sdbx-web.service
sudo systemctl status sdbxd.service sdbx-web.service
```

If the diff contains an unexpected registry, image, service, permission,
route, mount, or generated file, do not accept it. Restore the matching binary
pair and project snapshot.

## Roll back the controller

Rollback is valid only when the target release notes say the older controller
supports the current project schema and lock.

1. Stop `sdbx-web` and `sdbxd` if installed.
2. Preserve the failed state for diagnosis.
3. Restore the matching binary pair.
4. Restore the corresponding project snapshot if the newer release changed
   incompatible state.
5. Verify the lock, status, doctor, and VPN boundary before restarting host
   services.

Do not downgrade over an unexplained newer lock and regenerate it.

## Roll back application state

Automatic image rollback is not application-data rollback. If an upstream
container migrated its database incompatibly:

1. stop the affected stack;
2. preserve the failed state;
3. restore the application-consistent data snapshot;
4. restore the matching SDBX project, lock, and previous image digests;
5. follow the upstream application's supported rollback procedure;
6. start only after verifying compatibility.

Never delete a database, volume, download tree, or media tree merely to make an
older image start.

## Acceptance criteria

A change is complete only when:

- both binaries identify the intended release and commit;
- `sdbx lock verify`, `sdbx status`, and `sdbx doctor` pass;
- expected services and routes are healthy in fresh sessions;
- Sonarr, Radarr, Lidarr, Prowlarr, and Whisparr retain both Authelia and their
  SDBX-managed Forms credentials;
- native-auth applications retain their own administrators;
- VPN protection is proven where configured;
- the Dashboard retains its broker, mTLS, Authelia admin, Host, Origin, token,
  and loopback recovery boundaries;
- an off-host encrypted backup and its separate recovery credential exist.
