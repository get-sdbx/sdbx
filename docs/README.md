# SDBX documentation

These documents describe the public `v1.0.0-RC2` product contract. Executable
CLI help, the embedded catalog, generated references, and tests remain the
source of truth when prose disagrees.

## Install and start

- [Installation](installation.md) — signed binaries, source builds, systemd
  services, remote Dashboard, and local recovery access.
- [Getting started](getting-started.md) — initialize and verify the first
  project after the binaries are installed.
- [Compatibility](compatibility.md) — supported hosts, required tooling,
  routing modes, filesystems, and RC2 evidence boundaries.

## Operate

- [Operations](operations.md) — lifecycle, configuration, integrations,
  diagnostics, authentication, VPN, and incident-safe evidence.
- [Backup and restore](backup-restore.md) — encrypted recovery, credential
  custody, exclusions, and restore drills.
- [Updates and rollback](upgrade.md) — previewed binary and image updates,
  application-state precautions, and rollback.
- [Troubleshooting](troubleshooting.md) — symptom-based investigation and
  bounded remediation.
- [Addons and presets](addons.md) — inspect, enable, disable, and operate
  optional services.

## Understand and extend

- [Architecture](architecture.md) — trust boundaries, locking, generation,
  routing, integrations, management, and recovery.
- [Threat model](threat-model.md) — protected assets, actors, abuse cases,
  controls, and residual risks.
- [External sources](external-sources.md) — immutable signed commits,
  registry allowlists, permissions, and cache promotion.
- [Service catalog authoring](../services/README.md) — validated definition
  schema and admission rules.
- [Security policy](../SECURITY.md)
- [Support](../SUPPORT.md)
- [Contributing](../CONTRIBUTING.md)

## Generated reference

- [CLI](reference/cli.md)
- [Configuration](configuration.md)
- [Services](reference/services.md)
- [Presets](reference/presets.md)

## Publication rules

- Use synthetic `.example.test` domains and synthetic credentials.
- Never publish real host paths, domains, IPs, account identifiers, tokens,
  media metadata, production screenshots, run IDs, recovery hashes, or raw
  acceptance evidence.
- Keep maintainer ledgers, work notes, release checklists, and test artifacts
  outside the public Git history.
- Run `make docs` after executable metadata changes and `make docs-check`
  before review.
