# Contributing to SDBX

SDBX accepts bug fixes, security hardening, tests, documentation, service
definitions, and focused product improvements. Public development happens
through GitHub issues and pull requests after the repository cutover.

Do not put vulnerabilities, credentials, private infrastructure identifiers,
personal media data, or unredacted deployment output in a public issue or pull
request. Follow [SECURITY.md](SECURITY.md) for private vulnerability reports.

## Expectations

- Keep changes focused and explain the user-visible outcome.
- Prefer simple, explicit components over generic privileged machinery.
- Preserve reproducibility: project intent, catalog definitions, locks, and
  generated runtime have separate ownership.
- Treat Docker access, the broker, host paths, external catalogs, route
  authentication, secrets, and backups as security boundaries.
- Use English for code, comments, commit messages, and documentation.
- Use synthetic examples such as `media.example.test`; never copy real
  deployment data into fixtures or screenshots.
- Be respectful and constructive in technical discussion.

## Development environment

Required for the full local gate:

- Go 1.26.5 or newer;
- Git and Make;
- Docker Engine 24.0 or newer;
- Docker Compose plugin 2.20 or newer.

The Makefile downloads and executes pinned `goimports`, `golangci-lint`, and
other Go-based quality tools with `go run`; do not install arbitrary global
versions to satisfy the gate. The first run therefore requires module-download
network access.

SDBX v1 first-class deployment support targets Linux amd64. Linux arm64
remains a compatibility build and must keep its archive, installer, binary
metadata, and image-manifest checks green. CLI-only development can happen on
macOS, but platform-dependent supported behavior must be verified on Linux
amd64 before merge.

Fork the public repository, then clone your fork:

```bash
git clone https://github.com/YOUR_ACCOUNT/SDBX.git
cd SDBX
git remote add upstream https://github.com/get-sdbx/sdbx.git
git switch -c fix/short-description
```

Download the pinned module graph and build both binaries:

```bash
go mod download
go mod verify
make build

./bin/sdbx --help
./bin/sdbxd -version
```

Do not use `go get -u ./...` as setup. Dependency upgrades are intentional,
reviewed changes with their own compatibility and security evidence.

## Understand the boundaries before editing

The main execution paths are:

- `cmd/sdbx/cmd/` — Cobra CLI contracts and operator workflows;
- `internal/config/` and `internal/settings/` — project intent and typed
  mutations;
- `internal/registry/` plus `services/` — embedded catalog, strict validation,
  graph resolution, external source trust, and lock provenance;
- `internal/generator/` — deterministic Compose and policy generation;
- `internal/docker/`, `internal/doctor/`, `internal/vpn/`, and
  `internal/integrate/` — day-two operations;
- `cmd/sdbxd/`, `internal/broker/`, and `internal/management/` — the typed
  privileged management boundary;
- `internal/webui/` — the authenticated host Dashboard and static UI.

Read [docs/architecture.md](docs/architecture.md) and
[SECURITY.md](SECURITY.md) before changing a trust boundary. Service-definition
work starts with [services/README.md](services/README.md).

## Make the change

1. Reproduce the behavior or state the invariant being added.
2. Add a focused failing test when practical.
3. Implement the smallest complete change.
4. Update command help and documentation in the same pull request.
5. Run targeted tests while iterating.
6. Run the full applicable gate before opening the pull request.
7. Review the final diff for unrelated edits, generated files, credentials, and
   private URLs.

Go code must be formatted with `gofmt`; `make fmt` also runs the repository's
pinned `goimports` version. Keep functions cohesive, propagate context through
blocking operations, bound untrusted input and output, and return errors with
actionable context.

Do not edit generated project files to change behavior. Change the generator,
schema, or source of project intent and assert the generated result in tests.

## Test locally

Run the tests closest to the change first:

```bash
go test ./cmd/sdbx/cmd/...
go test ./internal/registry/... ./internal/generator/...
go test ./internal/broker/... ./internal/management/...
go test ./internal/webui/...
```

Before submission, run the complete local candidate gate plus the race suite:

```bash
make ci
go test -race ./...
git diff --check
```

`make ci` already covers formatting, generated documentation, licenses, module
integrity, Vet, lint, ordinary tests, security scanners, workflow/shell safety,
builds, and release validation. The six exposure/routing Compose profiles are
a required GitHub Actions matrix; when generation, routing, networks, secrets,
or service definitions change, run the equivalent focused Compose fixtures
locally and verify the complete matrix on the pull request.

There is no arbitrary coverage percentage that makes a change acceptable.
Tests must cover the changed behavior, error paths, and relevant security
invariants. Do not weaken a test or linter to make a change pass.

### Security-sensitive changes

A pull request that touches root or Docker access, the broker API, source
verification, paths, secrets, authentication, routing, networking, backup
restore, update rollback, or subprocess execution must include:

- the attacker or failure case considered;
- the boundary that rejects it;
- a regression test for both allowed and denied behavior;
- redaction and size-limit checks where external data is handled;
- rollback or recovery behavior where state changes.

Never introduce:

- a raw Docker-socket mount or consumer in any container; Docker operations
  remain confined to the host CLI and typed `sdbxd` broker;
- an arbitrary command, path, mount, container-exec, or Docker API broker
  primitive;
- plaintext credentials in command arguments, Compose environment, logs, JSON,
  screenshots, or fixtures;
- mutable external catalog refs or unpinned release images;
- plaintext backups or silent destructive cleanup.

### UI changes

Public-facing UI work must be checked at desktop and mobile widths with:

- keyboard-only navigation and visible focus;
- screen-reader names and status announcements;
- reduced-motion behavior;
- loading, empty, offline, degraded, success, validation, and error states;
- a clean browser console.

Use synthetic data. Store Playwright screenshots and traces only under the
ignored `output/playwright/` directory.

### Documentation changes

Verify examples against `--help` and the current implementation. Prefer links
to the generated [CLI reference](docs/reference/cli.md) over duplicating long
flag lists, then run `make docs-check`.
Do not claim an installer, release artifact, support channel, platform, service,
security property, or deployment mode that is not tested and available.

## Service catalog changes

The official catalog is embedded in the native binary. Add or change a
definition under `services/core/NAME/service.yaml` or
`services/addons/NAME/service.yaml`, then:

```bash
go test ./internal/registry/... ./internal/generator/...
make build
./bin/sdbx addon list --all
```

Update inventory assertions when a service is intentionally added or retired.
Every route needs explicit authentication ownership and an explicit trust-zone
network. Dangerous permissions, registries, dependencies, secrets, and
templates are validated; do not bypass those checks. See
[services/README.md](services/README.md) for the schema and review checklist.

## Commits and pull requests

Use a concise imperative subject that describes the outcome. Conventional
Commit prefixes are welcome but not required. Do not add generated build
artifacts or `Co-Authored-By` trailers.

Keep your branch current before review:

```bash
git fetch upstream
git rebase upstream/main
git push --force-with-lease origin HEAD
```

`--force-with-lease` is appropriate only for your own pull-request branch after
a rebase. Never rewrite shared branches.

The pull request template asks for:

- outcome and intentional scope;
- related issue;
- security and trust-boundary impact;
- exact validation commands and manual checks;
- documentation, migration, rollback, and website impact;
- synthetic screenshots or evidence for UI work.

Automated checks and maintainer review must pass before merge. A maintainer may
request a smaller pull request, additional platform evidence, threat analysis,
or an independent security review.

## Report issues

Search existing issues and use the matching GitHub issue template. A useful bug
report includes:

- SDBX version or commit;
- Linux distribution and architecture;
- Docker Engine and Compose versions;
- exposure mode and routing strategy;
- minimal reproduction;
- expected and actual behavior;
- relevant redacted `sdbx --json doctor` checks and service logs.

Questions that reveal a documentation gap are valid issues. Security reports
must use the private process in [SECURITY.md](SECURITY.md), never a public issue.
