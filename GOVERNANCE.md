# Governance

SDBX uses a maintainer-led governance model. The repository owner is the
project lead until maintainership is explicitly delegated in the repository.

## Principles

Decisions prioritize:

1. user and host security;
2. feature truth and reproducibility;
3. simple, maintainable architecture;
4. accessibility and operator experience;
5. compatibility backed by tests;
6. sustainable maintainer workload.

Popularity is not sufficient reason to weaken a trust boundary, add a
privileged escape hatch, or publish an unverified release claim.

## Roles

### Contributors

Anyone may report defects, propose changes, improve documentation, or submit a
pull request under the contribution and conduct policies.

### Reviewers

Reviewers provide technical feedback. Review activity alone does not grant
merge, release, security-advisory, signing-key, or infrastructure authority.

### Maintainers

Maintainers may triage issues, review and merge changes, and apply labels.
Their scope is recorded through repository permissions and `CODEOWNERS`.

### Project lead

The project lead has final authority over:

- security and trust-boundary changes;
- public API, configuration, lock, and catalog contracts;
- supported platforms and deprecations;
- maintainer appointments and removal;
- release approval and signing;
- repository visibility and infrastructure.

The lead must not bypass required checks merely to meet a date.

## Decision process

Small fixes proceed through a focused issue or pull request with tests and
review.

Changes to architecture, security boundaries, configuration or lock schemas,
external-source trust, CLI compatibility, release supply chain, governance, or
supported platforms require:

1. a written problem and threat/compatibility impact;
2. alternatives and trade-offs;
3. an implementation and migration plan;
4. tests and documentation;
5. explicit maintainer approval.

When maintainers disagree, record the unresolved facts and trade-offs. The
project lead decides after the review window or defers the change. Silence is
not approval for a breaking or security-sensitive change.

## Merge requirements

A change may merge only when:

- scope and ownership are clear;
- required review and maintainer approval are complete;
- mandatory CI is green;
- security, privacy, and compatibility effects are addressed;
- user-facing behavior and documentation agree;
- generated artifacts show no unexplained drift;
- commits contain no secrets, production data, or co-author trailers added by
  automation.

Maintainers may require an independent security or UI review beyond normal
code ownership.

## Releases

Only the project lead or an explicitly delegated release maintainer may create
a public release. Release authorization does not imply permission to make the
repository public, rotate keys, deploy the website, or archive another
repository unless those actions are separately approved.

The maintainer release process is intentionally not part of the public product
documentation. A release with a known failed mandatory gate is not permitted.

## Security decisions

Vulnerability details stay private until coordinated disclosure and follow the
process in [SECURITY.md](SECURITY.md). No maintainer may promise a disclosure
date, CVE, bounty, or compensation without authority to deliver it.

## Maintainer changes

New maintainers are appointed by the project lead based on sustained,
security-conscious contributions and reliable review. Access should follow
least privilege and be reviewed periodically.

A maintainer may step down at any time. Access may be removed for inactivity,
security risk, repeated policy violations, or conduct violations. Sensitive
access and credentials must be revoked promptly when a role changes.

## Amendments

Governance changes use the same public review process as other
security-sensitive project changes and require project-lead approval.
