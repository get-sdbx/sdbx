# External source trust

Every official SDBX service and preset is embedded in the release binary.
External sources are optional extensions; they are not required for normal
operation and do not replace the official catalog.

Catalog definitions are executable deployment policy. A signed source can ask
for host mounts, devices, Linux capabilities, secrets, or powerful networking.
Treat source approval like code review.

## Minimum trust contract

A Git source must have:

- a lowercase unique name;
- an HTTPS, SSH, or SCP-style SSH URL without an embedded password;
- one exact 40- or 64-character commit hash;
- the full fingerprint of the expected OpenPGP or SSH signing key;
- an explicit image-registry allowlist;
- only the catalog permissions needed by its definitions.

Branches, tags, abbreviated commits, unsigned commits, unexpected signers, and
credential-bearing URLs are rejected.

`sources.yaml` is parsed as security policy, not permissive application
configuration. Unknown fields, multiple YAML documents, incorrect API or kind
identities, unsupported future versions, duplicate/reserved source names,
invalid sources even when disabled, and non-positive cache TTLs fail closed.
Commands do not replace or rewrite the existing file when those checks fail.

New sources receive no image-registry grant by default. Every
`--allow-registry` value is an explicit trust decision; without one, the source
can be added and inspected but none of its container images can enter a valid
resolution or lock. `sdbx source add` prints the exact URL, commit, signer,
registries, and catalog permissions before persisting the source.

## Review before adding

Independently obtain and verify:

1. repository ownership and maintainer identity;
2. the intended commit hash from a trusted channel;
3. the signing fingerprint from a separate trusted channel;
4. the complete commit diff and every `service.yaml`;
5. image registries, repositories, tags, and upstream ownership;
6. route authentication ownership and published ports;
7. mounts, devices, capabilities, networking mode, commands, sysctls, secrets,
   and generated templates;
8. activation selectors, conditional expressions, transitive dependencies,
   and override behavior.

A cryptographically valid signature proves only that the configured key signed
the commit.

## Configure signature verification

`--signing-key` pins the expected signer fingerprint; it does not install that
signer's public key. Git must first be able to validate the commit signature.
Obtain the verification material through a channel independent from the source
repository and compare its full fingerprint before use.

For an OpenPGP-signed source, import only the reviewed public key into a
dedicated keyring:

```bash
install -d -m 0700 ~/.config/sdbx/catalog-gnupg
GNUPGHOME="$HOME/.config/sdbx/catalog-gnupg" \
  gpg --import /secure/reviewed-catalog-signing-key.asc
GNUPGHOME="$HOME/.config/sdbx/catalog-gnupg" \
  gpg --fingerprint FULL_SIGNER_FINGERPRINT
```

For an SSH-signed source, create a dedicated Git `allowedSignersFile`. The
principal is a local trust label; the public key and fingerprint are the
security boundary:

```text
catalog-source ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... reviewed-catalog-key
```

```bash
install -d -m 0700 ~/.config/sdbx/catalog-git
install -m 0600 /secure/allowed_signers \
  ~/.config/sdbx/catalog-git/allowed_signers
git config --file ~/.config/sdbx/catalog-git/config \
  gpg.ssh.allowedSignersFile \
  "$HOME/.config/sdbx/catalog-git/allowed_signers"
GIT_CONFIG_NOSYSTEM=1 \
GIT_CONFIG_GLOBAL="$HOME/.config/sdbx/catalog-git/config" \
  git -C /secure/reviewed-catalog verify-commit FULL_SIGNED_COMMIT
```

Run `sdbx source update` with the same isolated verification environment:

```bash
GNUPGHOME="$HOME/.config/sdbx/catalog-gnupg" \
GIT_CONFIG_NOSYSTEM=1 \
GIT_CONFIG_GLOBAL="$HOME/.config/sdbx/catalog-git/config" \
  sdbx source update community
```

Set those environment variables in the invoking service or operator session
when refreshes are automated. Do not reuse a personal writable keyring or a
shared mutable Git configuration for catalog trust. The repository access key
passed with `--ssh-key` authenticates transport only; it is not the commit
signing key or an `allowedSignersFile`.

SDBX reads Git's cryptographic signature status and then compares the full
reported signing or primary fingerprint with `--signing-key`. A missing public
key, missing `gpg.ssh.allowedSignersFile`, untrusted signature, signer mismatch,
or verification-command failure aborts the refresh and leaves the last verified
cache active.

## Add a source

With no dangerous permission grants:

```bash
sdbx source add community https://forgejo.example.test/team/catalog.git \
  --ref 0123456789abcdef0123456789abcdef01234567 \
  --signing-key 0123456789ABCDEF0123456789ABCDEF01234567 \
  --allow-registry docker.io
sdbx source update community
sdbx source info community
```

The example values are synthetic. Replace them with the independently verified
commit and fingerprint.

Private repositories may use `--ssh-key /secure/catalog-key`. The key path is
stored in the user source configuration; protect the file and avoid a shared
operator account.

Sources are stored in `~/.config/sdbx/sources.yaml` and cached privately under
`~/.cache/sdbx/sources` by default. `cache.ttl` defaults to `24h`, must be a
positive Go duration, and controls when normal catalog access re-fetches and
re-verifies an already cached source. An explicit `sdbx source update` always
re-fetches the pinned commit regardless of that TTL.

Configuration migration removes only the exact obsolete version-1 private
`official` record because the official catalog is now embedded. `official` is
not a reserved name for an explicit version-2 user source; such a source is
listed, verified, and removable like any other external source.

Every Git refresh uses a new private staging checkout. SDBX bounds the complete
refresh to two minutes and 64 KiB of combined Git diagnostics. It rejects a
source that exceeds any fixed v1 cache limit:

- 64 MiB and 12,000 entries for one complete cached checkout;
- 10,000 Git objects;
- 32 MiB, 4,096 regular files, and 4 MiB per file in the checked-out tree;
- 256 MiB for all persistent external-source caches together; or
- any symbolic link in the checkout.

The staged commit, signer, remote, clean working tree, objects, and budgets are
verified before one atomic directory rename makes it active. A failed,
oversized, slow, unsigned, dirty, or otherwise invalid refresh is deleted and
leaves the previous verified checkout untouched. These limits are safety
boundaries, not tuning knobs. Split an unusually large catalog into reviewed
sources instead of weakening them.

Catalog discovery adds a second parse-work boundary before definitions are
accumulated: at most 4,096 traversed entries, eight path components, 32 MiB of
tree data, 512 service definitions, and 16 MiB of definition data. Every
traversed file is capped at 4 MiB and every `service.yaml` at 1 MiB. Service
definitions must use one of the three canonical layouts documented below the
source root: `<name>/service.yaml`, `core/<name>/service.yaml`, or
`addons/<name>/service.yaml`.

## Permission grants

Definitions must declare the exact host-sensitive behavior they use, and the
source must receive matching grants. Supported permission classes include:

- `privileged`;
- `host-network`;
- `device`;
- `host-chown`;
- `host-mount`;
- `host-port`;
- `config-path`, `data-path`, `downloads-path`, `media-path`,
  `project-path`, and `secrets-path`;
- `network:edge`, `network:app`, `network:download`, or
  `network:management`;
- `service-network:name`;
- `service-override:name`;
- `route:admin-only`, `route:protected`, `route:native-auth`, or
  `route:public`;
- `capability:NAME`;
- `secret:name`.

Environment files are authorized as host paths, and every published host port,
trust-zone membership, and shared service namespace must be both declared and
granted. Docker-socket mounts are not a grantable v1 permission. They are
rejected before and after catalog-template rendering.

Every browser route requires an exact grant for its authentication owner.
Granting a route means trusting the selected image with requests and cookies
scoped to the shared SDBX domain. This includes the Authelia session cookie for
hosts covered by that cookie. A signature and a `route:*` grant make the
decision explicit and lock-recorded; they do not sandbox a malicious
application. Treat `route:public` and `route:native-auth` as deliberate public
exposure, and review protected applications as cookie-bearing trust
principals.

For example:

```bash
sdbx source add hardware https://forgejo.example.test/team/hardware.git \
  --ref 0123456789abcdef0123456789abcdef01234567 \
  --signing-key SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
  --allow-registry ghcr.io \
  --allow-permission device \
  --allow-permission capability:SYS_ADMIN
```

Do not use `*`, `capability:*`, `secret:*`, or an unrestricted registry unless
the review explicitly accepts the resulting host-level blast radius.

The validator rejects missing declarations, unused declarations, unknown
permissions, ungranted permissions, and images outside the source allowlist.
Templates receive a restricted read-only data object; they do not receive
arbitrary process, filesystem, or secret access.

## Priority and overrides

Higher-priority sources are checked first. An external definition can replace
an embedded service name only when it declares `service-override:NAME` and the
operator grants that exact permission to the source. The default CLI priority
is 10; the embedded catalog has the lowest priority.

Replacement always selects one complete `kind: Service` definition. Partial
`kind: ServiceOverride` documents are not a supported catalog resource and are
rejected. Project-level routing/subdomain/path customization belongs in the
reviewed `services` map in `.sdbx.yaml`; it cannot replace images, environment,
volumes, permissions, or container policy.

Catalog activation and conditional rendering are closed vocabularies. Every
definition declares exactly one of `always`, `requireAddon`, or a supported
`requireConfig` selector. Unknown `when` expressions, optional dependency
metadata with no runtime semantics, invalid or duplicate dependency names,
unsupported readiness conditions, and required dependencies disabled by the
current configuration all fail closed. The exact supported expressions are
listed in the catalog authoring guide.

The declaration and grant are both recorded in the lock so the collision is
reviewable. A definition with no matching embedded identity may not carry an
unused override permission. Source name `embedded` is reserved, and duplicate
source identities are rejected.

## Lock and update behavior

After a source is verified:

```bash
sdbx lock diff
sdbx lock
sdbx lock verify
```

The lock records source type, URL or path, exact ref and commit, signer,
priority, permissions, registries, source digest, definition digests, and
resolved image digests.

`sdbx source update` re-fetches and re-verifies the same immutable commit; it
does not advance to a branch head. To adopt a new source revision:

1. review the new commit and signature;
2. update the configured exact ref;
3. re-verify the source;
4. inspect the lock diff;
5. create the new lock only after approval.

Do not edit only the cached checkout. The remote URL, checked-out commit, and
signature are revalidated.

## Local sources

Local sources are useful for development and tests. They do not require Git
signatures and are not a third-party trust guarantee. A release or production
lock containing local source material must receive explicit review and should
not be presented as equivalent to the embedded catalog.

## Removal

Before removing a source, identify every active definition it supplies and
preview the replacement graph:

```bash
sdbx source info community
sdbx source remove community
sdbx lock diff
```

Removing source configuration does not delete application data. Do not accept
a lock change until every replacement or removed service is understood.
