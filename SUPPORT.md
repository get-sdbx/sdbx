# Support

SDBX is community-maintained software. Support is best effort; there is no
guaranteed response time or managed-hosting service.

## Before requesting help

Use the current documentation:

- [Getting Started](docs/getting-started.md)
- [Operations](docs/operations.md)
- [Troubleshooting](docs/troubleshooting.md)
- [CLI Reference](docs/reference/cli.md)
- [Configuration Reference](docs/configuration.md)
- [Security Policy](SECURITY.md)

Collect:

```bash
sdbx version
sdbx lock verify
sdbx status
sdbx doctor
```

Include the Linux distribution and architecture plus Docker Engine and Compose
versions. Reduce the problem to one command or service when possible.

## Public support

Use [GitHub Issues](https://github.com/get-sdbx/sdbx/issues):

- bug report for reproducible SDBX defects;
- feature request for scoped product proposals;
- question for behavior not answered by the documentation.

Search existing issues first and use the matching form. Keep one problem per
issue.

SDBX does not currently advertise Discord, chat, forum, or paid support.

## Privacy and redaction

Public reports must use synthetic values. Do not attach:

- `.sdbx.yaml`, `.sdbx.lock`, `.env`, generated Compose, or source
  configuration without a field-by-field review;
- VPN credentials, Authelia secrets, API keys, cookies, tokens, age identities,
  passphrases, or private keys;
- broker token files or raw audit logs;
- production domains, IP addresses, usernames, paths, media names, indexers,
  download history, or personal data.

SDBX redacts its own bounded external errors, but upstream application logs can
still contain sensitive data. Replace deployment identifiers with values under
`.example.test`.

## Unsupported requests

The project cannot provide:

- legal advice about content or sources;
- credentials, indexers, invitation codes, or copyrighted media;
- administration of an operator's Linux host, DNS, VPN, or Cloudflare account;
- recovery of an encrypted archive without its identity or passphrase;
- support for modified binaries, unreviewed external catalogs, or unsupported
  host platforms as if they were official releases.

Upstream application defects should be reported upstream unless SDBX generated
the unsafe or invalid configuration.

## Vulnerabilities

Do not report a security vulnerability in a public issue. Follow
[SECURITY.md](SECURITY.md) and use GitHub private vulnerability reporting.

## Conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
Use the private contact identified in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
for conduct reports. No unverified project-domain mailbox is an operational
reporting channel.
