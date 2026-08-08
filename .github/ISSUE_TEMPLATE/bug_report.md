---
name: Bug report
about: Report reproducible incorrect behavior
title: "[Bug] "
labels: bug
assignees: ""
---

<!--
Do not report vulnerabilities or suspected credential exposure in a public
issue. Follow SECURITY.md instead.

Before submitting, remove passwords, tokens, cookies, API keys, private
domains/IPs, filesystem identities, and personal media details from every
command, log, configuration excerpt, and screenshot.
-->

## Summary

<!-- What failed, and what user-visible result did you expect? -->

## Reproduction

1.
2.
3.

## Environment

- SDBX version or commit: <!-- `sdbx version` -->
- Linux distribution and version:
- Architecture: <!-- amd64 (supported) or arm64 (compatibility) -->
- Docker Engine version: <!-- `docker version` -->
- Docker Compose version: <!-- `docker compose version` -->
- Exposure mode: <!-- lan, direct, or cloudflared -->
- Routing strategy: <!-- subdomain or path -->

## Diagnostics

<!--
Run `sdbx doctor --json` and include only relevant redacted checks. Say which
checks were omitted. Do not attach the whole project or secrets directory.
-->

```json
{}
```

## Relevant configuration

<!--
Include only the minimum redacted keys from .sdbx.yaml. Do not paste .env,
secret files, backup credentials, or application databases.
-->

```yaml
{}
```

## Relevant logs

<!-- Use `sdbx logs <service>`. Redact credentials and private identifiers. -->

```text
Paste the smallest relevant redacted excerpt.
```

## Regression

- [ ] This worked in an earlier SDBX version.
- Last known working version or commit:

## Checklist

- [ ] I reproduced this on supported Linux amd64, or clearly marked it as a
      Linux arm64 compatibility or development-only Darwin CLI issue.
- [ ] I searched existing issues.
- [ ] I ran `sdbx doctor` and reviewed the result.
- [ ] I removed secrets and private data.
- [ ] This report does not describe a security vulnerability.
