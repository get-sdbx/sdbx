## Outcome

<!-- State the user-visible or engineering result. -->

## Scope

<!-- List the intentionally changed areas and anything deliberately excluded. -->

## Related issue

<!-- Use "Closes #123" when appropriate. -->

## Security and trust boundaries

<!--
Describe effects on root/Docker access, broker operations, networks, route
authentication, secrets, backups, external sources, or public exposure.
-->

## Validation

<!-- List exact commands and manual checks that passed. -->

- [ ] Targeted tests pass.
- [ ] `go test ./...` passes.
- [ ] `go test -race ./...` passes when the change crosses concurrency,
      management, filesystem, or security boundaries.
- [ ] `make lint` and `go vet ./...` pass.
- [ ] Both `sdbx` and `sdbxd` build.
- [ ] Public-facing UI changes were checked on desktop and mobile, with
      keyboard navigation and a clean browser console.

## Documentation and release impact

- [ ] User-facing behavior and command help agree.
- [ ] Documentation matches executable behavior.
- [ ] The sibling website was checked when product claims or UI changed.
- [ ] Configuration, lock, migration, and rollback implications are documented.
- [ ] No private repository URL, credential, personal data, or debug artifact was
      added to public content.

## Review checklist

- [ ] I reviewed the diff for unrelated changes.
- [ ] I preserved generated-file and transaction invariants.
- [ ] I added or updated tests for the changed behavior.
- [ ] I did not add a raw Docker socket, generic broker primitive, plaintext
      secret argument, plaintext backup, or mutable release dependency.
- [ ] I did not add a `Co-Authored-By` trailer.

## Screenshots or evidence

<!-- Use synthetic data. Store local browser artifacts under output/playwright/. -->
