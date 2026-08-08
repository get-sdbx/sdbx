#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

repository_root="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/.."
    pwd
)"
readonly repository_root
test_root="$(mktemp -d)"

cleanup() {
    rm -rf -- "$test_root"
}
trap cleanup EXIT

valid_root="$test_root/valid"
mkdir -p "$valid_root/.github/workflows"
cat >"$valid_root/.github/workflows/reusable.yml" <<'EOF'
name: Reusable
on:
  workflow_call:
jobs:
  noop:
    runs-on: ubuntu-24.04
    steps:
      - run: "true"
EOF
cat >"$valid_root/.github/workflows/ci.yml" <<'EOF'
name: CI
on:
  push:
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      - uses: actions/setup-go@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      - uses: goreleaser/goreleaser-action@cccccccccccccccccccccccccccccccccccccccc
  reusable:
    uses: ./.github/workflows/reusable.yml
EOF

"$repository_root/scripts/check-workflow-actions.sh" --root "$valid_root"

expect_failure() {
    local name="$1"
    local replacement="$2"
    local expected="$3"
    local invalid_root="$test_root/$name"
    cp -R "$valid_root" "$invalid_root"
    perl -0pi -e "$replacement" "$invalid_root/.github/workflows/ci.yml"
    if "$repository_root/scripts/check-workflow-actions.sh" \
        --root "$invalid_root" >"$test_root/$name.out" 2>&1; then
        printf 'Workflow action test failed: unsafe %s case was accepted\n' \
            "$name" >&2
        exit 1
    fi
    grep -q "$expected" "$test_root/$name.out"
}

expect_failure \
    floating-tag \
    's#actions/checkout\@a{40}#actions/checkout\@v7#' \
    'full lowercase commit SHA'
expect_failure \
    short-sha \
    's#actions/checkout\@a{40}#actions/checkout\@aaaaaaaaaaaa#' \
    'full lowercase commit SHA'
expect_failure \
    uppercase-sha \
    's#actions/checkout\@a{40}#actions/checkout\@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#' \
    'full lowercase commit SHA'
expect_failure \
    dynamic-ref \
    's#actions/checkout\@a{40}#actions/checkout\@\\$\\{\\{ matrix.ref \\}\\}#' \
    'full lowercase commit SHA'
expect_failure \
    unreviewed-owner \
    's#actions/checkout\@a{40}#docker/login-action\@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa#' \
    'unreviewed action'
expect_failure \
    unreviewed-github-action \
    's#actions/checkout\@a{40}#actions/cache\@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa#' \
    'unreviewed action'
expect_failure \
    remote-reusable-workflow \
    's#actions/checkout\@a{40}#octo/example/.github/workflows/reuse.yml\@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa#' \
    'unreviewed action'
expect_failure \
    missing-local-workflow \
    's#\./\.github/workflows/reusable\.yml#./.github/workflows/missing.yml#' \
    'missing or unsafe local workflow'
expect_failure \
    local-traversal \
    's#\./\.github/workflows/reusable\.yml#./.github/workflows/../outside.yml#' \
    'unsafe local workflow reference'
expect_failure \
    inline-mapping \
    's#- uses: actions/checkout\@a{40}#- { uses: actions/checkout\@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa }#' \
    'unsupported YAML syntax'

symlink_root="$test_root/symlink"
cp -R "$valid_root" "$symlink_root"
ln -s "$symlink_root/.github/workflows/ci.yml" \
    "$symlink_root/.github/workflows/linked.yml"
if "$repository_root/scripts/check-workflow-actions.sh" \
    --root "$symlink_root" >"$test_root/symlink.out" 2>&1; then
    printf '%s\n' \
        "Workflow action test failed: symlinked workflow was accepted" >&2
    exit 1
fi
grep -q 'regular non-symlink' "$test_root/symlink.out"

empty_root="$test_root/empty"
mkdir -p "$empty_root/.github/workflows"
if "$repository_root/scripts/check-workflow-actions.sh" \
    --root "$empty_root" >"$test_root/empty.out" 2>&1; then
    printf '%s\n' \
        "Workflow action test failed: empty workflow directory was accepted" >&2
    exit 1
fi
grep -q 'no workflow files' "$test_root/empty.out"

printf '%s\n' \
    "Workflow action policy accepted reviewed SHA pins and rejected unsafe references"
