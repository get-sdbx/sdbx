#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

repository_root="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/.."
    pwd
)"
readonly repository_root
readonly verifier="$repository_root/scripts/verify-amd64-acceptance-evidence.sh"
readonly candidate_commit="0123456789abcdef0123456789abcdef01234567"
readonly expected_maintainer="github:maiko"
readonly evidence_url="https://evidence.example.test/sdbx/acceptance.json"
test_root="$(mktemp -d)"

cleanup() {
    rm -rf -- "$test_root"
}
trap cleanup EXIT

fail() {
    printf 'amd64 acceptance evidence test failed: %s\n' "$*" >&2
    exit 1
}

sha256_file() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    else
        shasum -a 256 "$file" | awk '{print $1}'
    fi
}

verify_fixture() {
    local file="$1"
    local digest
    digest="$(sha256_file "$file")"
    "$verifier" \
        --commit "$candidate_commit" \
        --maintainer "$expected_maintainer" \
        --sha256 "$digest" \
        --url "$evidence_url" \
        --fixture-file "$file"
}

expect_failure() {
    local description="$1"
    shift
    if "$@" >"$test_root/failure.out" 2>&1; then
        fail "$description unexpectedly succeeded"
    fi
}

write_valid_fixture() {
    local destination="$1"
    cat >"$destination" <<EOF
{
  "schema": "sdbx.amd64-acceptance/v2",
  "candidateCommit": "$candidate_commit",
  "platform": "linux/amd64",
  "verdict": "accepted",
  "acceptedBy": "github:maiko",
  "completedAt": "2026-07-30T01:02:03Z",
  "checks": {
    "artifact_integrity": "pass",
    "backup_restore": "pass",
    "binary_smoke": "pass",
    "browser": "pass",
    "compose_profiles": "pass",
    "console": "pass",
    "routing_auth": "pass",
    "update_rollback": "pass",
    "vpn_killswitch": "pass"
  },
  "artifacts": [
    {
      "name": "host-qa-summary.json",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ]
}
EOF
}

valid_fixture="$test_root/valid.json"
write_valid_fixture "$valid_fixture"
verify_fixture "$valid_fixture" >/dev/null

valid_digest="$(sha256_file "$valid_fixture")"
expect_failure \
    "wrong protected digest" \
    "$verifier" \
    --commit "$candidate_commit" \
    --maintainer "$expected_maintainer" \
    --sha256 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
    --url "$evidence_url" \
    --fixture-file "$valid_fixture"

expect_failure \
    "wrong candidate commit" \
    "$verifier" \
    --commit "fedcba9876543210fedcba9876543210fedcba98" \
    --maintainer "$expected_maintainer" \
    --sha256 "$valid_digest" \
    --url "$evidence_url" \
    --fixture-file "$valid_fixture"

for mutation in \
    '.verdict = "rejected"' \
    '.platform = "linux/arm64"' \
    '.checks.vpn_killswitch = "skip"' \
    'del(.checks.backup_restore)' \
    '.completedAt = "2026-99-99T25:61:61Z"' \
    '.completedAt = "2999-01-01T00:00:00Z"' \
    '.unexpected = true' \
    '.artifacts[0].sha256 = "not-a-digest"' \
    '.artifacts[0].unexpected = true' \
    '.artifacts += [.artifacts[0]]'; do
    invalid_fixture="$test_root/invalid-$(printf '%s' "$mutation" | cksum | awk '{print $1}').json"
    jq "$mutation" "$valid_fixture" >"$invalid_fixture"
    expect_failure "invalid evidence mutation $mutation" verify_fixture "$invalid_fixture"
done

expect_failure \
    "wrong responsible maintainer" \
    "$verifier" \
    --commit "$candidate_commit" \
    --maintainer "github:different-maintainer" \
    --sha256 "$valid_digest" \
    --url "$evidence_url" \
    --fixture-file "$valid_fixture"

expect_failure \
    "credential-bearing URL" \
    "$verifier" \
    --commit "$candidate_commit" \
    --maintainer "$expected_maintainer" \
    --sha256 "$valid_digest" \
    --url "https://user@example.test/evidence.json" \
    --fixture-file "$valid_fixture"

printf 'amd64 acceptance evidence regressions passed\n'
