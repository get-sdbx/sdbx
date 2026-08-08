#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

usage() {
    cat <<'EOF'
Usage:
  scripts/verify-amd64-acceptance-evidence.sh \
    --commit SHA1 --maintainer github:LOGIN --sha256 SHA256 \
    --url HTTPS_URL [--fixture-file FILE]

Download and verify the immutable Linux amd64 release-acceptance document.
--fixture-file is reserved for the repository's synthetic regression tests.
EOF
}

fail() {
    printf 'amd64 acceptance evidence verification failed: %s\n' "$*" >&2
    exit 1
}

candidate_commit=""
expected_maintainer=""
expected_sha256=""
evidence_url=""
fixture_file=""

while (($# > 0)); do
    case "$1" in
        --commit)
            (($# >= 2)) || fail "--commit requires a value"
            candidate_commit="$2"
            shift 2
            ;;
        --sha256)
            (($# >= 2)) || fail "--sha256 requires a value"
            expected_sha256="$2"
            shift 2
            ;;
        --maintainer)
            (($# >= 2)) || fail "--maintainer requires a value"
            expected_maintainer="$2"
            shift 2
            ;;
        --url)
            (($# >= 2)) || fail "--url requires a value"
            evidence_url="$2"
            shift 2
            ;;
        --fixture-file)
            (($# >= 2)) || fail "--fixture-file requires a path"
            fixture_file="$2"
            shift 2
            ;;
        --help | -h)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

[[ "$candidate_commit" =~ ^[a-f0-9]{40}$ ]] ||
    fail "--commit must be a lowercase 40-character Git object ID"
[[ "$expected_maintainer" =~ ^github:[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$ ]] ||
    fail "--maintainer must be github:LOGIN with a valid GitHub username"
[[ "$expected_sha256" =~ ^[a-f0-9]{64}$ ]] ||
    fail "--sha256 must be a lowercase SHA-256 digest"
[[ "$evidence_url" =~ ^https://[^/@[:space:]]+(/[^[:space:]]*)?$ ]] ||
    fail "--url must be a credential-free HTTPS URL"
command -v jq >/dev/null 2>&1 || fail "jq is required"

work_dir="$(mktemp -d)"
cleanup() {
    rm -rf -- "$work_dir"
}
trap cleanup EXIT

evidence_file="$work_dir/amd64-acceptance.json"
if [[ -n "$fixture_file" ]]; then
    [[ -f "$fixture_file" && ! -L "$fixture_file" ]] ||
        fail "fixture must be a regular non-symlink file"
    cp "$fixture_file" "$evidence_file"
else
    command -v curl >/dev/null 2>&1 || fail "curl is required"
    curl \
        --fail \
        --silent \
        --show-error \
        --location \
        --proto '=https' \
        --proto-redir '=https' \
        --tlsv1.2 \
        --max-time 60 \
        --max-filesize 1048576 \
        --output "$evidence_file" \
        "$evidence_url"
fi

[[ -f "$evidence_file" && ! -L "$evidence_file" ]] ||
    fail "downloaded evidence is not a regular file"
evidence_size="$(wc -c <"$evidence_file" | tr -d '[:space:]')"
[[ "$evidence_size" =~ ^[0-9]+$ ]] ||
    fail "cannot determine evidence size"
((evidence_size > 0 && evidence_size <= 1048576)) ||
    fail "evidence must contain between 1 byte and 1 MiB"

if command -v sha256sum >/dev/null 2>&1; then
    actual_sha256="$(sha256sum "$evidence_file" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
    actual_sha256="$(shasum -a 256 "$evidence_file" | awk '{print $1}')"
else
    fail "sha256sum or shasum is required"
fi
[[ "$actual_sha256" == "$expected_sha256" ]] ||
    fail "downloaded evidence SHA-256 does not match the protected value"

required_checks='[
  "artifact_integrity",
  "backup_restore",
  "binary_smoke",
  "browser",
  "compose_profiles",
  "console",
  "routing_auth",
  "update_rollback",
  "vpn_killswitch"
]'

jq -e \
    --arg commit "$candidate_commit" \
    --arg maintainer "$expected_maintainer" \
    --argjson required_checks "$required_checks" '
      type == "object" and
      (keys | sort) ==
        ([
          "artifacts",
          "candidateCommit",
          "checks",
          "completedAt",
          "platform",
          "acceptedBy",
          "schema",
          "verdict"
        ] | sort) and
      .schema == "sdbx.amd64-acceptance/v2" and
      .candidateCommit == $commit and
      .platform == "linux/amd64" and
      .verdict == "accepted" and
      .acceptedBy == $maintainer and
      (.completedAt | type == "string" and
        test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$") and
        (try (fromdateiso8601 <= (now + 300)) catch false)) and
      (.checks | type == "object") and
      ([.checks | keys[]] | sort) == ($required_checks | sort) and
      ([.checks[]] | all(. == "pass")) and
      (.artifacts | type == "array" and length > 0) and
      ([.artifacts[] |
        type == "object" and
        (keys | sort) == ["name", "sha256"] and
        (.name | type == "string" and
          test("^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")) and
        (.sha256 | type == "string" and test("^[a-f0-9]{64}$"))
      ] | all) and
      ([.artifacts[].name] | length == (unique | length))
    ' "$evidence_file" >/dev/null ||
    fail "evidence schema, candidate binding, verdict, checks, or artifacts are invalid"

printf 'Verified Linux amd64 acceptance evidence for %s (%s)\n' \
    "$candidate_commit" \
    "$actual_sha256"
