#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

repository_root="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/.."
    pwd -P
)"
readonly repository_root
gate="$repository_root/scripts/audit-catalog-images.sh"
readonly gate

test_directory="$(mktemp -d)"
readonly test_directory
clean_summary="$test_directory/clean.json"
critical_summary="$test_directory/critical.json"
high_summary="$test_directory/high.json"
inconsistent_summary="$test_directory/inconsistent.json"
fractional_summary="$test_directory/fractional.json"
readonly clean_summary critical_summary high_summary
readonly inconsistent_summary fractional_summary

cleanup() {
    rm -f \
        "$clean_summary" \
        "$critical_summary" \
        "$high_summary" \
        "$inconsistent_summary" \
        "$fractional_summary"
    rmdir "$test_directory"
}
trap cleanup EXIT

write_summary() {
    local destination="$1"
    local critical="$2"
    local fixable_critical="$3"
    local high="$4"

    jq -n \
        --argjson critical "$critical" \
        --argjson fixableCritical "$fixable_critical" \
        --argjson high "$high" \
        '{
          totals: {
            platformImages: 2,
            critical: $critical,
            fixableCritical: $fixableCritical,
            high: $high
          }
        }' >"$destination"
}

assert_status() {
    local expected="$1"
    local summary="$2"
    local actual

    set +e
    "$gate" --enforce-summary "$summary" >/dev/null 2>&1
    actual=$?
    set -e
    if [[ "$actual" -ne "$expected" ]]; then
        printf 'catalog image gate test: expected status %s, got %s for %s\n' \
            "$expected" "$actual" "$summary" >&2
        exit 1
    fi
}

assert_advisory_message() {
    local summary="$1"
    local output

    output="$("$gate" --enforce-summary "$summary" 2>&1)"
    if [[ "$output" != *"upstream findings are preserved as advisory evidence"* ]]; then
        printf '%s\n' \
            'catalog image gate test: result did not explain the advisory upstream-risk policy' >&2
        exit 1
    fi
}

write_summary "$clean_summary" 0 0 0
write_summary "$critical_summary" 1 1 0
write_summary "$high_summary" 0 0 1
write_summary "$inconsistent_summary" 0 1 0
write_summary "$fractional_summary" 0 0 0.5

assert_status 0 "$clean_summary"
assert_status 0 "$critical_summary"
assert_status 0 "$high_summary"
assert_status 1 "$inconsistent_summary"
assert_status 1 "$fractional_summary"
assert_advisory_message "$high_summary"

printf 'catalog image gate tests passed\n'
