#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

require_signature=false
dist_dir="dist"
dist_dir_set=false

fail() {
    printf 'release asset listing failed: %s\n' "$*" >&2
    exit 1
}

while (($# > 0)); do
    case "$1" in
        --require-signature)
            require_signature=true
            shift
            ;;
        -*)
            fail "unknown argument: $1"
            ;;
        *)
            [[ "$dist_dir_set" == "false" ]] ||
                fail "only one distribution directory may be provided"
            dist_dir="$1"
            dist_dir_set=true
            shift
            ;;
    esac
done

command -v jq >/dev/null 2>&1 || fail "jq is required"
readonly artifacts_file="$dist_dir/artifacts.json"
[[ -f "$artifacts_file" && ! -L "$artifacts_file" ]] ||
    fail "missing regular artifacts.json in $dist_dir"

archive_names="$(
    jq -r '.[] | select(.type == "Archive") | .name' "$artifacts_file" |
        LC_ALL=C sort
)"
sbom_names="$(
    jq -r '.[] | select(.type == "SBOM") | .name' "$artifacts_file" |
        LC_ALL=C sort
)"
checksum_names="$(
    jq -r '.[] | select(.type == "Checksum") | .name' "$artifacts_file" |
        LC_ALL=C sort
)"

archive_count="$(printf '%s\n' "$archive_names" | sed '/^$/d' | wc -l | tr -d ' ')"
sbom_count="$(printf '%s\n' "$sbom_names" | sed '/^$/d' | wc -l | tr -d ' ')"
checksum_count="$(
    printf '%s\n' "$checksum_names" | sed '/^$/d' | wc -l | tr -d ' '
)"
[[ "$archive_count" == "2" ]] ||
    fail "expected two archives, found $archive_count"
[[ "$sbom_count" == "2" ]] ||
    fail "expected two SBOMs, found $sbom_count"
[[ "$checksum_count" == "1" && "$checksum_names" == "checksums.txt" ]] ||
    fail "expected the single checksum asset checksums.txt"

amd64_archive="$(
    printf '%s\n' "$archive_names" |
        awk '/_linux_amd64\.tar\.gz$/ { print }'
)"
arm64_archive="$(
    printf '%s\n' "$archive_names" |
        awk '/_linux_arm64\.tar\.gz$/ { print }'
)"
[[ -n "$amd64_archive" && "$amd64_archive" != *$'\n'* ]] ||
    fail "expected exactly one Linux amd64 archive"
[[ -n "$arm64_archive" && "$arm64_archive" != *$'\n'* ]] ||
    fail "expected exactly one Linux arm64 archive"
[[ "${amd64_archive/_linux_amd64.tar.gz/_linux_arm64.tar.gz}" == "$arm64_archive" ]] ||
    fail "Linux archive versions do not match"

expected_sbom_names="$(
    printf '%s.spdx.json\n' "$amd64_archive" "$arm64_archive" |
        LC_ALL=C sort
)"
[[ "$sbom_names" == "$expected_sbom_names" ]] ||
    fail "SBOM names do not match the two release archives"

while IFS= read -r archive_name; do
    [[ -n "$archive_name" ]] || continue
    [[ "$archive_name" =~ ^sdbx_[0-9A-Za-z.+-]+_linux_(amd64|arm64)\.tar\.gz$ ]] ||
        fail "unexpected archive name: $archive_name"
    [[ -f "$dist_dir/$archive_name" && ! -L "$dist_dir/$archive_name" ]] ||
        fail "archive is missing or not a regular file: $archive_name"
done <<<"$archive_names"

while IFS= read -r sbom_name; do
    [[ -n "$sbom_name" ]] || continue
    [[ "$sbom_name" =~ ^sdbx_[0-9A-Za-z.+-]+_linux_(amd64|arm64)\.tar\.gz\.spdx\.json$ ]] ||
        fail "unexpected SBOM name: $sbom_name"
    [[ -f "$dist_dir/$sbom_name" && ! -L "$dist_dir/$sbom_name" ]] ||
        fail "SBOM is missing or not a regular file: $sbom_name"
done <<<"$sbom_names"

[[ -f "$dist_dir/checksums.txt" && ! -L "$dist_dir/checksums.txt" ]] ||
    fail "checksums.txt is missing or not a regular file"

printf '%s\n' "$archive_names" "$sbom_names" "checksums.txt"
if [[ "$require_signature" == "true" ]]; then
    signature_name="checksums.txt.sigstore.json"
    [[ -f "$dist_dir/$signature_name" && ! -L "$dist_dir/$signature_name" ]] ||
        fail "$signature_name is missing or not a regular file"
    printf '%s\n' "$signature_name"
fi
