#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

repository_root="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/.."
    pwd
)"
readonly repository_root
readonly dist_dir="$repository_root/dist"
test_root="$(mktemp -d)"

cleanup() {
    if [[ -n "$test_root" && -d "$test_root" ]]; then
        rm -rf -- "$test_root"
    fi
}
trap cleanup EXIT

fail() {
    printf 'release reproducibility test failed: %s\n' "$*" >&2
    exit 1
}

for command in cmp jq make; do
    command -v "$command" >/dev/null 2>&1 ||
        fail "required command is unavailable: $command"
done

cd "$repository_root"
make release-snapshot
scripts/verify-release-artifacts.sh "$dist_dir"

first_run="$test_root/first"
mkdir -p "$first_run"
cp "$dist_dir"/*.tar.gz "$dist_dir"/*.spdx.json "$first_run/"

make release-snapshot
scripts/verify-release-artifacts.sh "$dist_dir"

archive_count=0
for archive in "$dist_dir"/*.tar.gz; do
    [[ -f "$archive" ]] || fail "snapshot did not produce an archive"
    archive_count=$((archive_count + 1))
    archive_name="$(basename "$archive")"
    cmp -s "$first_run/$archive_name" "$archive" ||
        fail "archive is not byte-for-byte reproducible: $archive_name"
done
[[ "$archive_count" == "2" ]] ||
    fail "expected two archives, found $archive_count"

sbom_count=0
for sbom in "$dist_dir"/*.spdx.json; do
    [[ -f "$sbom" ]] || fail "snapshot did not produce an SPDX SBOM"
    sbom_count=$((sbom_count + 1))
    sbom_name="$(basename "$sbom")"
    jq -S 'del(.creationInfo.created, .documentNamespace)' \
        "$first_run/$sbom_name" >"$test_root/first-sbom.json"
    jq -S 'del(.creationInfo.created, .documentNamespace)' \
        "$sbom" >"$test_root/second-sbom.json"
    cmp -s "$test_root/first-sbom.json" "$test_root/second-sbom.json" ||
        fail "SBOM content changed beyond its unique namespace and timestamp: $sbom_name"
done
[[ "$sbom_count" == "2" ]] ||
    fail "expected two SPDX SBOMs, found $sbom_count"

printf 'release archives are byte-for-byte reproducible and SBOM content is stable\n'
