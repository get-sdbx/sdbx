#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

repository_root="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/.."
    pwd
)"
dist_dir="dist"
dist_dir_set=false
release_tag=""
expected_commit=""

fail() {
    printf 'release artifact verification failed: %s\n' "$*" >&2
    exit 1
}

while (($# > 0)); do
    case "$1" in
        --release-tag)
            (($# >= 2)) || fail "--release-tag requires a value"
            release_tag="$2"
            shift 2
            ;;
        --commit)
            (($# >= 2)) || fail "--commit requires a value"
            expected_commit="$2"
            shift 2
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

if [[ -n "$release_tag" ]]; then
    [[ "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]] ||
        fail "release tag must be semantic version with an optional prerelease"
fi
if [[ -n "$expected_commit" ]]; then
    [[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] ||
        fail "expected commit must be a full lowercase Git object ID"
    [[ -n "$release_tag" ]] ||
        fail "--commit requires --release-tag"
fi

readonly repository_root
readonly dist_dir
readonly release_tag
readonly expected_commit
readonly artifacts_file="$dist_dir/artifacts.json"
readonly checksums_file="$dist_dir/checksums.txt"

for command in go jq tar; do
    command -v "$command" >/dev/null 2>&1 ||
        fail "required command is unavailable: $command"
done

[[ -d "$dist_dir" ]] || fail "distribution directory does not exist: $dist_dir"
[[ -f "$artifacts_file" && ! -L "$artifacts_file" ]] ||
    fail "missing regular artifacts.json"
[[ -f "$checksums_file" && ! -L "$checksums_file" ]] ||
    fail "missing regular checksums.txt"

archive_names="$(
    jq -r '.[] | select(.type == "Archive") | .name' "$artifacts_file" |
        LC_ALL=C sort
)"
archive_count="$(printf '%s\n' "$archive_names" | sed '/^$/d' | wc -l | tr -d ' ')"
[[ "$archive_count" == "2" ]] ||
    fail "expected two Linux release archives, found $archive_count"

sbom_names="$(
    jq -r '.[] | select(.type == "SBOM") | .name' "$artifacts_file" |
        LC_ALL=C sort
)"
sbom_count="$(printf '%s\n' "$sbom_names" | sed '/^$/d' | wc -l | tr -d ' ')"
[[ "$sbom_count" == "2" ]] ||
    fail "expected two archive SBOMs, found $sbom_count"

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

if [[ -n "$release_tag" ]]; then
    release_version="${release_tag#v}"
    [[ "$amd64_archive" == "sdbx_${release_version}_linux_amd64.tar.gz" ]] ||
        fail "archive version does not match release tag $release_tag"
fi

expected_checksum_names="$(
    printf '%s\n' "$archive_names" "$sbom_names" |
        LC_ALL=C sort
)"
actual_checksum_names=""
while IFS= read -r checksum_line; do
    [[ "$checksum_line" =~ ^[0-9a-f]{64}\ \ [0-9A-Za-z._+-]+$ ]] ||
        fail "checksums.txt contains a malformed or unsafe entry"
    checksum_name="${checksum_line#*  }"
    actual_checksum_names+="${checksum_name}"$'\n'
done <"$checksums_file"
actual_checksum_names="$(
    printf '%s' "$actual_checksum_names" |
        sed '/^$/d' |
        LC_ALL=C sort
)"
[[ "$actual_checksum_names" == "$expected_checksum_names" ]] ||
    fail "checksums.txt does not cover exactly both archives and both SBOMs"

if command -v sha256sum >/dev/null 2>&1; then
    (
        cd "$dist_dir"
        sha256sum --check checksums.txt
    )
elif command -v shasum >/dev/null 2>&1; then
    (
        cd "$dist_dir"
        shasum -a 256 --check checksums.txt
    )
else
    fail "sha256sum or shasum is required"
fi

expected_go_version="go$(
    awk '$1 == "go" { print $2; exit }' "$repository_root/go.mod"
)"
[[ "$expected_go_version" != "go" ]] ||
    fail "could not resolve the pinned Go version"

expected_entries="$(
    printf '%s\n' \
        CHANGELOG.md \
        LICENSE \
        product-manifest.json \
        README.md \
        SECURITY.md \
        THIRD_PARTY_NOTICES.txt \
        docs/installation.md \
        packaging/systemd/sdbx-web.service \
        packaging/systemd/sdbxd.env.example \
        packaging/systemd/sdbxd.service \
        sdbx \
        sdbxd |
        LC_ALL=C sort
)"

while IFS= read -r archive_name; do
    [[ -n "$archive_name" ]] || continue
    [[ "$archive_name" =~ ^sdbx_[0-9A-Za-z.+-]+_linux_(amd64|arm64)\.tar\.gz$ ]] ||
        fail "unexpected archive name: $archive_name"
    archive_path="$dist_dir/$archive_name"
    [[ -f "$archive_path" && ! -L "$archive_path" ]] ||
        fail "missing regular archive: $archive_name"
    architecture="${archive_name%.tar.gz}"
    architecture="${architecture##*_linux_}"

    actual_entries="$(tar -tzf "$archive_path" | sed 's#^\./##' | LC_ALL=C sort)"
    [[ "$actual_entries" == "$expected_entries" ]] ||
        fail "archive contents differ from the release allowlist: $archive_name"

    if ! tar -tvzf "$archive_path" | awk '$1 !~ /^-/ { exit 1 }'; then
        fail "archive contains a non-regular entry: $archive_name"
    fi

    work_dir="$(mktemp -d)"
    trap 'rm -rf "$work_dir"' EXIT
    tar -xzf "$archive_path" -C "$work_dir"
    for binary in sdbx sdbxd; do
        [[ -f "$work_dir/$binary" && ! -L "$work_dir/$binary" ]] ||
            fail "$archive_name does not contain a regular $binary binary"
        [[ -x "$work_dir/$binary" ]] ||
            fail "$archive_name contains a non-executable $binary binary"
        binary_metadata="$(go version -m "$work_dir/$binary")"
        [[ "$binary_metadata" == *": $expected_go_version"* ]] ||
            fail "$archive_name contains $binary built by an unexpected Go version"
        [[ "$binary_metadata" == *$'\tbuild\tGOOS=linux'* ]] ||
            fail "$archive_name contains a non-Linux $binary binary"
        [[ "$binary_metadata" == *$'\tbuild\tGOARCH='"$architecture"* ]] ||
            fail "$archive_name contains $binary for the wrong architecture"
        [[ "$binary_metadata" == *$'\tbuild\tCGO_ENABLED=0'* ]] ||
            fail "$archive_name contains a dynamically configured $binary binary"

        expected_package="github.com/get-sdbx/sdbx/cmd/$binary"
        [[ "$binary_metadata" == *$'\tpath\t'"$expected_package"* ]] ||
            fail "$archive_name contains the wrong $binary entry point"

        if [[ -n "$expected_commit" ]]; then
            [[ "$binary_metadata" == *$'\tbuild\tvcs.revision='"$expected_commit"* ]] ||
                fail "$archive_name contains $binary from the wrong commit"
            [[ "$binary_metadata" == *$'\tbuild\tvcs.modified=false'* ]] ||
                fail "$archive_name contains a dirty $binary build"
        fi
    done
    rm -rf "$work_dir"
    trap - EXIT

    sbom_path="$dist_dir/$archive_name.spdx.json"
    [[ -f "$sbom_path" && ! -L "$sbom_path" ]] ||
        fail "missing regular archive SBOM: $(basename "$sbom_path")"
    jq -e '
        (.spdxVersion | startswith("SPDX-")) and
        (.SPDXID == "SPDXRef-DOCUMENT") and
        ((.packages | length) > 0)
    ' "$sbom_path" >/dev/null ||
        fail "invalid SPDX SBOM: $(basename "$sbom_path")"
done <<<"$archive_names"

scripts/check-release-licenses.sh "$dist_dir"

printf 'verified two Linux archives, both binaries, checksums, and SPDX SBOMs\n'
