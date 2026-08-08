#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

repository_root="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/.."
    pwd
)"
readonly repository_root
readonly list_script="$repository_root/scripts/list-release-assets.sh"
test_root="$(mktemp -d)"

cleanup() {
    if [[ -n "$test_root" && -d "$test_root" ]]; then
        rm -rf -- "$test_root"
    fi
}
trap cleanup EXIT

fail() {
    printf 'release asset test failed: %s\n' "$*" >&2
    exit 1
}

write_fixture() {
    local fixture_dir="$1"

    mkdir -p "$fixture_dir"
    printf '%s\n' \
        '[' \
        '  {"type":"Archive","name":"sdbx_1.0.0_linux_amd64.tar.gz"},' \
        '  {"type":"Archive","name":"sdbx_1.0.0_linux_arm64.tar.gz"},' \
        '  {"type":"SBOM","name":"sdbx_1.0.0_linux_amd64.tar.gz.spdx.json"},' \
        '  {"type":"SBOM","name":"sdbx_1.0.0_linux_arm64.tar.gz.spdx.json"},' \
        '  {"type":"Checksum","name":"checksums.txt"}' \
        ']' >"$fixture_dir/artifacts.json"

    : >"$fixture_dir/sdbx_1.0.0_linux_amd64.tar.gz"
    : >"$fixture_dir/sdbx_1.0.0_linux_arm64.tar.gz"
    : >"$fixture_dir/sdbx_1.0.0_linux_amd64.tar.gz.spdx.json"
    : >"$fixture_dir/sdbx_1.0.0_linux_arm64.tar.gz.spdx.json"
    : >"$fixture_dir/checksums.txt"
}

expect_failure() {
    local description="$1"
    shift

    if "$@" >/dev/null 2>&1; then
        fail "$description unexpectedly succeeded"
    fi
}

command -v jq >/dev/null 2>&1 || fail "jq is required"
[[ -x "$list_script" ]] || fail "release asset listing script is not executable"

valid_fixture="$test_root/valid fixture"
write_fixture "$valid_fixture"
expected="$test_root/expected"
printf '%s\n' \
    sdbx_1.0.0_linux_amd64.tar.gz \
    sdbx_1.0.0_linux_arm64.tar.gz \
    sdbx_1.0.0_linux_amd64.tar.gz.spdx.json \
    sdbx_1.0.0_linux_arm64.tar.gz.spdx.json \
    checksums.txt >"$expected"
"$list_script" "$valid_fixture" >"$test_root/actual"
cmp -s "$expected" "$test_root/actual" ||
    fail "valid fixture produced an unexpected public asset allowlist"

expect_failure \
    "signature-required fixture without a signature" \
    "$list_script" --require-signature "$valid_fixture"
: >"$valid_fixture/checksums.txt.sigstore.json"
printf '%s\n' checksums.txt.sigstore.json >>"$expected"
"$list_script" --require-signature "$valid_fixture" >"$test_root/signed-actual"
cmp -s "$expected" "$test_root/signed-actual" ||
    fail "signed fixture produced an unexpected public asset allowlist"

missing_file_fixture="$test_root/missing-file"
write_fixture "$missing_file_fixture"
rm "$missing_file_fixture/sdbx_1.0.0_linux_arm64.tar.gz"
expect_failure \
    "fixture with a missing archive" \
    "$list_script" "$missing_file_fixture"

symlink_fixture="$test_root/symlink"
write_fixture "$symlink_fixture"
rm "$symlink_fixture/checksums.txt"
ln -s /dev/null "$symlink_fixture/checksums.txt"
expect_failure \
    "fixture with a symlinked public asset" \
    "$list_script" "$symlink_fixture"

duplicate_fixture="$test_root/duplicate"
write_fixture "$duplicate_fixture"
jq \
    '. + [{"type":"Archive","name":"sdbx_1.0.0_linux_amd64.tar.gz"}]' \
    "$duplicate_fixture/artifacts.json" >"$duplicate_fixture/artifacts.next"
mv "$duplicate_fixture/artifacts.next" "$duplicate_fixture/artifacts.json"
expect_failure \
    "fixture with a duplicate archive record" \
    "$list_script" "$duplicate_fixture"

mismatched_fixture="$test_root/mismatched"
write_fixture "$mismatched_fixture"
jq \
    'map(if .name == "sdbx_1.0.0_linux_arm64.tar.gz"
         then .name = "sdbx_2.0.0_linux_arm64.tar.gz"
         elif .name == "sdbx_1.0.0_linux_arm64.tar.gz.spdx.json"
         then .name = "sdbx_2.0.0_linux_arm64.tar.gz.spdx.json"
         else .
         end)' \
    "$mismatched_fixture/artifacts.json" >"$mismatched_fixture/artifacts.next"
mv "$mismatched_fixture/artifacts.next" "$mismatched_fixture/artifacts.json"
mv \
    "$mismatched_fixture/sdbx_1.0.0_linux_arm64.tar.gz" \
    "$mismatched_fixture/sdbx_2.0.0_linux_arm64.tar.gz"
mv \
    "$mismatched_fixture/sdbx_1.0.0_linux_arm64.tar.gz.spdx.json" \
    "$mismatched_fixture/sdbx_2.0.0_linux_arm64.tar.gz.spdx.json"
expect_failure \
    "fixture with mismatched architecture versions" \
    "$list_script" "$mismatched_fixture"

unsafe_name_fixture="$test_root/unsafe-name"
write_fixture "$unsafe_name_fixture"
jq \
    'map(if .name == "sdbx_1.0.0_linux_amd64.tar.gz"
         then .name = "../sdbx_1.0.0_linux_amd64.tar.gz"
         else .
         end)' \
    "$unsafe_name_fixture/artifacts.json" >"$unsafe_name_fixture/artifacts.next"
mv "$unsafe_name_fixture/artifacts.next" "$unsafe_name_fixture/artifacts.json"
expect_failure \
    "fixture with a path-traversing asset name" \
    "$list_script" "$unsafe_name_fixture"

artifacts_symlink_fixture="$test_root/artifacts-symlink"
write_fixture "$artifacts_symlink_fixture"
mv \
    "$artifacts_symlink_fixture/artifacts.json" \
    "$artifacts_symlink_fixture/artifacts.real.json"
ln -s artifacts.real.json "$artifacts_symlink_fixture/artifacts.json"
expect_failure \
    "fixture with a symlinked artifact manifest" \
    "$list_script" "$artifacts_symlink_fixture"

printf 'release asset allowlist accepted the exact set and rejected unsafe variants\n'
