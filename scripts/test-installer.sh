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
    if [[ -n "$test_root" && -d "$test_root" ]]; then
        rm -rf -- "$test_root"
    fi
}
trap cleanup EXIT

fail() {
    printf 'installer test failed: %s\n' "$*" >&2
    exit 1
}

fixture_dir="$test_root/fixture"
payload_dir="$test_root/payload"
fake_bin="$test_root/bin"
install_dir="$test_root/install"
systemd_assets_dir="$test_root/systemd-assets"
mkdir -p \
    "$fixture_dir" \
    "$fake_bin" \
    "$payload_dir/docs" \
    "$payload_dir/packaging/systemd"

for file in \
    CHANGELOG.md \
    LICENSE \
    product-manifest.json \
    README.md \
    SECURITY.md \
    THIRD_PARTY_NOTICES.txt; do
    printf 'synthetic %s\n' "$file" >"$payload_dir/$file"
done
printf 'synthetic installation guide\n' >"$payload_dir/docs/installation.md"
cat >"$payload_dir/packaging/systemd/sdbxd.service" <<'EOF'
[Service]
ExecStart=/usr/local/bin/sdbxd \
  --project-dir=${SDBX_PROJECT_DIR}
EOF
cat >"$payload_dir/packaging/systemd/sdbx-web.service" <<'EOF'
[Service]
ExecStart=/usr/local/bin/sdbx serve \
  --addr=127.0.0.1:18777
EOF
printf 'SDBX_PROJECT_DIR=/srv/sdbx/project\n' \
    >"$payload_dir/packaging/systemd/sdbxd.env.example"

cat >"$payload_dir/sdbx" <<'EOF'
#!/usr/bin/env sh
if [ "${1:-}" = "version" ]; then
    printf 'sdbx 1.2.3\n'
    exit 0
fi
exit 1
EOF
cat >"$payload_dir/sdbxd" <<'EOF'
#!/usr/bin/env sh
if [ "${1:-}" = "-version" ]; then
    printf 'sdbxd 1.2.3 (commit synthetic, built synthetic)\n'
    exit 0
fi
exit 1
EOF
chmod 0755 "$payload_dir/sdbx" "$payload_dir/sdbxd"

build_archive() {
    local release_architecture="$1"
    local archive_name="sdbx_1.2.3_linux_${release_architecture}.tar.gz"
    tar -czf "$fixture_dir/$archive_name" \
        -C "$payload_dir" \
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
        sdbxd
}

write_checksum_manifest() {
    : >"$fixture_dir/checksums.txt"
    local release_architecture
    for release_architecture in amd64 arm64; do
        local archive_name="sdbx_1.2.3_linux_${release_architecture}.tar.gz"
        local archive_checksum
        if command -v sha256sum >/dev/null 2>&1; then
            archive_checksum="$(
                sha256sum "$fixture_dir/$archive_name" | awk '{print $1}'
            )"
        else
            archive_checksum="$(
                shasum -a 256 "$fixture_dir/$archive_name" | awk '{print $1}'
            )"
        fi
        printf '%s  %s\n' \
            "$archive_checksum" \
            "$archive_name" \
            >>"$fixture_dir/checksums.txt"
    done
}

for release_architecture in amd64 arm64; do
    build_archive "$release_architecture"
done
write_checksum_manifest
printf '{"synthetic":"sigstore bundle"}\n' \
    >"$fixture_dir/checksums.txt.sigstore.json"

cat >"$fake_bin/uname" <<'EOF'
#!/usr/bin/env sh
case "${1:-}" in
    -s) printf 'Linux\n' ;;
    -m) printf '%s\n' "${SDBX_INSTALLER_TEST_MACHINE:-x86_64}" ;;
    *) printf 'Linux\n' ;;
esac
EOF

cat >"$fake_bin/curl" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

destination=""
write_out=""
url=""
while (($# > 0)); do
    case "$1" in
        --output)
            destination="$2"
            shift 2
            ;;
        --write-out)
            write_out="$2"
            shift 2
            ;;
        --proto | --proto-redir | --retry | --max-filesize)
            shift 2
            ;;
        --fail | --silent | --show-error | --location | --tlsv1.2 | --retry-all-errors)
            shift
            ;;
        *)
            url="$1"
            shift
            ;;
    esac
done

if [[ -n "$write_out" ]]; then
    [[ "$destination" == "/dev/null" ]]
    printf 'https://github.com/get-sdbx/sdbx/releases/tag/v1.2.3'
    exit 0
fi

[[ -n "$destination" && -n "$url" ]]
cp "$SDBX_INSTALLER_FIXTURE_DIR/${url##*/}" "$destination"
EOF

cat >"$fake_bin/cosign" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${1:-}" == "version" && "${2:-}" == "--json" ]]; then
    printf '{"gitVersion":"v%s.1.2"}\n' \
        "${SDBX_INSTALLER_COSIGN_MAJOR:-3}"
    exit 0
fi
if [[ "${SDBX_INSTALLER_COSIGN_FAIL:-0}" == "1" ]]; then
    exit 1
fi
arguments="$*"
[[ "$arguments" == *"--certificate-identity https://github.com/get-sdbx/sdbx/.github/workflows/release.yml@refs/tags/v1.2.3"* ]]
[[ "$arguments" == *"--certificate-oidc-issuer https://token.actions.githubusercontent.com"* ]]
EOF

cat >"$fake_bin/mv" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

source_argument=""
target_argument=""
for argument in "$@"; do
    source_argument="$target_argument"
    target_argument="$argument"
done
failure_target="${SDBX_INSTALLER_MV_FAIL_TARGET:-sdbxd}"
if [[ "${SDBX_INSTALLER_MV_FAIL:-0}" == "1" &&
    "$source_argument" == */."$failure_target".install.* &&
    "$target_argument" == */"$failure_target" ]]; then
    exit 1
fi
exec /bin/mv "$@"
EOF
chmod 0755 \
    "$fake_bin/uname" \
    "$fake_bin/curl" \
    "$fake_bin/cosign" \
    "$fake_bin/mv"

PATH="$fake_bin:$PATH" \
    SDBX_INSTALLER_FIXTURE_DIR="$fixture_dir" \
    "$repository_root/install.sh" \
    --version v1.2.3 \
    --install-dir "$install_dir" \
    --systemd-assets-dir "$systemd_assets_dir"

[[ -x "$install_dir/sdbx" && -x "$install_dir/sdbxd" ]] ||
    fail "verified installation did not install both binaries"
for asset in sdbxd.service sdbx-web.service sdbxd.env.example; do
    [[ -f "$systemd_assets_dir/$asset" &&
        ! -L "$systemd_assets_dir/$asset" ]] ||
        fail "verified installation did not preserve $asset"
    asset_mode="$(
        stat -c '%a' "$systemd_assets_dir/$asset" 2>/dev/null ||
            stat -f '%Lp' "$systemd_assets_dir/$asset"
    )"
    [[ "$asset_mode" == "644" ]] ||
        fail "verified systemd asset has the wrong mode: $asset"
done
grep -Fq "ExecStart=$install_dir/sdbxd " \
    "$systemd_assets_dir/sdbxd.service" ||
    fail "installed daemon unit does not use the selected binary directory"
grep -Fq "ExecStart=$install_dir/sdbx serve " \
    "$systemd_assets_dir/sdbx-web.service" ||
    fail "installed Web unit does not use the selected binary directory"

arm64_install_dir="$test_root/arm64-install"
arm64_output="$(
    PATH="$fake_bin:$PATH" \
        SDBX_INSTALLER_FIXTURE_DIR="$fixture_dir" \
        SDBX_INSTALLER_TEST_MACHINE=aarch64 \
        "$repository_root/install.sh" \
        --version v1.2.3 \
        --install-dir "$arm64_install_dir"
)"
[[ -x "$arm64_install_dir/sdbx" && -x "$arm64_install_dir/sdbxd" ]] ||
    fail "verified arm64 installation did not install both binaries"
[[ "$arm64_output" == *"Linux arm64 is a compatibility build"* ]] ||
    fail "arm64 installation did not disclose its compatibility support status"

latest_install_dir="$test_root/latest-install"
PATH="$fake_bin:$PATH" \
    SDBX_INSTALLER_FIXTURE_DIR="$fixture_dir" \
    "$repository_root/install.sh" \
    --install-dir "$latest_install_dir"
[[ -x "$latest_install_dir/sdbx" && -x "$latest_install_dir/sdbxd" ]] ||
    fail "latest-release resolution did not install both binaries"

rollback_install_dir="$test_root/rollback-install"
mkdir -p "$rollback_install_dir"
printf 'previous sdbx\n' >"$rollback_install_dir/sdbx"
printf 'previous sdbxd\n' >"$rollback_install_dir/sdbxd"
chmod 0755 "$rollback_install_dir/sdbx" "$rollback_install_dir/sdbxd"
if PATH="$fake_bin:$PATH" \
    SDBX_INSTALLER_FIXTURE_DIR="$fixture_dir" \
    SDBX_INSTALLER_MV_FAIL=1 \
    "$repository_root/install.sh" \
    --version v1.2.3 \
    --install-dir "$rollback_install_dir"; then
    fail "installer accepted a partial binary commit"
fi
[[ "$(cat "$rollback_install_dir/sdbx")" == "previous sdbx" ]] ||
    fail "failed installation did not restore the previous sdbx binary"
[[ "$(cat "$rollback_install_dir/sdbxd")" == "previous sdbxd" ]] ||
    fail "failed installation did not restore the previous sdbxd binary"
if find "$rollback_install_dir" -name '.*.install.*' -o -name '.*.backup.*' |
    grep -q .; then
    fail "failed installation left staging or backup files behind"
fi

asset_rollback_install_dir="$test_root/asset-rollback-install"
asset_rollback_systemd_dir="$test_root/asset-rollback-systemd"
mkdir -p "$asset_rollback_install_dir" "$asset_rollback_systemd_dir"
for file in sdbx sdbxd; do
    printf 'previous %s\n' "$file" >"$asset_rollback_install_dir/$file"
    chmod 0755 "$asset_rollback_install_dir/$file"
done
for file in sdbxd.service sdbx-web.service sdbxd.env.example; do
    printf 'previous %s\n' "$file" >"$asset_rollback_systemd_dir/$file"
    chmod 0644 "$asset_rollback_systemd_dir/$file"
done
if PATH="$fake_bin:$PATH" \
    SDBX_INSTALLER_FIXTURE_DIR="$fixture_dir" \
    SDBX_INSTALLER_MV_FAIL=1 \
    SDBX_INSTALLER_MV_FAIL_TARGET=sdbx-web.service \
    "$repository_root/install.sh" \
    --version v1.2.3 \
    --install-dir "$asset_rollback_install_dir" \
    --systemd-assets-dir "$asset_rollback_systemd_dir"; then
    fail "installer accepted a partial systemd asset commit"
fi
for file in sdbx sdbxd; do
    [[ "$(cat "$asset_rollback_install_dir/$file")" == "previous $file" ]] ||
        fail "asset failure did not restore the previous $file binary"
done
for file in sdbxd.service sdbx-web.service sdbxd.env.example; do
    [[ "$(cat "$asset_rollback_systemd_dir/$file")" == "previous $file" ]] ||
        fail "asset failure did not restore the previous $file"
done

signature_failure_dir="$test_root/signature-failure"
if PATH="$fake_bin:$PATH" \
    SDBX_INSTALLER_FIXTURE_DIR="$fixture_dir" \
    SDBX_INSTALLER_COSIGN_FAIL=1 \
    "$repository_root/install.sh" \
    --version v1.2.3 \
    --install-dir "$signature_failure_dir"; then
    fail "installer accepted a failed Sigstore verification"
fi
[[ ! -e "$signature_failure_dir/sdbx" && ! -e "$signature_failure_dir/sdbxd" ]] ||
    fail "signature failure wrote an installed binary"

cosign_version_failure_dir="$test_root/cosign-version-failure"
if PATH="$fake_bin:$PATH" \
    SDBX_INSTALLER_FIXTURE_DIR="$fixture_dir" \
    SDBX_INSTALLER_COSIGN_MAJOR=2 \
    "$repository_root/install.sh" \
    --version v1.2.3 \
    --install-dir "$cosign_version_failure_dir"; then
    fail "installer accepted unsupported cosign v2"
fi
[[ ! -e "$cosign_version_failure_dir/sdbx" &&
    ! -e "$cosign_version_failure_dir/sdbxd" ]] ||
    fail "cosign version failure wrote an installed binary"

cat >"$payload_dir/sdbx" <<'EOF'
#!/usr/bin/env sh
if [ "${1:-}" = "version" ]; then
    printf 'sdbx 9.9.9\n'
    exit 0
fi
exit 1
EOF
chmod 0755 "$payload_dir/sdbx"
build_archive amd64
write_checksum_manifest

version_failure_dir="$test_root/version-failure"
if PATH="$fake_bin:$PATH" \
    SDBX_INSTALLER_FIXTURE_DIR="$fixture_dir" \
    "$repository_root/install.sh" \
    --version v1.2.3 \
    --install-dir "$version_failure_dir"; then
    fail "installer accepted a mismatched binary version"
fi
[[ ! -e "$version_failure_dir/sdbx" && ! -e "$version_failure_dir/sdbxd" ]] ||
    fail "version failure wrote an installed binary"

cat >"$payload_dir/sdbx" <<'EOF'
#!/usr/bin/env sh
if [ "${1:-}" = "version" ]; then
    printf 'sdbx 1.2.3\n'
    exit 0
fi
exit 1
EOF
chmod 0755 "$payload_dir/sdbx"
build_archive amd64
write_checksum_manifest

rm -f "$payload_dir/README.md"
ln -s LICENSE "$payload_dir/README.md"
build_archive amd64
write_checksum_manifest

unsafe_archive_dir="$test_root/unsafe-archive"
if PATH="$fake_bin:$PATH" \
    SDBX_INSTALLER_FIXTURE_DIR="$fixture_dir" \
    "$repository_root/install.sh" \
    --version v1.2.3 \
    --install-dir "$unsafe_archive_dir"; then
    fail "installer accepted a symlink archive entry"
fi
[[ ! -e "$unsafe_archive_dir/sdbx" && ! -e "$unsafe_archive_dir/sdbxd" ]] ||
    fail "unsafe archive failure wrote an installed binary"

rm -f "$payload_dir/README.md"
printf 'synthetic README.md\n' >"$payload_dir/README.md"
build_archive amd64
write_checksum_manifest

duplicate_checksum="$(
    awk '$2 == "sdbx_1.2.3_linux_amd64.tar.gz" { print; exit }' \
        "$fixture_dir/checksums.txt"
)"
printf '%s\n' "$duplicate_checksum" >>"$fixture_dir/checksums.txt"
duplicate_checksum_dir="$test_root/duplicate-checksum"
if PATH="$fake_bin:$PATH" \
    SDBX_INSTALLER_FIXTURE_DIR="$fixture_dir" \
    "$repository_root/install.sh" \
    --version v1.2.3 \
    --install-dir "$duplicate_checksum_dir"; then
    fail "installer accepted a duplicate archive checksum"
fi
[[ ! -e "$duplicate_checksum_dir/sdbx" &&
    ! -e "$duplicate_checksum_dir/sdbxd" ]] ||
    fail "duplicate checksum failure wrote an installed binary"
write_checksum_manifest

archive_name="sdbx_1.2.3_linux_amd64.tar.gz"
printf 'tamper\n' >>"$fixture_dir/$archive_name"
checksum_failure_dir="$test_root/checksum-failure"
if PATH="$fake_bin:$PATH" \
    SDBX_INSTALLER_FIXTURE_DIR="$fixture_dir" \
    "$repository_root/install.sh" \
    --version v1.2.3 \
    --install-dir "$checksum_failure_dir"; then
    fail "installer accepted a checksum mismatch"
fi
[[ ! -e "$checksum_failure_dir/sdbx" && ! -e "$checksum_failure_dir/sdbxd" ]] ||
    fail "checksum failure wrote an installed binary"

printf 'installer architectures, transaction rollback, version, archive safety, cosign, signature, checksum, latest, and failure tests passed\n'
