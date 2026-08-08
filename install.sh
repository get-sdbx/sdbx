#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly repository="get-sdbx/sdbx"
readonly github_origin="https://github.com"
readonly oidc_issuer="https://token.actions.githubusercontent.com"
readonly workflow_identity_prefix="https://github.com/get-sdbx/sdbx/.github/workflows/release.yml@refs/tags/"
readonly max_archive_bytes=$((256 * 1024 * 1024))
readonly max_metadata_bytes=$((4 * 1024 * 1024))

requested_version=""
requested_install_dir=""
requested_systemd_assets_dir=""
temporary_dir=""

log() {
    printf '%s\n' "$*"
}

fail() {
    printf 'sdbx installer: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [[ -n "$temporary_dir" && -d "$temporary_dir" ]]; then
        rm -rf -- "$temporary_dir"
    fi
}
trap cleanup EXIT

usage() {
    cat <<'EOF'
Usage: install.sh [--version vX.Y.Z[-PRERELEASE]] [--install-dir DIRECTORY]
                  [--systemd-assets-dir DIRECTORY]

Downloads the signed SDBX Linux release, verifies the keyless Sigstore
signature and SHA-256 checksum before extraction, and installs both `sdbx` and
`sdbxd`. When --systemd-assets-dir is set, the version-matched service units
and environment example are installed there in the same transaction.

Requirements: curl, tar, cosign v3, and sha256sum or shasum.
EOF
}

while (($# > 0)); do
    case "$1" in
        --version)
            (($# >= 2)) || fail "--version requires a value"
            requested_version="$2"
            shift 2
            ;;
        --install-dir)
            (($# >= 2)) || fail "--install-dir requires a value"
            requested_install_dir="$2"
            shift 2
            ;;
        --systemd-assets-dir)
            (($# >= 2)) || fail "--systemd-assets-dir requires a value"
            requested_systemd_assets_dir="$2"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

for command in awk curl tar cosign grep install mktemp sed; do
    command -v "$command" >/dev/null 2>&1 ||
        fail "required command is unavailable: $command"
done
if ! command -v sha256sum >/dev/null 2>&1 &&
    ! command -v shasum >/dev/null 2>&1; then
    fail "sha256sum or shasum is required"
fi
if ! cosign_version_json="$(cosign version --json 2>/dev/null)"; then
    fail "cosign v3 is required and its version could not be determined"
fi
cosign_major="$(
    printf '%s\n' "$cosign_version_json" |
        sed -n \
            's/.*"gitVersion"[[:space:]]*:[[:space:]]*"v\{0,1\}\([0-9][0-9]*\)\..*/\1/p'
)"
[[ "$cosign_major" == "3" ]] ||
    fail "cosign v3 is required"

case "$(uname -s)" in
    Linux) os_name="linux" ;;
    *) fail "SDBX v1 release artifacts support Linux hosts only" ;;
esac

case "$(uname -m)" in
    x86_64) architecture="amd64" ;;
    aarch64 | arm64)
        architecture="arm64"
        log "Linux arm64 is a compatibility build and does not carry the full v1 clean-host support guarantee."
        ;;
    *) fail "unsupported Linux architecture: $(uname -m)" ;;
esac

curl_secure() {
    local destination="$1"
    local url="$2"
    local maximum_bytes="$3"
    curl \
        --fail \
        --silent \
        --show-error \
        --location \
        --proto '=https' \
        --proto-redir '=https' \
        --tlsv1.2 \
        --retry 3 \
        --retry-all-errors \
        --max-filesize "$maximum_bytes" \
        --output "$destination" \
        "$url"
    local size
    size="$(wc -c <"$destination" | tr -d ' ')"
    [[ "$size" =~ ^[0-9]+$ && "$size" -gt 0 && "$size" -le "$maximum_bytes" ]] ||
        fail "downloaded file has an invalid size: $(basename "$destination")"
}

latest_release_version() {
    local effective_url
    effective_url="$(
        curl \
            --fail \
            --silent \
            --show-error \
            --location \
            --proto '=https' \
            --proto-redir '=https' \
            --tlsv1.2 \
            --retry 3 \
            --retry-all-errors \
            --output /dev/null \
            --write-out '%{url_effective}' \
            "$github_origin/$repository/releases/latest"
    )"
    printf '%s\n' "${effective_url##*/}"
}

version="$requested_version"
if [[ -z "$version" ]]; then
    log "Resolving the latest stable SDBX release..."
    version="$(latest_release_version)"
fi
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]] ||
    fail "release version must match vX.Y.Z or vX.Y.Z-PRERELEASE"

version_without_prefix="${version#v}"
archive_name="sdbx_${version_without_prefix}_${os_name}_${architecture}.tar.gz"
release_url="$github_origin/$repository/releases/download/$version"

temporary_dir="$(mktemp -d)"
chmod 0700 "$temporary_dir"
archive_path="$temporary_dir/$archive_name"
checksums_path="$temporary_dir/checksums.txt"
signature_path="$temporary_dir/checksums.txt.sigstore.json"

log "Downloading SDBX $version for $os_name/$architecture..."
curl_secure "$archive_path" "$release_url/$archive_name" "$max_archive_bytes"
curl_secure "$checksums_path" "$release_url/checksums.txt" "$max_metadata_bytes"
curl_secure \
    "$signature_path" \
    "$release_url/checksums.txt.sigstore.json" \
    "$max_metadata_bytes"

log "Verifying the signed checksum manifest..."
if ! cosign verify-blob \
    --bundle "$signature_path" \
    --certificate-identity "$workflow_identity_prefix$version" \
    --certificate-oidc-issuer "$oidc_issuer" \
    "$checksums_path" >/dev/null; then
    fail "signed checksum manifest verification failed"
fi

expected_checksum="$(
    awk -v archive="$archive_name" '
        $2 == archive && length($1) == 64 && $1 ~ /^[0-9a-fA-F]+$/ {
            count++
            checksum=tolower($1)
        }
        END {
            if (count == 1) {
                print checksum
            }
        }
    ' "$checksums_path"
)"
[[ "$expected_checksum" =~ ^[0-9a-f]{64}$ ]] ||
    fail "signed checksum manifest has no unique entry for $archive_name"

if command -v sha256sum >/dev/null 2>&1; then
    actual_checksum="$(sha256sum "$archive_path" | awk '{print tolower($1)}')"
else
    actual_checksum="$(shasum -a 256 "$archive_path" | awk '{print tolower($1)}')"
fi
[[ "$actual_checksum" == "$expected_checksum" ]] ||
    fail "archive checksum mismatch"

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
actual_entries="$(tar -tzf "$archive_path" | sed 's#^\./##' | LC_ALL=C sort)"
[[ "$actual_entries" == "$expected_entries" ]] ||
    fail "archive contents differ from the release allowlist"
if ! tar -tvzf "$archive_path" | awk '$1 !~ /^-/ { exit 1 }'; then
    fail "archive contains a symlink or another non-regular entry"
fi

extract_dir="$temporary_dir/extract"
install -d -m 0700 "$extract_dir"
tar -xzf "$archive_path" -C "$extract_dir"
for binary in sdbx sdbxd; do
    [[ -f "$extract_dir/$binary" && ! -L "$extract_dir/$binary" ]] ||
        fail "archive does not contain a regular $binary binary"
done
for asset in sdbxd.service sdbx-web.service sdbxd.env.example; do
    asset_path="$extract_dir/packaging/systemd/$asset"
    [[ -f "$asset_path" && ! -L "$asset_path" ]] ||
        fail "archive does not contain a regular $asset asset"
done

expected_binary_version="$version_without_prefix"
if ! cli_version_output="$("$extract_dir/sdbx" version)"; then
    fail "downloaded sdbx binary cannot report its version"
fi
cli_version_line="${cli_version_output%%$'\n'*}"
[[ "$cli_version_line" == "sdbx $expected_binary_version" ]] ||
    fail "downloaded sdbx version does not match $version"

if ! daemon_version_output="$("$extract_dir/sdbxd" -version)"; then
    fail "downloaded sdbxd binary cannot report its version"
fi
daemon_version_prefix="sdbxd $expected_binary_version (commit "
[[ "$daemon_version_output" == \
    "$daemon_version_prefix"*", built "*")" ]] ||
    fail "downloaded sdbxd version does not match $version"

if [[ -n "$requested_install_dir" ]]; then
    install_dir="$requested_install_dir"
else
    install_dir="/usr/local/bin"
    if [[ ! -d "$install_dir" || ! -w "$install_dir" ]]; then
        install_dir="${HOME:?HOME is required}/.local/bin"
    fi
fi

if [[ -e "$install_dir" && ( ! -d "$install_dir" || -L "$install_dir" ) ]]; then
    fail "install directory must be a real directory: $install_dir"
fi
install -d -m 0755 "$install_dir"
[[ -w "$install_dir" ]] ||
    fail "install directory is not writable: $install_dir"

if [[ -n "$requested_systemd_assets_dir" ]]; then
    systemd_assets_dir="$requested_systemd_assets_dir"
    if [[ -e "$systemd_assets_dir" &&
        ( ! -d "$systemd_assets_dir" || -L "$systemd_assets_dir" ) ]]; then
        fail "systemd assets directory must be a real directory: $systemd_assets_dir"
    fi
    install -d -m 0755 "$systemd_assets_dir"
    [[ -w "$systemd_assets_dir" ]] ||
        fail "systemd assets directory is not writable: $systemd_assets_dir"

    [[ "$install_dir" =~ ^/[A-Za-z0-9._/-]+$ &&
        "$install_dir" != "/" &&
        "$install_dir" != */ &&
        "$install_dir" != *"//"* &&
        ! "$install_dir" =~ (^|/)\.\.?(/|$) ]] ||
        fail "systemd binary install path must be an absolute path without whitespace, repeated separators, or dot segments"
fi

log "Installing both binaries into $install_dir..."
install_sources=(
    "$extract_dir/sdbx"
    "$extract_dir/sdbxd"
)
install_targets=(
    "$install_dir/sdbx"
    "$install_dir/sdbxd"
)
install_modes=(
    "0755"
    "0755"
)
install_labels=(
    "sdbx binary"
    "sdbxd binary"
)
if [[ -n "$requested_systemd_assets_dir" ]]; then
    log "Installing version-matched systemd assets into $systemd_assets_dir..."
    rendered_systemd_dir="$temporary_dir/rendered-systemd"
    install -d -m 0700 "$rendered_systemd_dir"
    for service in sdbxd.service sdbx-web.service; do
        awk -v binary_dir="$install_dir" '
          /^ExecStart=\/usr\/local\/bin\/sdbxd([[:space:]]|$)/ {
              sub(/^ExecStart=\/usr\/local\/bin\/sdbxd/, "ExecStart=" binary_dir "/sdbxd")
              daemon_replacements++
          }
          /^ExecStart=\/usr\/local\/bin\/sdbx([[:space:]]|$)/ {
              sub(/^ExecStart=\/usr\/local\/bin\/sdbx/, "ExecStart=" binary_dir "/sdbx")
              cli_replacements++
          }
          { print }
          END {
              expected_daemon = (FILENAME ~ /sdbxd\.service$/) ? 1 : 0
              expected_cli = (FILENAME ~ /sdbx-web\.service$/) ? 1 : 0
              if (daemon_replacements != expected_daemon || cli_replacements != expected_cli) {
                  exit 1
              }
          }
        ' "$extract_dir/packaging/systemd/$service" \
            >"$rendered_systemd_dir/$service" ||
            fail "could not bind $service to the selected binary install path"
        grep -Fq "ExecStart=$install_dir/" "$rendered_systemd_dir/$service" ||
            fail "$service does not reference the selected binary install path"
    done

    for asset in sdbxd.service sdbx-web.service sdbxd.env.example; do
        if [[ "$asset" == "sdbxd.env.example" ]]; then
            asset_source="$extract_dir/packaging/systemd/$asset"
        else
            asset_source="$rendered_systemd_dir/$asset"
        fi
        install_sources+=("$asset_source")
        install_targets+=("$systemd_assets_dir/$asset")
        install_modes+=("0644")
        install_labels+=("$asset systemd asset")
    done
fi

staged_targets=()
backup_targets=()
new_targets_installed=()
install_commit_complete=false

rollback_installation() {
    [[ "$install_commit_complete" == "false" ]] || return 0
    set +e
    local index
    for ((index = ${#install_targets[@]} - 1; index >= 0; index--)); do
        local target="${install_targets[$index]:-}"
        local staged="${staged_targets[$index]:-}"
        local backup="${backup_targets[$index]:-}"
        local installed="${new_targets_installed[$index]:-false}"

        if [[ -n "$backup" && -f "$backup" && ! -L "$backup" ]]; then
            mv -f -- "$backup" "$target" ||
                printf 'sdbx installer: failed to restore %s\n' "$target" >&2
        elif [[ "$installed" == "true" &&
            -f "$target" && ! -L "$target" ]]; then
            rm -f -- "$target"
        fi
        if [[ -n "$staged" && -f "$staged" && ! -L "$staged" ]]; then
            rm -f -- "$staged"
        fi
    done
}
trap 'rollback_installation; cleanup' EXIT

for index in "${!install_targets[@]}"; do
    target="${install_targets[$index]}"
    target_dir="${target%/*}"
    target_name="${target##*/}"
    if [[ -e "$target" || -L "$target" ]]; then
        [[ -f "$target" && ! -L "$target" ]] ||
            fail "existing install target must be a regular file: $target"
    fi
    staged_target="$(mktemp "$target_dir/.${target_name}.install.XXXXXX")"
    install \
        -m "${install_modes[$index]}" \
        "${install_sources[$index]}" \
        "$staged_target"
    staged_targets+=("$staged_target")
    backup_targets+=("")
    new_targets_installed+=(false)
done

for index in "${!install_targets[@]}"; do
    target="${install_targets[$index]}"
    if [[ -f "$target" && ! -L "$target" ]]; then
        target_dir="${target%/*}"
        target_name="${target##*/}"
        backup_target="$(mktemp "$target_dir/.${target_name}.backup.XXXXXX")"
        if ! mv -f -- "$target" "$backup_target"; then
            rm -f -- "$backup_target"
            fail "could not stage the existing ${install_labels[$index]} for replacement"
        fi
        backup_targets[index]="$backup_target"
    fi
done

for index in "${!install_targets[@]}"; do
    if ! mv -f -- "${staged_targets[$index]}" "${install_targets[$index]}"; then
        fail "could not commit the ${install_labels[$index]}"
    fi
    staged_targets[index]=""
    new_targets_installed[index]=true
done

"${install_targets[0]}" version
"${install_targets[1]}" -version
install_commit_complete=true
for backup_target in "${backup_targets[@]}"; do
    if [[ -n "$backup_target" ]]; then
        if ! rm -f -- "$backup_target"; then
            printf 'sdbx installer: remove stale backup manually: %s\n' \
                "$backup_target" >&2
        fi
    fi
done
trap cleanup EXIT
if [[ -n "$requested_systemd_assets_dir" ]]; then
    log "Systemd assets are verified and staged in: $systemd_assets_dir"
fi
log "SDBX $version is installed. Initialize a project with: sdbx init"
