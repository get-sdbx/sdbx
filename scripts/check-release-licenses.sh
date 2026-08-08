#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

repository_root="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/.."
    pwd
)"
readonly repository_root
readonly dist_dir="${1:-$repository_root/dist}"
readonly coreos_expression="Apache-2.0 AND LicenseRef-dccd26c6fd9c296daf44d0bc56bb4efc566edd4880381b3331c9a63e6e471338"
work_dir="$(mktemp -d)"

cleanup() {
    if [[ -n "$work_dir" && -d "$work_dir" ]]; then
        rm -rf -- "$work_dir"
    fi
}
trap cleanup EXIT

fail() {
    printf 'release license verification failed: %s\n' "$*" >&2
    exit 1
}

command -v jq >/dev/null 2>&1 ||
    fail "required command is unavailable: jq"

if command -v grant >/dev/null 2>&1; then
    grant_command=(grant)
elif command -v go >/dev/null 2>&1; then
    grant_command=(
        go run github.com/anchore/grant/cmd/grant@v0.6.8
    )
else
    fail "Grant is unavailable and Go cannot run the pinned fallback"
fi

sbom_count=0
for sbom in "$dist_dir"/*.spdx.json; do
    [[ -f "$sbom" ]] || fail "no SPDX SBOMs found in $dist_dir"
    sbom_count=$((sbom_count + 1))

    jq -e --arg expression "$coreos_expression" '
        [.packages[] | select(.name == "github.com/coreos/go-oidc/v3")] as $coreos
        | ($coreos | length) > 0
        and all(
            $coreos[];
            .versionInfo == "v3.20.0"
            and .licenseConcluded == $expression
        )
    ' "$sbom" >/dev/null ||
        fail "the reviewed CoreOS license exception changed in $(basename "$sbom")"

    grant_stderr="$work_dir/grant.stderr"
    if ! "${grant_command[@]}" -q check \
        --summary \
        --config "$repository_root/.grant.yaml" \
        "$sbom" \
        2>"$grant_stderr"; then
        cat "$grant_stderr" >&2
        fail "Grant rejected $(basename "$sbom")"
    fi

    if [[ -s "$grant_stderr" ]] &&
        sed '/unable to get license by ID: LicenseRef-dccd26c6fd9c296daf44d0bc56bb4efc566edd4880381b3331c9a63e6e471338; no matching spdx id found/d' \
            "$grant_stderr" |
            grep -q '[^[:space:]]'; then
        cat "$grant_stderr" >&2
        fail "Grant emitted an unexpected diagnostic for $(basename "$sbom")"
    fi
done
[[ "$sbom_count" == "2" ]] ||
    fail "expected two SPDX SBOMs, found $sbom_count"

printf 'release dependencies satisfy the reviewed license policy\n'
