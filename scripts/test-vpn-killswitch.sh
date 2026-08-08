#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly confirmation_phrase="interrupt-vpn-and-recreate-download-services"

mode="plan"
project_dir=""
sdbx_bin="sdbx"
confirmation=""
acknowledge_disposable_host=false
acknowledge_backup_tested=false
acknowledge_no_active_downloads=false
recovery_required=false
recovery_complete=false

usage() {
    cat <<EOF
Usage:
  scripts/test-vpn-killswitch.sh --plan
  scripts/test-vpn-killswitch.sh --execute --project-dir DIR \\
    --acknowledge-disposable-host \\
    --acknowledge-backup-tested \\
    --acknowledge-no-active-downloads \\
    --confirm $confirmation_phrase

This maintainer-only QA proof deliberately stops Gluetun and force-recreates
Gluetun and qBittorrent. The default --plan mode does not inspect or mutate a
stack. Never use --execute on a production host or while downloads are active.
EOF
}

fail() {
    printf 'VPN kill-switch proof failed: %s\n' "$*" >&2
    exit 1
}

while (($# > 0)); do
    case "$1" in
        --plan)
            mode="plan"
            shift
            ;;
        --execute)
            mode="execute"
            shift
            ;;
        --project-dir)
            (($# >= 2)) || fail "--project-dir requires a value"
            project_dir="$2"
            shift 2
            ;;
        --sdbx-bin)
            (($# >= 2)) || fail "--sdbx-bin requires a value"
            sdbx_bin="$2"
            shift 2
            ;;
        --acknowledge-disposable-host)
            acknowledge_disposable_host=true
            shift
            ;;
        --acknowledge-backup-tested)
            acknowledge_backup_tested=true
            shift
            ;;
        --acknowledge-no-active-downloads)
            acknowledge_no_active_downloads=true
            shift
            ;;
        --confirm)
            (($# >= 2)) || fail "--confirm requires a value"
            confirmation="$2"
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

if [[ "$mode" == "plan" ]]; then
    printf '%s\n' \
        "Destructive VPN kill-switch proof plan:" \
        "  1. Verify the lock, generated Compose model, live VPN status, and namespace topology." \
        "  2. Stop Gluetun while leaving the qBittorrent workload under observation." \
        "  3. Prove the external probe is reachable from the host but unreachable from qBittorrent." \
        "  4. Force-recreate Gluetun and qBittorrent, including on failure or interruption." \
        "  5. Re-verify namespace topology and distinct VPN egress." \
        "" \
        "No stack was inspected or changed."
    exit 0
fi

[[ "$acknowledge_disposable_host" == "true" ]] ||
    fail "--acknowledge-disposable-host is required"
[[ "$acknowledge_backup_tested" == "true" ]] ||
    fail "--acknowledge-backup-tested is required"
[[ "$acknowledge_no_active_downloads" == "true" ]] ||
    fail "--acknowledge-no-active-downloads is required"
[[ "$confirmation" == "$confirmation_phrase" ]] ||
    fail "exact confirmation is required: --confirm $confirmation_phrase"
[[ -n "$project_dir" ]] || fail "--project-dir is required"
[[ "$(uname -s)" == "Linux" ]] ||
    fail "--execute is supported only on the disposable Linux release-test host"

for command in curl docker; do
    command -v "$command" >/dev/null 2>&1 ||
        fail "required command is unavailable: $command"
done
if [[ "$sdbx_bin" == */* ]]; then
    [[ -x "$sdbx_bin" ]] || fail "SDBX binary is not executable: $sdbx_bin"
else
    command -v "$sdbx_bin" >/dev/null 2>&1 ||
        fail "SDBX binary is unavailable: $sdbx_bin"
fi

[[ -d "$project_dir" ]] || fail "project directory does not exist: $project_dir"
project_dir="$(
    cd "$project_dir"
    pwd -P
)"
readonly project_dir
[[ -f "$project_dir/.sdbx.yaml" && ! -L "$project_dir/.sdbx.yaml" ]] ||
    fail "project config must be a regular, non-symlink file"
[[ -f "$project_dir/.sdbx.lock" && ! -L "$project_dir/.sdbx.lock" ]] ||
    fail "project lock must be a regular, non-symlink file"
[[ -f "$project_dir/compose.yaml" && ! -L "$project_dir/compose.yaml" ]] ||
    fail "Compose model must be a regular, non-symlink file"

compose=(
    docker compose
    -f "$project_dir/compose.yaml"
    -p sdbx
)

run_sdbx() {
    (
        cd "$project_dir"
        "$sdbx_bin" "$@"
    )
}

container_id() {
    local service="$1"
    local id
    id="$("${compose[@]}" ps --all -q "$service")"
    [[ "$id" =~ ^[0-9a-f]{12,64}$ ]] ||
        fail "expected exactly one $service container"
    printf '%s\n' "$id"
}

verify_topology() {
    local gluetun_id
    local qbittorrent_id
    local network_mode
    local port_bindings

    gluetun_id="$(container_id gluetun)"
    qbittorrent_id="$(container_id qbittorrent)"
    [[ "$(docker inspect --format '{{.State.Running}}' "$gluetun_id")" == "true" ]] ||
        fail "Gluetun is not running"
    [[ "$(docker inspect --format '{{.State.Running}}' "$qbittorrent_id")" == "true" ]] ||
        fail "qBittorrent is not running"

    network_mode="$(
        docker inspect --format '{{.HostConfig.NetworkMode}}' "$qbittorrent_id"
    )"
    [[ "$network_mode" == "container:$gluetun_id" ]] ||
        fail "qBittorrent does not share the active Gluetun network namespace"

    port_bindings="$(
        docker inspect --format '{{json .HostConfig.PortBindings}}' "$qbittorrent_id"
    )"
    [[ "$port_bindings" == "null" || "$port_bindings" == "{}" ]] ||
        fail "qBittorrent unexpectedly owns host port bindings"
}

recover_stack() {
    "${compose[@]}" up \
        -d \
        --force-recreate \
        --wait \
        --wait-timeout 120 \
        gluetun \
        qbittorrent
    verify_topology
    run_sdbx --json vpn status >/dev/null
}

on_exit() {
    local status=$?
    trap - EXIT INT TERM
    if [[ "$recovery_required" == "true" && "$recovery_complete" != "true" ]]; then
        printf 'Recovery required; force-recreating Gluetun and qBittorrent...\n' >&2
        if ! recover_stack; then
            printf '%s\n' \
                "AUTOMATIC RECOVERY FAILED." \
                "Keep download automation disabled and recover from the project directory with:" \
                "  docker compose -f compose.yaml -p sdbx up -d --force-recreate --wait --wait-timeout 120 gluetun qbittorrent" \
                "  sdbx vpn status" >&2
            status=1
        else
            recovery_complete=true
            printf 'Automatic recovery completed and VPN protection was re-verified.\n' >&2
        fi
    fi
    exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"${compose[@]}" config --quiet
run_sdbx --no-tui lock verify >/dev/null
verify_topology
run_sdbx --json vpn status >/dev/null
curl \
    --fail \
    --silent \
    --show-error \
    --max-time 8 \
    --output /dev/null \
    https://api.ipify.org

recovery_required=true
"${compose[@]}" stop --timeout 15 gluetun

if [[ "$(docker inspect --format '{{.State.Running}}' "$(container_id gluetun)")" == "true" ]]; then
    fail "Gluetun remained running after the outage was requested"
fi

curl \
    --fail \
    --silent \
    --show-error \
    --max-time 8 \
    --output /dev/null \
    https://api.ipify.org ||
    fail "the host could not reach the independent egress probe"

qbittorrent_id="$(container_id qbittorrent)"
if docker exec "$qbittorrent_id" \
    curl \
    --fail \
    --silent \
    --show-error \
    --max-time 8 \
    --output /dev/null \
    https://api.ipify.org >/dev/null 2>&1; then
    fail "qBittorrent retained public egress after Gluetun stopped"
fi

recover_stack
recovery_complete=true
printf 'VPN kill-switch proof passed; qBittorrent failed closed and recovery was verified.\n'
