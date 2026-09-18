#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly go_image="golang:1.26.8-bookworm@sha256:9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81"
readonly shellcheck_image="koalaman/shellcheck:v0.11.0@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d"

fail() {
    printf 'CI container failed: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: scripts/run-ci-container.sh MODE

Run a pinned CI container without relying on host bind mounts. Supported modes:
  root-boundaries  Run root ownership and broker boundary tests.
  shellcheck       Check the repository shell scripts.
EOF
}

if (($# != 1)); then
    usage >&2
    exit 1
fi

for command in docker git; do
    command -v "$command" >/dev/null 2>&1 ||
        fail "required command is unavailable: $command"
done

git rev-parse --verify HEAD >/dev/null 2>&1 ||
    fail "the current directory is not a Git worktree with a valid HEAD"

container_id=""
cleanup() {
    if [[ -n "$container_id" ]]; then
        docker rm --force "$container_id" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

case "$1" in
    root-boundaries)
        archive_prefix="src/"
        container_id="$(
            docker create \
                --cap-drop ALL \
                --cap-add CHOWN \
                --cap-add DAC_OVERRIDE \
                --cap-add DAC_READ_SEARCH \
                --cap-add FOWNER \
                --security-opt no-new-privileges \
                --workdir /src \
                "$go_image" \
                go test -mod=readonly \
                ./internal/securefs \
                ./internal/backup \
                ./internal/management \
                ./internal/broker
        )"
        ;;
    shellcheck)
        archive_prefix="mnt/"
        container_id="$(
            docker create \
                --cap-drop ALL \
                --security-opt no-new-privileges \
                --workdir /mnt \
                "$shellcheck_image" \
                /mnt/install.sh \
                /mnt/scripts/audit-catalog-images.sh \
                /mnt/scripts/check-github-controls.sh \
                /mnt/scripts/check-release-licenses.sh \
                /mnt/scripts/check-workflow-actions.sh \
                /mnt/scripts/list-release-assets.sh \
                /mnt/scripts/run-ci-container.sh \
                /mnt/scripts/test-amd64-acceptance-evidence.sh \
                /mnt/scripts/test-github-controls.sh \
                /mnt/scripts/test-installer.sh \
                /mnt/scripts/test-release-assets.sh \
                /mnt/scripts/test-release-reproducibility.sh \
                /mnt/scripts/test-systemd-units.sh \
                /mnt/scripts/test-vpn-killswitch.sh \
                /mnt/scripts/test-workflow-actions.sh \
                /mnt/scripts/verify-amd64-acceptance-evidence.sh \
                /mnt/scripts/verify-release-artifacts.sh
        )"
        ;;
    --help | -h)
        usage
        exit 0
        ;;
    *)
        fail "unsupported mode: $1"
        ;;
esac
readonly archive_prefix container_id

git archive --format=tar --prefix="$archive_prefix" HEAD |
    docker cp - "$container_id:/"

docker start "$container_id" >/dev/null
container_status="$(docker wait "$container_id")"
docker logs "$container_id"

if [[ ! "$container_status" =~ ^[0-9]+$ ]]; then
    fail "Docker returned an invalid container status: $container_status"
fi
if ((container_status != 0)); then
    fail "container exited with status $container_status"
fi
