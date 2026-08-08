#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

repository_root="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/.."
    pwd
)"
readonly repository_root
readonly ubuntu_image="ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90"
readonly container_name="sdbx-systemd-unit-test-$$-${RANDOM}"

cleanup() {
    docker rm --force "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
    printf 'systemd unit test failed: %s\n' "$*" >&2
    exit 1
}

command -v docker >/dev/null 2>&1 || {
    fail "docker is unavailable"
}

docker create \
    --name "$container_name" \
    --security-opt no-new-privileges \
    "$ubuntu_image" \
    bash -Eeuo pipefail -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends systemd >/dev/null

        cp /units/sdbxd.service /etc/systemd/system/
        cp /units/sdbx-web.service /etc/systemd/system/
        printf "%s\n" \
            "[Unit]" \
            "Description=Synthetic Docker dependency" \
            "[Service]" \
            "Type=oneshot" \
            "ExecStart=/bin/true" \
            "RemainAfterExit=yes" \
            >/etc/systemd/system/docker.service
        install -m 0755 /dev/null /usr/local/bin/sdbx
        install -m 0755 /dev/null /usr/local/bin/sdbxd

        systemd-analyze verify \
            /etc/systemd/system/sdbxd.service \
            /etc/systemd/system/sdbx-web.service
        report="$(
            systemd-analyze security \
                --offline=yes \
                --no-pager \
                /etc/systemd/system/sdbxd.service \
                /etc/systemd/system/sdbx-web.service
        )"
        printf "%s\n" "$report" | grep "Overall exposure level"
        test "$(
            printf "%s\n" "$report" |
                grep -c "Overall exposure level.* OK"
        )" -eq 2
    ' >/dev/null

# Upload through the Docker API so remote DinD daemons receive the reviewed
# unit files instead of resolving a runner-local bind-mount path.
docker cp "$repository_root/packaging/systemd/." "$container_name:/units"
docker start "$container_name" >/dev/null
container_status="$(docker wait "$container_name")"
docker logs "$container_name"
[[ "$container_status" == "0" ]] ||
    fail "container exited with status $container_status"
