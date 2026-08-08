#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

repository_root="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/.."
    pwd
)"
readonly repository_root
readonly verifier="$repository_root/scripts/check-cloudflare-tunnel.sh"
readonly account_id="0123456789abcdef0123456789abcdef"
readonly tunnel_id="01234567-89ab-cdef-0123-456789abcdef"
test_root="$(mktemp -d)"

cleanup() {
    rm -rf -- "$test_root"
}
trap cleanup EXIT

fail() {
    printf 'Cloudflare tunnel test failed: %s\n' "$*" >&2
    exit 1
}

fixture_dir="$test_root/valid"
mkdir -p "$fixture_dir"
route_plan="$test_root/route-plan.json"
cat >"$route_plan" <<'EOF'
{
  "management": "remote",
  "routes": [
    {"hostname":"auth.sdbx.example.test","service":"http://traefik:8081"},
    {"hostname":"filebrowser.sdbx.example.test","service":"http://traefik:8081"},
    {"hostname":"jellyfin.sdbx.example.test","service":"http://traefik:8081"},
    {"hostname":"nzbhydra.sdbx.example.test","service":"http://traefik:8081"},
    {"hostname":"prowlarr.sdbx.example.test","service":"http://traefik:8081"},
    {"hostname":"qbt.sdbx.example.test","service":"http://traefik:8081"},
    {"hostname":"sonarr.sdbx.example.test","service":"http://traefik:8081"}
  ],
  "urls": ["https://sdbx.example.test"]
}
EOF
cat >"$fixture_dir/token.json" <<'EOF'
{
  "success": true,
  "result": {
    "id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "status": "active",
    "expires_on": "2099-01-01T00:00:00Z"
  }
}
EOF
cat >"$fixture_dir/tunnel.json" <<EOF
{
  "success": true,
  "result": {
    "id": "$tunnel_id",
    "account_tag": "$account_id",
    "config_src": "cloudflare",
    "status": "healthy",
    "deleted_at": null
  }
}
EOF
cat >"$fixture_dir/configuration.json" <<EOF
{
  "success": true,
  "result": {
    "tunnel_id": "$tunnel_id",
    "source": "cloudflare",
    "config": {
      "ingress": [
        {"hostname":"auth.sdbx.example.test","service":"http://traefik:8081"},
        {"hostname":"filebrowser.sdbx.example.test","service":"http://traefik:8081"},
        {"hostname":"jellyfin.sdbx.example.test","service":"http://traefik:8081"},
        {"hostname":"nzbhydra.sdbx.example.test","service":"http://traefik:8081"},
        {"hostname":"prowlarr.sdbx.example.test","service":"http://traefik:8081"},
        {"hostname":"qbt.sdbx.example.test","service":"http://traefik:8081"},
        {"hostname":"sonarr.sdbx.example.test","service":"http://traefik:8081"},
        {"service":"http_status:404"}
      ]
    }
  }
}
EOF

"$verifier" \
    --account-id "$account_id" \
    --tunnel-id "$tunnel_id" \
    --route-plan "$route_plan" \
    --fixture-dir "$fixture_dir"

expect_failure() {
    local name="$1"
    local file="$2"
    local mutation="$3"
    local invalid_dir="$test_root/invalid-$name"
    cp -R "$fixture_dir" "$invalid_dir"
    jq "$mutation" "$invalid_dir/$file.json" >"$test_root/$name.json"
    mv "$test_root/$name.json" "$invalid_dir/$file.json"
    if "$verifier" \
        --account-id "$account_id" \
        --tunnel-id "$tunnel_id" \
        --route-plan "$route_plan" \
        --fixture-dir "$invalid_dir" >"$test_root/$name.out" 2>&1; then
        fail "$name unexpectedly passed"
    fi
}

expect_failure token-disabled token '.result.status = "disabled"'
expect_failure token-expired token '.result.expires_on = "2020-01-01T00:00:00Z"'
expect_failure tunnel-degraded tunnel '.result.status = "degraded"'
expect_failure tunnel-local tunnel '.result.config_src = "local"'
expect_failure configuration-wrong-tunnel configuration \
    '.result.tunnel_id = "11111111-2222-3333-4444-555555555555"'
expect_failure wrong-origin configuration \
    '.result.config.ingress[0].service = "http://legacy-traefik:80"'
expect_failure path-matcher configuration \
    '.result.config.ingress[0].path = "/auth"'
expect_failure host-override configuration \
    '.result.config.ingress[0].originRequest.httpHostHeader = "example.test"'
expect_failure global-origin-policy configuration \
    '.result.config.originRequest.httpHostHeader = "example.test"'
expect_failure missing-host configuration \
    '.result.config.ingress |=
       map(select(.hostname != "sonarr.sdbx.example.test"))'
expect_failure duplicate-host configuration \
    '.result.config.ingress[1].hostname = "auth.sdbx.example.test"'
expect_failure extra-host configuration \
    '.result.config.ingress |=
       .[0:-1] + [{"hostname":"extra.sdbx.example.test","service":"http://traefik:8081"}] +
       [.[-1]]'
expect_failure catchall-not-last configuration \
    '.result.config.ingress |= [.[-1]] + .[0:-1]'
expect_failure catchall-forwarding configuration \
    '.result.config.ingress[-1].service = "http://traefik:8081"'

invalid_plan="$test_root/invalid-plan.json"
jq '.routes[0].service = "http://unexpected:80"' "$route_plan" >"$invalid_plan"
if "$verifier" \
    --account-id "$account_id" \
    --tunnel-id "$tunnel_id" \
    --route-plan "$invalid_plan" \
    --fixture-dir "$fixture_dir" >"$test_root/invalid-plan.out" 2>&1; then
    fail "invalid route plan unexpectedly passed"
fi

printf '%s\n' \
    "Cloudflare tunnel verifier accepted the exact mapping and rejected drift"
