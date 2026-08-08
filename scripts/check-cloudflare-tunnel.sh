#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

usage() {
    cat <<'EOF'
Usage:
  scripts/check-cloudflare-tunnel.sh \
    --account-id ACCOUNT_ID --tunnel-id UUID --route-plan FILE \
    [--fixture-dir DIRECTORY]

Read and verify the remotely managed Cloudflare Tunnel against the exact JSON
emitted by `sdbx tunnel routes --json`. Normal mode requires
CLOUDFLARE_API_TOKEN and performs only GET requests. --fixture-dir is reserved
for synthetic repository tests.
EOF
}

fail() {
    printf 'Cloudflare tunnel check failed: %s\n' "$*" >&2
    exit 1
}

account_id=""
tunnel_id=""
route_plan=""
fixture_dir=""
while (($# > 0)); do
    case "$1" in
        --account-id)
            (($# >= 2)) || fail "--account-id requires a value"
            account_id="$2"
            shift 2
            ;;
        --tunnel-id)
            (($# >= 2)) || fail "--tunnel-id requires a value"
            tunnel_id="$2"
            shift 2
            ;;
        --route-plan)
            (($# >= 2)) || fail "--route-plan requires a file"
            route_plan="$2"
            shift 2
            ;;
        --fixture-dir)
            (($# >= 2)) || fail "--fixture-dir requires a directory"
            fixture_dir="$2"
            shift 2
            ;;
        --help | -h)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

[[ "$account_id" =~ ^[a-f0-9]{32}$ ]] ||
    fail "--account-id must be a lowercase 32-character identifier"
[[ "$tunnel_id" =~ ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$ ]] ||
    fail "--tunnel-id must be a lowercase UUID"
command -v jq >/dev/null 2>&1 || fail "jq is required"
[[ -f "$route_plan" && ! -L "$route_plan" ]] ||
    fail "--route-plan must be a regular non-symlink file"
route_plan_size="$(wc -c <"$route_plan" | tr -d '[:space:]')"
[[ "$route_plan_size" =~ ^[0-9]+$ &&
    "$route_plan_size" -gt 0 &&
    "$route_plan_size" -le 1048576 ]] ||
    fail "--route-plan must contain between 1 byte and 1 MiB"
jq -e '
  .management == "remote" and
  (.routes | type == "array" and length > 0) and
  ([.routes[].hostname] | length == (unique | length)) and
  all(
    .routes[];
    (.hostname | type == "string") and
    (.hostname | test("^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$") and contains(".") and (contains("..") | not)) and
    .service == "http://traefik:8081"
  )
' "$route_plan" >/dev/null ||
    fail "--route-plan is not a valid SDBX remote route plan"

work_dir="$(mktemp -d)"
cleanup() {
    rm -rf -- "$work_dir"
}
trap cleanup EXIT

if [[ -n "$fixture_dir" ]]; then
    [[ -d "$fixture_dir" && ! -L "$fixture_dir" ]] ||
        fail "fixture directory must be a real directory"
else
    command -v curl >/dev/null 2>&1 || fail "curl is required"
    cloudflare_token="${CLOUDFLARE_API_TOKEN:-}"
    [[ "$cloudflare_token" =~ ^[A-Za-z0-9_-]{40,128}$ ]] ||
        fail "CLOUDFLARE_API_TOKEN is missing or malformed"
    curl_config="$work_dir/curl.conf"
    printf 'header = "Authorization: Bearer %s"\n' "$cloudflare_token" \
        >"$curl_config"
    chmod 0600 "$curl_config"
    unset cloudflare_token
fi

fetch_json() {
    local name="$1"
    local endpoint="$2"
    local destination="$work_dir/$name.json"
    if [[ -n "$fixture_dir" ]]; then
        local source="$fixture_dir/$name.json"
        [[ -f "$source" && ! -L "$source" ]] ||
            fail "missing regular fixture: $name.json"
        cp "$source" "$destination"
    else
        curl \
            --config "$curl_config" \
            --fail \
            --silent \
            --show-error \
            --proto '=https' \
            --tlsv1.2 \
            --max-time 30 \
            --max-filesize 1048576 \
            --output "$destination" \
            "https://api.cloudflare.com/client/v4/$endpoint"
    fi
    local size
    size="$(wc -c <"$destination" | tr -d '[:space:]')"
    [[ "$size" =~ ^[0-9]+$ && "$size" -gt 0 && "$size" -le 1048576 ]] ||
        fail "$name response must contain between 1 byte and 1 MiB"
    jq -e . "$destination" >/dev/null ||
        fail "$name response is not valid JSON"
    printf '%s\n' "$destination"
}

token_json="$(fetch_json token "accounts/$account_id/tokens/verify")"
tunnel_json="$(
    fetch_json tunnel "accounts/$account_id/cfd_tunnel/$tunnel_id"
)"
configuration_json="$(
    fetch_json configuration \
        "accounts/$account_id/cfd_tunnel/$tunnel_id/configurations"
)"

jq -e '
  .success == true and
  .result.status == "active" and
  (
    (.result.expires_on // null) == null or
    (
      .result.expires_on |
      type == "string" and
      (try (fromdateiso8601 > now) catch false)
    )
  )
' "$token_json" >/dev/null ||
    fail "API token is not active or has expired"

jq -e \
    --arg account "$account_id" \
    --arg tunnel "$tunnel_id" '
      .success == true and
      .result.id == $tunnel and
      .result.account_tag == $account and
      .result.config_src == "cloudflare" and
      .result.status == "healthy" and
      (.result.deleted_at // null) == null
    ' "$tunnel_json" >/dev/null ||
    fail "tunnel identity, remote-management mode, or health is invalid"

expected_hostnames="$(jq -c '[.routes[].hostname] | sort' "$route_plan")"
expected_origin="http://traefik:8081"

jq -e \
    --arg tunnel "$tunnel_id" \
    --arg origin "$expected_origin" \
    --argjson hostnames "$expected_hostnames" '
      .success == true and
      .result.tunnel_id == $tunnel and
      .result.source == "cloudflare" and
      (.result.config | type == "object") and
      ((.result.config.originRequest // {}) == {}) and
      (.result.config.ingress | type == "array") and
      (.result.config.ingress | length) == (($hostnames | length) + 1) and
      (.result.config.ingress as $ingress |
        ([$ingress[0:-1][].hostname] | sort) == ($hostnames | sort) and
        all(
          $hostnames[];
          . as $hostname |
          ([
            $ingress[] |
            select(
              .hostname == $hostname and
              .service == $origin and
              ((.path // "") == "") and
              ((.originRequest // {}) == {})
            )
          ] | length) == 1
        ) and
        ($ingress[-1].service == "http_status:404") and
        (($ingress[-1].hostname // "") == "") and
        (($ingress[-1].path // "") == "") and
        (($ingress[-1].originRequest // {}) == {})
      )
    ' "$configuration_json" >/dev/null ||
    fail "remote ingress must contain only the route-plan hostnames and terminal 404"

printf 'Cloudflare tunnel mapping check passed for %s\n' "$tunnel_id"
