#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

readonly grype_image="anchore/grype@sha256:391bfda62888fb4e98ff5c4c81598f7431a3c1eac3f8519d69d1ff00df247c1d"
readonly grype_version="0.112.0"
readonly default_output_dir="output/catalog-image-audit"
repository_root="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/.."
    pwd -P
)"
readonly repository_root
script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/$(basename "${BASH_SOURCE[0]}")"
readonly script_path

usage() {
    cat <<'EOF'
Usage:
  scripts/audit-catalog-images.sh --inventory-only [OUTPUT_DIR]
  scripts/audit-catalog-images.sh --scan [OUTPUT_DIR]

Inventory mode resolves all embedded service images to immutable Linux amd64
and arm64 manifest digests without pulling or executing their layers.

Scan mode runs digest-pinned Grype in a hardened container, scans every exact
platform digest, and preserves JSON evidence. Upstream findings are reported
without suppression and do not fail the audit by severity alone. The audit
still fails closed when its inventory, scanner, database, or evidence is
incomplete or inconsistent. Scans run serially and refuse concurrent
invocations. Grype's cataloging can return incomplete-but-successful reports
under memory pressure, so parallel catalog scans are intentionally unsupported.
EOF
}

fail() {
    printf 'catalog image audit failed: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 ||
        fail "required command is unavailable: $1"
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

run_grype() {
    local cache_dir="$1"
    local temp_dir="$2"
    shift 2
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --cap-drop ALL \
        --security-opt no-new-privileges:true \
        --read-only \
        --env HOME=/tmp \
        --env GRYPE_CHECK_FOR_APP_UPDATE=false \
        --env GRYPE_DB_AUTO_UPDATE=false \
        --env GRYPE_DB_CACHE_DIR=/var/lib/grype/db \
        --mount "type=bind,src=${cache_dir},dst=/var/lib/grype/db" \
        --mount "type=bind,src=${temp_dir},dst=/tmp" \
        "$grype_image" "$@"
}

scan_one() {
    (($# == 4)) || fail "invalid internal scan invocation"
    local audit_dir="$2"
    local cache_dir="$3"
    local record="$4"
    local service
    local platform
    local reference
    local index_digest
    local safe_platform
    local report
    local report_tmp
    local scan_log
    local summary
    local summary_tmp
    local temp_dir
    local expected_digest

    service="$(jq -r '.service' <<<"$record")"
    platform="$(jq -r '.platform' <<<"$record")"
    reference="$(jq -r '.reference' <<<"$record")"
    index_digest="$(jq -r '.indexDigest' <<<"$record")"
    [[ "$service" =~ ^[a-z0-9][a-z0-9-]*$ ]] ||
        fail "unsafe service in inventory record"
    [[ "$platform" =~ ^linux/(amd64|arm64)$ ]] ||
        fail "unsafe platform in inventory record"
    [[ "$reference" =~ ^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$ ]] ||
        fail "unsafe immutable reference in inventory record"
    [[ "$index_digest" =~ ^sha256:[0-9a-f]{64}$ ]] ||
        fail "unsafe index digest in inventory record"

    safe_platform="${platform//\//-}"
    report="$audit_dir/reports/${service}-${safe_platform}.grype.json"
    scan_log="$audit_dir/logs/${service}-${safe_platform}.stderr.log"
    summary="$audit_dir/summaries/${service}-${safe_platform}.json"
    temp_dir="$audit_dir/tmp/${service}-${safe_platform}"
    mkdir -p "$temp_dir"
    chmod 0700 "$temp_dir"
    report_tmp="$(mktemp "$audit_dir/reports/.report.XXXXXX")"
    if ! run_grype "$cache_dir" "$temp_dir" \
        "registry:$reference" \
        --platform "$platform" \
        --quiet \
        --output json >"$report_tmp" 2>"$scan_log"; then
        rm -f "$report_tmp"
        sed 's/^/catalog image audit: scanner: /' "$scan_log" >&2
        fail "Grype could not scan $service for $platform"
    fi
    mv "$report_tmp" "$report"
    expected_digest="${reference##*@}"
    if ! jq -e \
        --arg digest "$expected_digest" \
        --arg platform "$platform" \
        --arg version "$grype_version" \
        --slurpfile database "$audit_dir/database.json" \
        '
          .descriptor.name == "grype" and
          .descriptor.version == $version and
          .descriptor.configuration.platform == $platform and
          .descriptor.db.status.valid == true and
          .descriptor.db.status.schemaVersion == $database[0].schemaVersion and
          .descriptor.db.status.from == $database[0].from and
          .descriptor.db.status.built == $database[0].built and
          .source.target.manifestDigest == $digest and
          (.matches | type) == "array"
        ' "$report" >/dev/null; then
        fail "Grype returned mismatched evidence for $service on $platform"
    fi

    summary_tmp="$(mktemp "$audit_dir/summaries/.summary.XXXXXX")"
    if ! jq \
        --arg service "$service" \
        --arg platform "$platform" \
        --arg indexDigest "$index_digest" \
        --arg reference "$reference" \
        --arg report "reports/${service}-${safe_platform}.grype.json" \
        '
          ([.matches[]? |
              select(.vulnerability.severity == "Critical") |
              {
                id: .vulnerability.id,
                package: .artifact.name,
                version: .artifact.version,
                fixState: .vulnerability.fix.state,
                fixVersions: .vulnerability.fix.versions
              }
            ] | unique) as $critical |
          ([.matches[]? |
              select(.vulnerability.severity == "High") |
              {
                id: .vulnerability.id,
                package: .artifact.name,
                version: .artifact.version,
                fixState: .vulnerability.fix.state,
                fixVersions: .vulnerability.fix.versions
              }
            ] | unique) as $high |
          {
            service: $service,
            platform: $platform,
            indexDigest: $indexDigest,
            reference: $reference,
            report: $report,
            critical: ($critical | length),
            fixableCritical: (
              [$critical[] | select(.fixState == "fixed")] | length
            ),
            high: ($high | length),
            criticalFindings: $critical,
            highFindings: $high
          }
        ' "$report" >"$summary_tmp"; then
        rm -f "$summary_tmp"
        fail "Grype returned invalid JSON for $service on $platform"
    fi
    mv "$summary_tmp" "$summary"
}

enforce_summary() {
    (($# == 2)) || fail "invalid internal summary enforcement invocation"
    local summary="$2"
    local critical
    local fixable
    local high
    local platform_count

    if ! jq -e '
      (.totals.platformImages | type) == "number" and
      (.totals.critical | type) == "number" and
      (.totals.fixableCritical | type) == "number" and
      (.totals.high | type) == "number" and
      ([
        .totals.platformImages,
        .totals.critical,
        .totals.fixableCritical,
        .totals.high
      ] | all(. == floor)) and
      .totals.platformImages >= 0 and
      .totals.critical >= 0 and
      .totals.fixableCritical >= 0 and
      .totals.fixableCritical <= .totals.critical and
      .totals.high >= 0
    ' "$summary" >/dev/null; then
        fail "summary totals are invalid"
    fi

    platform_count="$(jq -r '.totals.platformImages' "$summary")"
    critical="$(jq -r '.totals.critical' "$summary")"
    fixable="$(jq -r '.totals.fixableCritical' "$summary")"
    high="$(jq -r '.totals.high' "$summary")"
    printf 'catalog image audit: scanned %s manifests; upstream critical=%s, fixable-critical=%s, high=%s\n' \
        "$platform_count" "$critical" "$fixable" "$high"
    printf '%s\n' \
        'catalog image audit: upstream findings are preserved as advisory evidence; freshness, provenance, platform coverage, and scan completeness remain release gates'
}

if [[ "${1:-}" == "--scan-one" ]]; then
    scan_one "$@"
    exit 0
fi
if [[ "${1:-}" == "--enforce-summary" ]]; then
    require_command jq
    enforce_summary "$@"
    exit 0
fi

(($# >= 1 && $# <= 2)) || {
    usage >&2
    exit 2
}
mode="$1"
case "$mode" in
    --inventory-only | --scan) ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

require_command go
require_command jq
if ! command -v sha256sum >/dev/null 2>&1; then
    require_command shasum
fi
if [[ "$mode" == "--scan" ]]; then
    require_command docker
    require_command xargs
fi

cd "$repository_root"
mkdir -p "$repository_root/output"
requested_output_dir="${2:-$default_output_dir}"
if [[ "$requested_output_dir" == /* ]]; then
    output_dir="$requested_output_dir"
else
    output_dir="$repository_root/$requested_output_dir"
fi
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd -P)"
case "$output_dir/" in
    "$repository_root/output/"*) ;;
    *) fail "OUTPUT_DIR must resolve inside $repository_root/output" ;;
esac
readonly output_dir

if [[ "$mode" == "--scan" ]]; then
    lock_dir="$output_dir/.scan-lock"
    if ! mkdir "$lock_dir" 2>/dev/null; then
        fail "another catalog image scan is active (or left $lock_dir behind)"
    fi
    cleanup() {
        local status=$?
        trap - EXIT
        [[ -z "${inventory_tmp:-}" ]] || rm -f "$inventory_tmp"
        [[ -z "${summary_tmp:-}" ]] || rm -f "$summary_tmp"
        rmdir "$lock_dir" 2>/dev/null || true
        exit "$status"
    }
    trap cleanup EXIT
    audit_dir="$(mktemp -d "$output_dir/run.XXXXXX")"
else
    audit_dir="$output_dir"
fi
readonly audit_dir
if [[ "$mode" == "--scan" ]]; then
    audit_tool="$audit_dir/sdbx-imageaudit"
    go build -trimpath -o "$audit_tool" ./cmd/sdbx-imageaudit
    chmod 0500 "$audit_tool"
fi
inventory="$audit_dir/inventory.json"
inventory_tmp="$(mktemp "$audit_dir/.inventory.XXXXXX")"
if [[ "$mode" != "--scan" ]]; then
    trap 'rm -f "$inventory_tmp"' EXIT
fi
if [[ "$mode" == "--scan" ]]; then
    "$audit_tool" --embedded >"$inventory_tmp"
else
    go run ./cmd/sdbx-imageaudit --embedded >"$inventory_tmp"
fi
jq -e '
  .schemaVersion == 1 and
  (.images | length) > 0 and
  ([.images[].service] | unique | length) == (.images | length) and
  all(.images[];
    (.kind == "core" or .kind == "addon") and
    (.indexDigest | test("^sha256:[0-9a-f]{64}$")) and
    ([.platforms[].platform] == ["linux/amd64", "linux/arm64"]) and
    all(.platforms[];
      (.digest | test("^sha256:[0-9a-f]{64}$"))
    )
  )
' "$inventory_tmp" >/dev/null ||
    fail "inventory is incomplete or malformed"
mv "$inventory_tmp" "$inventory"
inventory_tmp=""
if [[ "$mode" != "--scan" ]]; then
    trap - EXIT
fi
catalog_count="$(jq -r '.images | length' "$inventory")"
platform_count="$(jq -r '[.images[].platforms[]] | length' "$inventory")"

if [[ "$mode" == "--inventory-only" ]]; then
    printf 'catalog image audit: wrote %s services and %s immutable manifests to %s\n' \
        "$catalog_count" "$platform_count" "$inventory"
    exit 0
fi

cache_dir="$audit_dir/db"
control_temp_dir="$audit_dir/tmp/control"
mkdir -p \
    "$cache_dir" \
    "$audit_dir/logs" \
    "$audit_dir/reports" \
    "$audit_dir/summaries" \
    "$control_temp_dir"
chmod 0700 "$control_temp_dir"
audit_runner="$audit_dir/audit-runner.sh"
cp "$script_path" "$audit_runner"
chmod 0500 "$audit_runner"
audit_script_sha256="$(sha256_file "$audit_runner")"
docker pull "$grype_image" >/dev/null
run_grype "$cache_dir" "$control_temp_dir" \
    version -o json >"$audit_dir/scanner.json"
jq -e --arg version "$grype_version" '
  .application == "grype" and .version == $version
' "$audit_dir/scanner.json" >/dev/null ||
    fail "digest-pinned scanner did not report Grype $grype_version"
run_grype "$cache_dir" "$control_temp_dir" db update
run_grype "$cache_dir" "$control_temp_dir" \
    db status -o json >"$audit_dir/database.json"
jq -e '.valid == true' "$audit_dir/database.json" >/dev/null ||
    fail "Grype vulnerability database is unavailable"
database_path="$(jq -r '.path' "$audit_dir/database.json")"
database_relative_path="${database_path#/var/lib/grype/db/}"
[[ "$database_relative_path" =~ ^[0-9]+/vulnerability\.db$ ]] ||
    fail "Grype reported an unsafe vulnerability database path"
database_file="$cache_dir/$database_relative_path"
[[ -f "$database_file" ]] ||
    fail "Grype vulnerability database file is unavailable"
database_sha256="$(sha256_file "$database_file")"
database_built="$(jq -r '.built' "$audit_dir/database.json")"
database_schema="$(jq -r '.schemaVersion' "$audit_dir/database.json")"
database_source="$(jq -r '.from' "$audit_dir/database.json")"

jq -j '
  .images[] as $image |
  $image.platforms[] |
  {
    service: $image.service,
    platform: .platform,
    indexDigest: $image.indexDigest,
    reference: ($image.repository + "@" + .digest)
  } |
  tojson, "\u0000"
' "$inventory" |
    xargs -0 -n 1 -P 1 \
        "$audit_runner" --scan-one "$audit_dir" "$cache_dir"

summary_tmp="$(mktemp "$audit_dir/.summary.XXXXXX")"
inventory_sha256="$(sha256_file "$inventory")"
jq -s \
    --arg scannerImage "$grype_image" \
    --arg scannerVersion "$grype_version" \
    --arg inventorySha256 "$inventory_sha256" \
    --arg databaseSha256 "$database_sha256" \
    --arg databaseBuilt "$database_built" \
    --arg databaseSchema "$database_schema" \
    --arg databaseSource "$database_source" \
    --arg auditScript "audit-runner.sh" \
    --arg auditScriptSha256 "$audit_script_sha256" \
    '
      sort_by(.service, .platform) as $images |
      {
        schemaVersion: 1,
        scanner: "grype",
        scannerImage: $scannerImage,
        scannerVersion: $scannerVersion,
        inventorySha256: $inventorySha256,
        databaseSha256: $databaseSha256,
        databaseBuilt: $databaseBuilt,
        databaseSchema: $databaseSchema,
        databaseSource: $databaseSource,
        auditScript: $auditScript,
        auditScriptSha256: $auditScriptSha256,
        images: $images,
        totals: {
          platformImages: ($images | length),
          critical: ([$images[].critical] | add),
          fixableCritical: ([$images[].fixableCritical] | add),
          high: ([$images[].high] | add)
        }
      }
    ' "$audit_dir"/summaries/*.json >"$summary_tmp"
runner_sha256="$(sha256_file "$audit_runner")"
[[ "$runner_sha256" == "$audit_script_sha256" ]] ||
    fail "snapshotted audit runner changed during the scan"
jq -e \
    --argjson platformCount "$platform_count" \
    --arg auditScriptSha256 "$audit_script_sha256" \
    --slurpfile inventory "$inventory" '
  .totals.platformImages == $platformCount and
  (.images | length) == $platformCount and
  .auditScriptSha256 == $auditScriptSha256 and
  ([.images[] | {service, platform, indexDigest, reference}] |
    sort_by(.service, .platform, .indexDigest, .reference)) ==
  ([$inventory[0].images[] as $image |
      $image.platforms[] |
      {
        service: $image.service,
        platform: .platform,
        indexDigest: $image.indexDigest,
        reference: ($image.repository + "@" + .digest)
      }
    ] | sort_by(.service, .platform, .indexDigest, .reference))
' "$summary_tmp" >/dev/null ||
    fail "scan evidence does not exactly cover the immutable inventory"
mv "$summary_tmp" "$audit_dir/summary.json"
summary_tmp=""

printf 'catalog image audit: evidence written to %s\n' "$audit_dir"
"$audit_runner" --enforce-summary "$audit_dir/summary.json"
