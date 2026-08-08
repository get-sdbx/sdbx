#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

usage() {
    cat <<'EOF'
Usage: scripts/check-github-controls.sh --repo OWNER/REPO --codeowner @OWNER[/TEAM]
       [--fixture-dir DIR]

Read and verify the GitHub control plane required before an SDBX v1 tag.
The normal mode is read-only and uses `gh api`. --fixture-dir is reserved for
the repository's synthetic regression tests.
EOF
}

fail() {
    printf 'GitHub control-plane check failed: %s\n' "$*" >&2
    exit 1
}

repository=""
codeowner=""
fixture_dir=""
while (($# > 0)); do
    case "$1" in
        --repo)
            (($# >= 2)) || fail "--repo requires OWNER/REPO"
            repository="$2"
            shift 2
            ;;
        --codeowner)
            (($# >= 2)) || fail "--codeowner requires a value"
            codeowner="$2"
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

[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
    fail "--repo must be OWNER/REPO"
[[ "$codeowner" =~ ^@[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)?$ ]] ||
    fail "--codeowner must be a GitHub user or organization team"

command -v jq >/dev/null 2>&1 || fail "jq is required"
if [[ -n "$fixture_dir" ]]; then
    [[ -d "$fixture_dir" && ! -L "$fixture_dir" ]] ||
        fail "fixture directory must be a real directory"
else
    command -v gh >/dev/null 2>&1 || fail "gh is required"
fi

work_dir="$(mktemp -d)"
cleanup() {
    rm -rf -- "$work_dir"
}
trap cleanup EXIT

api_version="2022-11-28"

fetch_json() {
    local name="$1"
    local endpoint="$2"
    local destination="$work_dir/$name.json"
    if [[ -n "$fixture_dir" ]]; then
        local source="$fixture_dir/$name.json"
        [[ -f "$source" && ! -L "$source" ]] ||
            fail "missing regular fixture: $name.json"
        cp "$source" "$destination"
    elif ! gh api \
        --method GET \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: $api_version" \
        "$endpoint" >"$destination"; then
        fail "cannot read GitHub endpoint $endpoint"
    fi
    jq -e . "$destination" >/dev/null ||
        fail "$name response is not valid JSON"
    printf '%s\n' "$destination"
}

fetch_rulesets() {
    local destination="$work_dir/rulesets.json"
    if [[ -n "$fixture_dir" ]]; then
        local source="$fixture_dir/rulesets.json"
        [[ -f "$source" && ! -L "$source" ]] ||
            fail "missing regular fixture: rulesets.json"
        cp "$source" "$destination"
    else
        local summaries="$work_dir/ruleset-summaries.json"
        if ! gh api \
            --method GET \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: $api_version" \
            "repos/$repository/rulesets?includes_parents=true&per_page=100" \
            >"$summaries"; then
            fail "cannot read repository rulesets"
        fi
        jq -e 'type == "array"' "$summaries" >/dev/null ||
            fail "ruleset summary response is not an array"
        local ruleset_files=()
        local ruleset_id
        while IFS= read -r ruleset_id; do
            [[ "$ruleset_id" =~ ^[0-9]+$ ]] ||
                fail "GitHub returned a non-numeric ruleset ID"
            local ruleset_file="$work_dir/ruleset-$ruleset_id.json"
            if ! gh api \
                --method GET \
                -H "Accept: application/vnd.github+json" \
                -H "X-GitHub-Api-Version: $api_version" \
                "repos/$repository/rulesets/$ruleset_id" >"$ruleset_file"; then
                fail "cannot read ruleset $ruleset_id"
            fi
            ruleset_files+=("$ruleset_file")
        done < <(jq -r '.[].id' "$summaries")
        if ((${#ruleset_files[@]} == 0)); then
            printf '[]\n' >"$destination"
        else
            jq -s '.' "${ruleset_files[@]}" >"$destination"
        fi
    fi
    jq -e 'type == "array"' "$destination" >/dev/null ||
        fail "rulesets response is not an array"
    printf '%s\n' "$destination"
}

fetch_text() {
    local name="$1"
    local endpoint="$2"
    local destination="$work_dir/$name.txt"
    if [[ -n "$fixture_dir" ]]; then
        local source="$fixture_dir/$name.txt"
        [[ -f "$source" && ! -L "$source" ]] ||
            fail "missing regular fixture: $name.txt"
        cp "$source" "$destination"
    elif ! gh api \
        --method GET \
        -H "Accept: application/vnd.github.raw+json" \
        -H "X-GitHub-Api-Version: $api_version" \
        "$endpoint" >"$destination"; then
        fail "cannot read GitHub endpoint $endpoint"
    fi
    local size
    size="$(wc -c <"$destination" | tr -d '[:space:]')"
    [[ "$size" =~ ^[0-9]+$ && "$size" -gt 0 && "$size" -le 65536 ]] ||
        fail "$name response must contain between 1 byte and 64 KiB"
    printf '%s\n' "$destination"
}

failures=0
check_json() {
    local file="$1"
    local filter="$2"
    local message="$3"
    if ! jq -e "$filter" "$file" >/dev/null; then
        printf 'FAIL: %s\n' "$message" >&2
        failures=$((failures + 1))
    fi
}

repository_json="$(fetch_json repository "repos/$repository")"
actions_json="$(fetch_json actions "repos/$repository/actions/permissions")"
if jq -e '.allowed_actions == "selected"' "$actions_json" >/dev/null; then
    selected_actions_json="$(
        fetch_json selected-actions \
            "repos/$repository/actions/permissions/selected-actions"
    )"
else
    selected_actions_json="$work_dir/selected-actions.json"
    printf '{}\n' >"$selected_actions_json"
fi
rulesets_json="$(fetch_rulesets)"
environment_json="$(
    fetch_json environment "repos/$repository/environments/github-release"
)"
private_reporting_json="$(
    fetch_json private-vulnerability-reporting \
        "repos/$repository/private-vulnerability-reporting"
)"
code_scanning_json="$(
    fetch_json code-scanning "repos/$repository/code-scanning/default-setup"
)"
topics_json="$(fetch_json topics "repos/$repository/topics")"
codeowners_text="$(
    fetch_text codeowners \
        "repos/$repository/contents/.github/CODEOWNERS?ref=main"
)"

check_json "$repository_json" \
    '.visibility == "public" and .default_branch == "main"' \
    "repository must be public with main as its default branch"
check_json "$repository_json" \
    '.has_issues == true and .has_projects == false and
     .has_discussions == false and .has_wiki == false' \
    "only the maintained Issues collaboration surface may remain enabled"
check_json "$repository_json" \
    '.delete_branch_on_merge == true and .homepage == "https://sdbx.one"' \
    "merged branches must be deleted and the homepage must be https://sdbx.one"
check_json "$repository_json" \
    '.security_and_analysis.secret_scanning.status == "enabled" and
     .security_and_analysis.secret_scanning_push_protection.status == "enabled" and
     .security_and_analysis.dependabot_security_updates.status == "enabled"' \
    "secret scanning, push protection, and Dependabot security updates must be enabled"

check_json "$actions_json" \
    '.enabled == true and .allowed_actions == "selected" and
     .sha_pinning_required == true' \
    "Actions must be enabled, selected-only, and require full SHA pins"
check_json "$selected_actions_json" \
    '.github_owned_allowed == false and .verified_allowed == false and
     (.patterns_allowed | sort) ==
       [
         "actions/attest-build-provenance@*",
         "actions/attest@*",
         "actions/checkout@*",
         "actions/dependency-review-action@*",
         "actions/download-artifact@*",
         "actions/setup-go@*",
         "actions/upload-artifact@*",
         "goreleaser/goreleaser-action@*"
       ]' \
    "only the eight reviewed action repositories may be allowed"

required_checks_json='[
  "Compose cloudflared / path",
  "Compose cloudflared / subdomain",
  "Compose direct / path",
  "Compose direct / subdomain",
  "Compose lan / path",
  "Compose lan / subdomain",
  "Dependency review",
  "Documentation truth",
  "Go quality and tests",
  "Release snapshot",
  "Root ownership and broker boundaries",
  "Security gates",
  "Workflow and shell safety"
]'

if ! jq -e --argjson expected "$required_checks_json" '
    def targets_default:
      .target == "branch" and .enforcement == "active" and
      ((.conditions.ref_name.include // []) | index("~DEFAULT_BRANCH") != null);
    [.[] | select(targets_default)] as $sets |
    ($sets | length) > 0 and
    ([$sets[].bypass_actors[]?] | length) == 0 and
    ([$sets[].rules[]?.type] | index("deletion") != null) and
    ([$sets[].rules[]?.type] | index("non_fast_forward") != null) and
    ([ $sets[].rules[]? |
       select(.type == "pull_request") |
       .parameters |
       select(
         .required_approving_review_count == 0 and
         .dismiss_stale_reviews_on_push == true and
         .require_code_owner_review == false and
         .require_last_push_approval == false and
         .required_review_thread_resolution == true
       )
     ] | length) > 0 and
    (([ $sets[].rules[]? |
        select(.type == "required_status_checks") |
        .parameters |
        select(.strict_required_status_checks_policy == true) |
        .required_status_checks[]?.context
      ] | unique) as $actual |
     all($expected[]; . as $check | ($actual | index($check)) != null))
' "$rulesets_json" >/dev/null; then
    printf '%s\n' \
        "FAIL: active default-branch rulesets do not enforce the complete reviewed policy" \
        >&2
    failures=$((failures + 1))
fi

if ! jq -e '
    def targets_release_tags:
      .target == "tag" and .enforcement == "active" and
      ((.conditions.ref_name.include // []) |
       any(. == "refs/tags/v*" or . == "v*"));
    [.[] | select(targets_release_tags)] as $sets |
    ($sets | length) > 0 and
    ([$sets[].bypass_actors[]?] | length) > 0 and
    ([$sets[].rules[]?.type] | index("creation") != null) and
    ([$sets[].rules[]?.type] | index("deletion") != null) and
    ([$sets[].rules[]?.type] | index("non_fast_forward") != null)
' "$rulesets_json" >/dev/null; then
    printf '%s\n' \
        "FAIL: active v* tag rulesets do not restrict creation, deletion, and updates" \
        >&2
    failures=$((failures + 1))
fi

if ! jq -e '
    .name == "github-release" and
    .can_admins_bypass == false and
    ([
      .protection_rules[]? |
      select(.type == "required_reviewers")
    ] | length) == 0
' "$environment_json" >/dev/null; then
    printf '%s\n' \
        "FAIL: github-release must prevent admin bypass without requiring a fictional external reviewer" \
        >&2
    failures=$((failures + 1))
fi

required_codeowner_paths='/.github/ /.goreleaser.yaml /SECURITY.md /packaging/ /cmd/sdbxd/ /internal/backup/ /internal/broker/ /internal/generator/ /internal/management/ /internal/registry/ /internal/routing/ /internal/secrets/ /internal/securefs/ /internal/webui/ /services/'

owner_covers_codeowner_boundaries() {
    awk \
        -v expected_owner="$codeowner" \
        -v required_paths="$required_codeowner_paths" '
        BEGIN {
            required_count = split(required_paths, paths, /[[:space:]]+/)
            for (i = 1; i <= required_count; i++) {
                if (paths[i] != "") {
                    required[paths[i]] = 1
                }
            }
        }
        /^[[:space:]]*#/ || /^[[:space:]]*$/ {
            next
        }
        {
            pattern = $1
            if (!(pattern in required)) {
                next
            }
            for (i = 2; i <= NF; i++) {
                if ($i == expected_owner) {
                    present[pattern] = 1
                }
            }
        }
        END {
            for (pattern in required) {
                if (!(pattern in present)) {
                    exit 1
                }
            }
        }
    ' "$codeowners_text"
}

if ! owner_covers_codeowner_boundaries; then
    printf '%s\n' \
        "FAIL: the reviewed codeowner must cover every trust-boundary path" \
        >&2
    failures=$((failures + 1))
fi

check_json "$private_reporting_json" \
    '.enabled == true' \
    "private vulnerability reporting must be enabled"
check_json "$code_scanning_json" \
    '.state == "configured" and
     .query_suite == "extended" and
     .threat_model == "remote_and_local" and
     (.languages | index("actions") != null) and
     (.languages | index("go") != null) and
     (.languages | index("javascript-typescript") != null)' \
    "CodeQL default setup must cover Actions, Go, and JavaScript with the extended suite"

required_topics_json='[
  "docker",
  "docker-compose",
  "go",
  "linux",
  "media-automation",
  "seedbox",
  "self-hosted"
]'
if ! jq -e --argjson expected "$required_topics_json" '
    (.names | unique) as $actual |
    all($expected[]; . as $topic | ($actual | index($topic)) != null)
' "$topics_json" >/dev/null; then
    printf '%s\n' \
        "FAIL: repository topics do not contain the reviewed public topic set" \
        >&2
    failures=$((failures + 1))
fi

if ((failures > 0)); then
    fail "$failures required control(s) are missing or unsafe"
fi

printf '%s\n' \
    "GitHub control-plane check passed for $repository"
