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

fail() {
    printf 'GitHub control test failed: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    rm -rf -- "$test_root"
}
trap cleanup EXIT

fixture_dir="$test_root/valid"
mkdir -p "$fixture_dir"

cat >"$fixture_dir/repository.json" <<'EOF'
{
  "visibility": "public",
  "default_branch": "main",
  "has_issues": true,
  "has_projects": false,
  "has_discussions": false,
  "has_wiki": false,
  "delete_branch_on_merge": true,
  "homepage": "https://sdbx.one",
  "security_and_analysis": {
    "secret_scanning": {"status": "enabled"},
    "secret_scanning_push_protection": {"status": "enabled"},
    "dependabot_security_updates": {"status": "enabled"}
  }
}
EOF
cat >"$fixture_dir/actions.json" <<'EOF'
{"enabled":true,"allowed_actions":"selected","sha_pinning_required":true}
EOF
cat >"$fixture_dir/selected-actions.json" <<'EOF'
{
  "github_owned_allowed": false,
  "verified_allowed": false,
  "patterns_allowed": [
    "actions/attest@*",
    "actions/attest-build-provenance@*",
    "actions/checkout@*",
    "actions/dependency-review-action@*",
    "actions/download-artifact@*",
    "actions/setup-go@*",
    "actions/upload-artifact@*",
    "goreleaser/goreleaser-action@*"
  ]
}
EOF
cat >"$fixture_dir/private-vulnerability-reporting.json" <<'EOF'
{"enabled":true}
EOF
cat >"$fixture_dir/code-scanning.json" <<'EOF'
{
  "state": "configured",
  "languages": ["actions", "go", "javascript-typescript"],
  "query_suite": "extended",
  "threat_model": "remote_and_local"
}
EOF
cat >"$fixture_dir/topics.json" <<'EOF'
{
  "names": [
    "docker",
    "docker-compose",
    "go",
    "linux",
    "media-automation",
    "seedbox",
    "self-hosted"
  ]
}
EOF
cat >"$fixture_dir/environment.json" <<'EOF'
{
  "name": "github-release",
  "can_admins_bypass": false,
  "protection_rules": []
}
EOF
cat >"$fixture_dir/codeowners.txt" <<'EOF'
* @get-sdbx/maintainers
/.github/ @get-sdbx/maintainers
/.goreleaser.yaml @get-sdbx/maintainers
/SECURITY.md @get-sdbx/maintainers
/packaging/ @get-sdbx/maintainers
/cmd/sdbxd/ @get-sdbx/maintainers
/internal/backup/ @get-sdbx/maintainers
/internal/broker/ @get-sdbx/maintainers
/internal/generator/ @get-sdbx/maintainers
/internal/management/ @get-sdbx/maintainers
/internal/registry/ @get-sdbx/maintainers
/internal/routing/ @get-sdbx/maintainers
/internal/secrets/ @get-sdbx/maintainers
/internal/securefs/ @get-sdbx/maintainers
/internal/webui/ @get-sdbx/maintainers
/services/ @get-sdbx/maintainers
EOF
cat >"$fixture_dir/rulesets.json" <<'EOF'
[
  {
    "target": "branch",
    "enforcement": "active",
    "bypass_actors": [],
    "conditions": {"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},
    "rules": [
      {"type":"deletion"},
      {"type":"non_fast_forward"},
      {
        "type":"pull_request",
        "parameters":{
          "required_approving_review_count":0,
          "dismiss_stale_reviews_on_push":true,
          "require_code_owner_review":false,
          "require_last_push_approval":false,
          "required_review_thread_resolution":true
        }
      },
      {
        "type":"required_status_checks",
        "parameters":{
          "strict_required_status_checks_policy":true,
          "required_status_checks":[
            {"context":"Compose cloudflared / path"},
            {"context":"Compose cloudflared / subdomain"},
            {"context":"Compose direct / path"},
            {"context":"Compose direct / subdomain"},
            {"context":"Compose lan / path"},
            {"context":"Compose lan / subdomain"},
            {"context":"Dependency review"},
            {"context":"Documentation truth"},
            {"context":"Go quality and tests"},
            {"context":"Release snapshot"},
            {"context":"Root ownership and broker boundaries"},
            {"context":"Security gates"},
            {"context":"Workflow and shell safety"}
          ]
        }
      }
    ]
  },
  {
    "target": "tag",
    "enforcement": "active",
    "bypass_actors":[
      {"actor_id":5,"actor_type":"RepositoryRole","bypass_mode":"always"}
    ],
    "conditions":{"ref_name":{"include":["refs/tags/v*"],"exclude":[]}},
    "rules":[
      {"type":"creation"},
      {"type":"deletion"},
      {"type":"non_fast_forward"}
    ]
  }
]
EOF

"$repository_root/scripts/check-github-controls.sh" \
    --repo get-sdbx/sdbx \
    --codeowner @get-sdbx/maintainers \
    --fixture-dir "$fixture_dir"

expect_failure() {
    local name="$1"
    local file="$2"
    local mutation="$3"
    local expected="$4"
    local invalid_dir="$test_root/invalid-$name"
    cp -R "$fixture_dir" "$invalid_dir"
    jq "$mutation" "$invalid_dir/$file.json" >"$test_root/$name.json"
    mv "$test_root/$name.json" "$invalid_dir/$file.json"
    if "$repository_root/scripts/check-github-controls.sh" \
        --repo get-sdbx/sdbx \
        --codeowner @get-sdbx/maintainers \
        --fixture-dir "$invalid_dir" >"$test_root/$name.out" 2>&1; then
        printf 'GitHub control test failed: unsafe %s policy was accepted\n' \
            "$name" >&2
        exit 1
    fi
    grep -q "$expected" "$test_root/$name.out"
}

expect_failure \
    actions-pin \
    actions \
    '.sha_pinning_required = false' \
    'require full SHA pins'
expect_failure \
    action-github-owned \
    selected-actions \
    '.github_owned_allowed = true' \
    'eight reviewed action'
expect_failure \
    action-verified \
    selected-actions \
    '.verified_allowed = true' \
    'eight reviewed action'
expect_failure \
    action-extra-pattern \
    selected-actions \
    '.patterns_allowed += ["actions/cache@*"]' \
    'eight reviewed action'
expect_failure \
    visibility \
    repository \
    '.visibility = "private"' \
    'repository must be public'
expect_failure \
    default-branch \
    repository \
    '.default_branch = "develop"' \
    'repository must be public'
expect_failure \
    collaboration-surface \
    repository \
    '.has_wiki = true' \
    'only the maintained Issues'
expect_failure \
    repository-homepage \
    repository \
    '.homepage = "https://example.test"' \
    'homepage must be https://sdbx.one'
expect_failure \
    secret-scanning \
    repository \
    '.security_and_analysis.secret_scanning.status = "disabled"' \
    'secret scanning, push protection'
expect_failure \
    push-protection \
    repository \
    '.security_and_analysis.secret_scanning_push_protection.status = "disabled"' \
    'secret scanning, push protection'
expect_failure \
    dependabot-security-updates \
    repository \
    '.security_and_analysis.dependabot_security_updates.status = "disabled"' \
    'secret scanning, push protection'
expect_failure \
    required-check \
    rulesets \
    '.[0].rules[3].parameters.required_status_checks |=
       map(select(.context != "Security gates"))' \
    'complete reviewed policy'
expect_failure \
    branch-bypass \
    rulesets \
    '.[0].bypass_actors = [
       {"actor_id":5,"actor_type":"RepositoryRole","bypass_mode":"always"}
     ]' \
    'complete reviewed policy'
expect_failure \
    branch-deletion \
    rulesets \
    '.[0].rules |= map(select(.type != "deletion"))' \
    'complete reviewed policy'
expect_failure \
    branch-non-fast-forward \
    rulesets \
    '.[0].rules |= map(select(.type != "non_fast_forward"))' \
    'complete reviewed policy'
expect_failure \
    branch-approval-count \
    rulesets \
    '.[0].rules[2].parameters.required_approving_review_count = 1' \
    'complete reviewed policy'
expect_failure \
    branch-stale-reviews \
    rulesets \
    '.[0].rules[2].parameters.dismiss_stale_reviews_on_push = false' \
    'complete reviewed policy'
expect_failure \
    branch-code-owner \
    rulesets \
    '.[0].rules[2].parameters.require_code_owner_review = true' \
    'complete reviewed policy'
expect_failure \
    branch-last-push \
    rulesets \
    '.[0].rules[2].parameters.require_last_push_approval = true' \
    'complete reviewed policy'
expect_failure \
    branch-thread-resolution \
    rulesets \
    '.[0].rules[2].parameters.required_review_thread_resolution = false' \
    'complete reviewed policy'
expect_failure \
    branch-strict-checks \
    rulesets \
    '.[0].rules[3].parameters.strict_required_status_checks_policy = false' \
    'complete reviewed policy'
expect_failure \
    tag-protection \
    rulesets \
    '.[1].rules |= map(select(.type != "creation"))' \
    'v\* tag rulesets'
expect_failure \
    tag-bypass \
    rulesets \
    '.[1].bypass_actors = []' \
    'v\* tag rulesets'
expect_failure \
    tag-deletion \
    rulesets \
    '.[1].rules |= map(select(.type != "deletion"))' \
    'v\* tag rulesets'
expect_failure \
    tag-non-fast-forward \
    rulesets \
    '.[1].rules |= map(select(.type != "non_fast_forward"))' \
    'v\* tag rulesets'
expect_failure \
    release-admin-bypass \
    environment \
    '.can_admins_bypass = true' \
    'prevent admin bypass'
expect_failure \
    release-fictional-reviewer \
    environment \
    '.protection_rules = [
       {
         "type":"required_reviewers",
         "prevent_self_review":true,
         "reviewers":[
           {"type":"User","reviewer":{"login":"someone-else"}}
         ]
       }
     ]' \
    'fictional external reviewer'
invalid_codeowners_dir="$test_root/invalid-codeowners"
cp -R "$fixture_dir" "$invalid_codeowners_dir"
awk '
    $1 == "/internal/broker/" {
        sub(/ @get-sdbx\/maintainers/, "")
    }
    { print }
' "$invalid_codeowners_dir/codeowners.txt" >"$test_root/codeowners.txt"
mv "$test_root/codeowners.txt" "$invalid_codeowners_dir/codeowners.txt"
if "$repository_root/scripts/check-github-controls.sh" \
    --repo get-sdbx/sdbx \
    --codeowner @get-sdbx/maintainers \
    --fixture-dir "$invalid_codeowners_dir" \
    >"$test_root/codeowners.out" 2>&1; then
    fail "unsafe CODEOWNERS policy was accepted"
fi
grep -q 'reviewed codeowner' "$test_root/codeowners.out"
expect_failure \
    private-reporting \
    private-vulnerability-reporting \
    '.enabled = false' \
    'private vulnerability reporting'
expect_failure \
    codeql-suite \
    code-scanning \
    '.query_suite = "default"' \
    'CodeQL default setup'
expect_failure \
    codeql-threat-model \
    code-scanning \
    '.threat_model = "remote"' \
    'CodeQL default setup'
expect_failure \
    codeql-language \
    code-scanning \
    '.languages |= map(select(. != "actions"))' \
    'CodeQL default setup'
expect_failure \
    repository-topic \
    topics \
    '.names |= map(select(. != "self-hosted"))' \
    'reviewed public topic set'

printf '%s\n' \
    "GitHub control-plane verifier accepted the complete policy and rejected drift"
