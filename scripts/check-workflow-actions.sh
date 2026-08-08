#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

usage() {
    cat <<'EOF'
Usage: scripts/check-workflow-actions.sh [--root DIR]

Verify that every external GitHub Action used by the repository is both:
  - one of the exact reviewed action repositories; and
  - pinned to a full, lowercase 40-character commit SHA.

Only checked-in reusable workflows below .github/workflows may be referenced
locally. The check is offline and performs no GitHub API calls.
EOF
}

fail() {
    printf 'Workflow action policy check failed: %s\n' "$*" >&2
    exit 1
}

root=""
while (($# > 0)); do
    case "$1" in
        --root)
            (($# >= 2)) || fail "--root requires a directory"
            root="$2"
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

if [[ -z "$root" ]]; then
    root="$(
        cd "$(dirname "${BASH_SOURCE[0]}")/.."
        pwd
    )"
fi
[[ -d "$root" && ! -L "$root" ]] ||
    fail "root must be a real directory"

workflow_dir="$root/.github/workflows"
[[ -d "$workflow_dir" && ! -L "$workflow_dir" ]] ||
    fail ".github/workflows must be a real directory"

shopt -s nullglob
workflow_files=("$workflow_dir"/*.yml "$workflow_dir"/*.yaml)
shopt -u nullglob
((${#workflow_files[@]} > 0)) ||
    fail "no workflow files found"

is_allowed_repository() {
    case "$1" in
        actions/attest-build-provenance | \
            actions/checkout | \
            actions/dependency-review-action | \
            actions/download-artifact | \
            actions/setup-go | \
            actions/upload-artifact | \
            goreleaser/goreleaser-action)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

usage_count=0
for workflow_file in "${workflow_files[@]}"; do
    [[ -f "$workflow_file" && ! -L "$workflow_file" ]] ||
        fail "workflow must be a regular non-symlink file: $workflow_file"

    line_number=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line_number=$((line_number + 1))
        [[ "$line" != *$'\r'* ]] ||
            fail "$workflow_file:$line_number contains a carriage return"
        if [[ ! "$line" =~ ^[[:space:]]*-?[[:space:]]*uses:[[:space:]]+([^[:space:]#]+) ]]; then
            [[ "$line" != *"uses:"* ]] ||
                fail "$workflow_file:$line_number uses unsupported YAML syntax"
            continue
        fi

        action_ref="${BASH_REMATCH[1]}"
        usage_count=$((usage_count + 1))

        if [[ "$action_ref" == ./* ]]; then
            [[ "$action_ref" != *".."* && "$action_ref" != *"//"* &&
                "$action_ref" != *"@"* ]] ||
                fail "$workflow_file:$line_number has an unsafe local workflow reference"
            local_workflow="$root/${action_ref#./}"
            [[ "$local_workflow" == "$workflow_dir/"* &&
                -f "$local_workflow" && ! -L "$local_workflow" ]] ||
                fail "$workflow_file:$line_number references a missing or unsafe local workflow"
            case "$local_workflow" in
                *.yml | *.yaml) ;;
                *)
                    fail "$workflow_file:$line_number local reference is not a workflow"
                    ;;
            esac
            continue
        fi

        [[ "$action_ref" =~ ^([^@]+)@([0-9a-f]{40})$ ]] ||
            fail "$workflow_file:$line_number must use a full lowercase commit SHA"
        action_repository="${BASH_REMATCH[1]}"
        is_allowed_repository "$action_repository" ||
            fail "$workflow_file:$line_number uses unreviewed action $action_repository"
    done <"$workflow_file"
done

((usage_count > 0)) ||
    fail "workflows contain no action or reusable-workflow references"

printf 'Workflow action policy passed for %d pinned reference(s)\n' "$usage_count"
