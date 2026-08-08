#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C

usage() {
    cat <<'EOF'
Usage: scripts/check-candidate-scope.sh

Verify that the current Git commit is a self-contained release candidate:
the worktree and index are clean, every input is tracked, ignored files are
not tracked, and the tree contains no symlink, submodule, non-portable, or
case-colliding path component.
EOF
}

if [[ "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi
if [[ "$#" -ne 0 ]]; then
    usage >&2
    exit 1
fi

repository_root="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    printf 'candidate scope check failed: not inside a Git repository\n' >&2
    exit 1
}
cd "$repository_root"

git rev-parse --verify 'HEAD^{commit}' >/dev/null

status="$(git status --porcelain=v1 --untracked-files=all)"
if [[ -n "$status" ]]; then
    printf 'candidate scope check failed: worktree or index is not clean\n' >&2
    printf '%s\n' "$status" >&2
    exit 1
fi

tracked_ignored="$(git ls-files -ci --exclude-standard)"
if [[ -n "$tracked_ignored" ]]; then
    printf 'candidate scope check failed: ignored files are tracked\n' >&2
    printf '%s\n' "$tracked_ignored" >&2
    exit 1
fi

submodules="$(git submodule status)"
if [[ -n "$submodules" ]]; then
    printf 'candidate scope check failed: submodules are not part of the v1 source contract\n' >&2
    printf '%s\n' "$submodules" >&2
    exit 1
fi

unsafe_path=0
while IFS= read -r -d '' path; do
    if [[ ! "$path" =~ ^[[:print:]]+$ || "$path" == *\\* ]]; then
        printf 'candidate scope check failed: non-portable tracked path %q\n' \
            "$path" >&2
        unsafe_path=1
    fi
done < <(git ls-files -z)
if [[ "$unsafe_path" -ne 0 ]]; then
    exit 1
fi

unsafe_mode=0
while IFS=$'\t' read -r metadata path; do
    mode="${metadata%% *}"
    case "$mode" in
        100644|100755)
            ;;
        *)
            printf 'candidate scope check failed: unsupported mode %s for %s\n' \
                "$mode" "$path" >&2
            unsafe_mode=1
            ;;
    esac
done < <(git ls-files --stage)
if [[ "$unsafe_mode" -ne 0 ]]; then
    exit 1
fi

case_collisions="$(
    git -c core.quotePath=false ls-files |
        awk -F/ '
            {
                prefix = $1
                print tolower(prefix) "\t" prefix
                for (field = 2; field <= NF; field++) {
                    prefix = prefix "/" $field
                    print tolower(prefix) "\t" prefix
                }
            }
        ' |
        sort -t $'\t' -k1,1 -k2,2 -u |
        awk -F '\t' '
            $1 == previous && $2 != original {
                print $1
                next
            }
            {
                previous = $1
                original = $2
            }
        '
)"
if [[ -n "$case_collisions" ]]; then
    printf 'candidate scope check failed: case-colliding tracked path components\n' >&2
    printf '%s\n' "$case_collisions" >&2
    exit 1
fi

commit="$(git rev-parse HEAD)"
tree="$(git rev-parse 'HEAD^{tree}')"
file_count="$(git ls-files | wc -l | tr -d ' ')"
printf 'candidate scope verified: commit %s, tree %s, %s tracked files\n' \
    "$commit" "$tree" "$file_count"
