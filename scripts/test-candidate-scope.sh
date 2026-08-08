#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scope_check="$script_dir/check-candidate-scope.sh"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT

new_repository() {
    local name="$1"
    local repository="$test_root/$name"
    mkdir -p "$repository"
    git -C "$repository" init -q
    git -C "$repository" config user.email "candidate-scope@example.test"
    git -C "$repository" config user.name "Candidate Scope Test"
    printf 'synthetic\n' >"$repository/tracked.txt"
    git -C "$repository" add tracked.txt
    git -C "$repository" commit -qm "synthetic baseline"
    printf '%s\n' "$repository"
}

expect_pass() {
    local repository="$1"
    (
        cd "$repository"
        "$scope_check"
    ) >/dev/null
}

expect_fail() {
    local repository="$1"
    if (
        cd "$repository"
        "$scope_check"
    ) >/dev/null 2>&1; then
        printf 'candidate scope test unexpectedly passed: %s\n' "$repository" >&2
        exit 1
    fi
}

add_index_only_paths() {
    local repository="$1"
    shift
    local blob
    blob="$(printf 'synthetic index-only path\n' |
        git -C "$repository" hash-object -w --stdin)"
    local path
    for path in "$@"; do
        printf '100644 %s\t%s\n' "$blob" "$path"
    done | git -C "$repository" update-index --add --index-info
    git -C "$repository" commit -qm "add index-only paths"
    git -C "$repository" update-index --skip-worktree "$@"
    if [[ -n "$(git -C "$repository" status --porcelain=v1 --untracked-files=all)" ]]; then
        printf 'candidate scope fixture is unexpectedly dirty: %s\n' \
            "$repository" >&2
        exit 1
    fi
}

clean_repository="$(new_repository clean)"
expect_pass "$clean_repository"

modified_repository="$(new_repository modified)"
printf 'modified\n' >"$modified_repository/tracked.txt"
expect_fail "$modified_repository"

untracked_repository="$(new_repository untracked)"
printf 'untracked\n' >"$untracked_repository/untracked.txt"
expect_fail "$untracked_repository"

ignored_tracked_repository="$(new_repository ignored-tracked)"
printf 'tracked.txt\n' >"$ignored_tracked_repository/.gitignore"
git -C "$ignored_tracked_repository" add .gitignore
git -C "$ignored_tracked_repository" commit -qm "ignore tracked input"
expect_fail "$ignored_tracked_repository"

symlink_repository="$(new_repository symlink)"
ln -s tracked.txt "$symlink_repository/linked.txt"
git -C "$symlink_repository" add linked.txt
git -C "$symlink_repository" commit -qm "add unsafe symlink"
expect_fail "$symlink_repository"

submodule_source="$(new_repository submodule-source)"
submodule_repository="$(new_repository submodule)"
git -c protocol.file.allow=always -C "$submodule_repository" submodule add -q \
    "$submodule_source" nested
git -C "$submodule_repository" commit -qm "add unsupported submodule"
expect_fail "$submodule_repository"

case_repository="$(new_repository case-collision)"
add_index_only_paths "$case_repository" Case.txt case.txt
expect_fail "$case_repository"

directory_case_repository="$(new_repository directory-case-collision)"
add_index_only_paths \
    "$directory_case_repository" \
    Docs/one.txt \
    docs/two.txt
expect_fail "$directory_case_repository"

backslash_repository="$(new_repository backslash-path)"
backslash_path='unsafe\name.txt'
printf 'backslash\n' >"$backslash_repository/$backslash_path"
git -C "$backslash_repository" add -- "$backslash_path"
git -C "$backslash_repository" commit -qm "add backslash path"
expect_fail "$backslash_repository"

unicode_repository="$(new_repository unicode-path)"
unicode_path='café.txt'
printf 'unicode\n' >"$unicode_repository/$unicode_path"
git -C "$unicode_repository" add -- "$unicode_path"
git -C "$unicode_repository" commit -qm "add non-portable Unicode path"
expect_fail "$unicode_repository"

printf 'candidate scope clean, dirty, ignored, symlink, submodule, path, and case tests passed\n'
