#!/usr/bin/env bash
# install-hooks.sh - Install x-precommit.sh as the pre-commit hook in one or all detected git repos
#
# Usage:
#     bash install-hooks.sh <repo> [--force]
#
#   <repo>     name of any direct child directory under PROJECT_ROOT that contains a .git/ directory,
#              OR "all" to install into every detected git repo
#              OR "." / "root" to install into PROJECT_ROOT itself if it is a git repo
#   --force    Overwrite an existing pre-commit hook (skip the safety check)
#
# Repos are auto-detected by scanning PROJECT_ROOT for direct children with .git/ dirs - no hardcoded names.
# Idempotent: re-running with the same source won't re-copy if the file is already up-to-date.
# Use --force after editing x-precommit.sh to redeploy to all repos.

set -e

# ============================================================
# Colors
# ============================================================

RED=$'\033[0;31m'
YELLOW=$'\033[0;33m'
GREEN=$'\033[0;32m'
BLUE=$'\033[0;34m'
NC=$'\033[0m'
BOLD=$'\033[1m'

if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
    RED=""; YELLOW=""; GREEN=""; BLUE=""; NC=""; BOLD=""
fi

# ============================================================
# Paths
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_HOOK="${SCRIPT_DIR}/x-precommit.sh"
# When this script lives at <project>/.claude/scripts/ → PROJECT_ROOT = <project>
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ============================================================
# Repo auto-detection
# ============================================================

# Echo each direct child of PROJECT_ROOT that contains a .git directory (one per line).
detect_repos() {
    local d
    for d in "$PROJECT_ROOT"/*/; do
        [ -d "$d" ] || continue
        if [ -d "${d}.git" ] || [ -f "${d}.git" ]; then
            basename "$d"
        fi
    done
}

DETECTED_REPOS="$(detect_repos)"

# ============================================================
# Argument parsing
# ============================================================

REPO="${1:-}"
FORCE="${2:-}"

print_help() {
    local detected_list
    if [ -n "$DETECTED_REPOS" ]; then
        detected_list="$(printf "%s\n" "$DETECTED_REPOS" | sed 's/^/    /')"
    else
        detected_list="    (none found under ${PROJECT_ROOT})"
    fi
    cat <<EOF
${BOLD}install-hooks.sh${NC} - install x-precommit.sh into detected git repos

${BOLD}Usage:${NC}
    bash install-hooks.sh <repo> [--force]

${BOLD}Arguments:${NC}
    <repo>   Any detected repo name (see below), or "all", or "." / "root" (PROJECT_ROOT itself).

${BOLD}Detected repos under ${PROJECT_ROOT}:${NC}
${detected_list}

${BOLD}Flags:${NC}
    --force           overwrite an existing pre-commit hook without asking

${BOLD}Examples:${NC}
    bash install-hooks.sh all
    bash install-hooks.sh all --force

${BOLD}After install:${NC}
    Test it: cd <repo>, stage a file with a known violation, git commit. Should be blocked.
    Bypass (use sparingly): git commit --no-verify
EOF
}

if [ -z "$REPO" ] || [ "$REPO" = "--help" ] || [ "$REPO" = "-h" ]; then
    print_help
    exit 0
fi

if [ ! -f "$SOURCE_HOOK" ]; then
    printf "${RED}❌ Source hook not found: %s${NC}\n" "$SOURCE_HOOK" >&2
    exit 1
fi

# ============================================================
# Per-repo install
# ============================================================

install_for_repo() {
    local repo_name="$1"
    local repo_path
    if [ "$repo_name" = "." ] || [ "$repo_name" = "root" ]; then
        repo_path="$PROJECT_ROOT"
        repo_name="(project root)"
    else
        repo_path="${PROJECT_ROOT}/${repo_name}"
    fi
    local target="${repo_path}/.git/hooks/pre-commit"

    if [ ! -d "$repo_path" ]; then
        printf "${RED}❌ %s: repo path does not exist (%s)${NC}\n" "$repo_name" "$repo_path"
        return 1
    fi

    if [ ! -d "${repo_path}/.git" ] && [ ! -f "${repo_path}/.git" ]; then
        printf "${RED}❌ %s: not a git repo (no .git at %s)${NC}\n" "$repo_name" "$repo_path"
        return 1
    fi

    # Handle git worktrees / submodules where .git is a file pointing to the real gitdir
    if [ -f "${repo_path}/.git" ]; then
        local gitdir
        gitdir=$(sed -n 's/^gitdir: //p' "${repo_path}/.git")
        if [ -n "$gitdir" ]; then
            # Resolve relative gitdir
            case "$gitdir" in
                /*) : ;;
                *)  gitdir="${repo_path}/${gitdir}" ;;
            esac
            target="${gitdir}/hooks/pre-commit"
            mkdir -p "$(dirname "$target")"
        fi
    fi

    # Already up to date?
    if [ -f "$target" ] && cmp -s "$SOURCE_HOOK" "$target"; then
        printf "${GREEN}✓ %s: already up-to-date${NC}\n" "$repo_name"
        return 0
    fi

    # Existing hook that ISN'T ours?
    if [ -f "$target" ] && [ "$FORCE" != "--force" ]; then
        printf "${YELLOW}⚠ %s: existing pre-commit hook found at %s${NC}\n" "$repo_name" "$target"
        printf "  Diff vs source:\n"
        diff -q "$SOURCE_HOOK" "$target" || true
        printf "  Pass --force to overwrite, or back it up manually first.\n"
        return 1
    fi

    # Backup old hook if force-overwriting
    if [ -f "$target" ] && [ "$FORCE" = "--force" ]; then
        local backup="${target}.bak.$(date +%Y%m%d-%H%M%S)"
        cp "$target" "$backup"
        printf "${BLUE}  backed up old hook to %s${NC}\n" "$backup"
    fi

    cp "$SOURCE_HOOK" "$target"
    chmod +x "$target"
    printf "${GREEN}✓ %s: installed at %s${NC}\n" "$repo_name" "$target"
    return 0
}

# ============================================================
# Run
# ============================================================

printf "${BOLD}Installing x-precommit hook from:${NC}\n  %s\n\n" "$SOURCE_HOOK"

if [ "$REPO" = "all" ]; then
    if [ -z "$DETECTED_REPOS" ]; then
        # Fall back to PROJECT_ROOT itself if it's a git repo
        if [ -d "${PROJECT_ROOT}/.git" ] || [ -f "${PROJECT_ROOT}/.git" ]; then
            install_for_repo "." || true
        else
            printf "${YELLOW}⚠ no git repos detected under %s${NC}\n" "$PROJECT_ROOT"
        fi
    else
        while IFS= read -r repo; do
            [ -z "$repo" ] && continue
            install_for_repo "$repo" || true
        done <<< "$DETECTED_REPOS"
    fi
else
    install_for_repo "$REPO"
fi

printf "\n${BOLD}Done.${NC}\n"
printf "Test it with: ${BLUE}cd %s/<repo> && touch test.ts && echo 'const x: any = 1;' > test.ts && git add test.ts && git commit -m test${NC}\n" "$PROJECT_ROOT"
printf "Then revert:  ${BLUE}git reset HEAD test.ts && rm test.ts${NC}\n"
