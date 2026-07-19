#!/usr/bin/env bash
# install-workflows.sh - Install the x-check GitHub Actions workflow into one or all detected git repos
#
# Copies BOTH:
#   - .claude/workflows/x-check.yml      → <repo>/.github/workflows/x-check.yml
#   - .claude/scripts/x-precommit.sh     → <repo>/.github/scripts/x-precommit.sh
#
# Both files MUST be committed + pushed to GitHub for the workflow to run on PRs/pushes.
# The installer stages them for you but does NOT commit (you review first).
#
# Usage:
#     bash install-workflows.sh <repo> [--force]
#
#   <repo>   Any detected repo name, or "all", or "." / "root" (PROJECT_ROOT itself).
#   --force  Overwrite existing files without prompting

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
SOURCE_WORKFLOW="${SCRIPT_DIR}/../workflows/x-check.yml"
SOURCE_HOOK="${SCRIPT_DIR}/x-precommit.sh"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ============================================================
# Repo auto-detection
# ============================================================

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
${BOLD}install-workflows.sh${NC} - install x-check GitHub Actions workflow into detected git repos

${BOLD}Usage:${NC}
    bash install-workflows.sh <repo> [--force]

${BOLD}Arguments:${NC}
    <repo>   Any detected repo name (below), or "all", or "." / "root" (PROJECT_ROOT itself).

${BOLD}Detected repos under ${PROJECT_ROOT}:${NC}
${detected_list}

${BOLD}Flags:${NC}
    --force  overwrite existing files without asking (auto-backs up old versions)

${BOLD}What it installs:${NC}
    1. .github/workflows/x-check.yml  ← the workflow definition
    2. .github/scripts/x-precommit.sh ← the script the workflow calls

${BOLD}After install - important:${NC}
    The installer stages the files but does NOT commit them. You must:
    1. Review the diff: cd <repo> && git diff --staged .github/
    2. Commit:          git commit -m "ci: add x-check workflow"
    3. Push:            git push
    4. The workflow runs on the NEXT PR or push to main/development/staging/production/dev-snad

${BOLD}Examples:${NC}
    bash install-workflows.sh all
    bash install-workflows.sh all --force
EOF
}

if [ -z "$REPO" ] || [ "$REPO" = "--help" ] || [ "$REPO" = "-h" ]; then
    print_help
    exit 0
fi

if [ ! -f "$SOURCE_WORKFLOW" ]; then
    printf "${RED}❌ Source workflow not found: %s${NC}\n" "$SOURCE_WORKFLOW" >&2
    exit 1
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
    local workflow_target="${repo_path}/.github/workflows/x-check.yml"
    local script_target="${repo_path}/.github/scripts/x-precommit.sh"
    local installed_count=0

    if [ ! -d "$repo_path" ]; then
        printf "${RED}❌ %s: repo path does not exist (%s)${NC}\n" "$repo_name" "$repo_path"
        return 1
    fi

    if [ ! -d "${repo_path}/.git" ] && [ ! -f "${repo_path}/.git" ]; then
        printf "${RED}❌ %s: not a git repo${NC}\n" "$repo_name"
        return 1
    fi

    printf "${BOLD}%s:${NC}\n" "$repo_name"

    mkdir -p "$(dirname "$workflow_target")"
    mkdir -p "$(dirname "$script_target")"

    # Backups go to /tmp so they're never accidentally committed
    local safe_name
    safe_name=$(printf "%s" "$repo_name" | tr -c 'A-Za-z0-9._-' '_')
    local backup_dir="/tmp/claude-kit-workflow-backups/${safe_name}"
    mkdir -p "$backup_dir"

    # Workflow file
    if [ -f "$workflow_target" ] && cmp -s "$SOURCE_WORKFLOW" "$workflow_target"; then
        printf "  ${GREEN}✓${NC} workflow already up-to-date\n"
    else
        if [ -f "$workflow_target" ] && [ "$FORCE" != "--force" ]; then
            printf "  ${YELLOW}⚠${NC} existing workflow at %s - pass --force to overwrite\n" "$workflow_target"
        else
            if [ -f "$workflow_target" ] && [ "$FORCE" = "--force" ]; then
                local backup="${backup_dir}/x-check.yml.bak.$(date +%Y%m%d-%H%M%S)"
                cp "$workflow_target" "$backup"
                printf "  ${BLUE}backed up old workflow to %s${NC}\n" "$backup"
            fi
            cp "$SOURCE_WORKFLOW" "$workflow_target"
            printf "  ${GREEN}✓${NC} workflow installed at .github/workflows/x-check.yml\n"
            installed_count=$((installed_count + 1))
        fi
    fi

    # Script file
    if [ -f "$script_target" ] && cmp -s "$SOURCE_HOOK" "$script_target"; then
        printf "  ${GREEN}✓${NC} script already up-to-date\n"
    else
        if [ -f "$script_target" ] && [ "$FORCE" != "--force" ]; then
            printf "  ${YELLOW}⚠${NC} existing script at %s - pass --force to overwrite\n" "$script_target"
        else
            if [ -f "$script_target" ] && [ "$FORCE" = "--force" ]; then
                local backup="${backup_dir}/x-precommit.sh.bak.$(date +%Y%m%d-%H%M%S)"
                cp "$script_target" "$backup"
                printf "  ${BLUE}backed up old script to %s${NC}\n" "$backup"
            fi
            cp "$SOURCE_HOOK" "$script_target"
            chmod +x "$script_target"
            printf "  ${GREEN}✓${NC} script installed at .github/scripts/x-precommit.sh\n"
            installed_count=$((installed_count + 1))
        fi
    fi

    # Stage the changes (don't commit)
    if [ "$installed_count" -gt 0 ]; then
        (
            cd "$repo_path"
            git add .github/workflows/x-check.yml .github/scripts/x-precommit.sh 2>/dev/null || true
        )
        printf "  ${BLUE}staged${NC} for commit (run: cd %s && git diff --staged .github/)\n" "$repo_path"
    fi

    return 0
}

# ============================================================
# Run
# ============================================================

printf "${BOLD}Installing x-check workflow + script from:${NC}\n"
printf "  workflow: %s\n" "$SOURCE_WORKFLOW"
printf "  script:   %s\n\n" "$SOURCE_HOOK"

if [ "$REPO" = "all" ]; then
    if [ -z "$DETECTED_REPOS" ]; then
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

cat <<EOF

${BOLD}Next steps:${NC}
  1. Review the staged changes: ${BLUE}cd <repo> && git diff --staged .github/${NC}
  2. Commit:                    ${BLUE}git commit -m "ci: add x-check workflow"${NC}
  3. Push:                      ${BLUE}git push${NC}
  4. The workflow will run on the NEXT PR or push to main/development/staging/production/dev-snad

${BOLD}Important:${NC} The workflow will only post PR comments if the PR is from the SAME repo (not a fork).
This is a GitHub Actions security limitation, not something we can change.
EOF
