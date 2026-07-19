#!/usr/bin/env bash
# x-precommit.sh - stitchub critical-rule pre-commit hook
#
# Source of truth: /Users/mac/Projects/mine/stitchub/.claude/scripts/x-precommit.sh
# Deployed via:    bash .claude/scripts/install-hooks.sh <repo>
#
# Enforces the BLOCKING critical rules from .claude/rules.md.
# Runs in milliseconds, no Claude calls, offline-friendly.
#
# Bypass (use sparingly!): git commit --no-verify
#
# Maintained by: Snad. To add a new pattern:
#   1. Add the rule to .claude/rules.md
#   2. Add a `scan_pattern` line in this file
#   3. Re-run: bash .claude/scripts/install-hooks.sh all --force

set -e

# ============================================================
# Config
# ============================================================

RED=$'\033[0;31m'
YELLOW=$'\033[0;33m'
GREEN=$'\033[0;32m'
BLUE=$'\033[0;34m'
NC=$'\033[0m'
BOLD=$'\033[1m'

# Disable colors if NO_COLOR env var is set or stdout isn't a tty
if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
    RED=""; YELLOW=""; GREEN=""; BLUE=""; NC=""; BOLD=""
fi

VIOLATIONS=0
WARNINGS=0

# Mode: "precommit" (read staged content via git show) or "ci" (read working-tree files via diff range)
MODE="precommit"
CI_BASE_REF=""

# ============================================================
# Helpers
# ============================================================

print_help() {
    cat <<EOF
${BOLD}x-precommit.sh${NC} - stitchub critical-rule pre-commit hook

${BOLD}Usage:${NC}
    bash x-precommit.sh                  Run check on staged files (default = precommit mode)
    bash x-precommit.sh --ci <base-ref>  Run check on files changed since <base-ref> (CI mode)
                                         e.g. --ci origin/main
    bash x-precommit.sh --list           List the critical patterns this hook enforces
    bash x-precommit.sh --help           Show this help

${BOLD}Modes:${NC}
    precommit (default)  Reads STAGED file content via git show. Fast, runs on every git commit.
    ci                   Reads WORKING-TREE content. Runs on a PR/push, scans files changed
                         since the base ref (e.g. origin/main). Used by GitHub Actions.

${BOLD}As a git hook:${NC}
    Installed as .git/hooks/pre-commit via:
    bash /Users/mac/Projects/mine/stitchub/.claude/scripts/install-hooks.sh <repo>

${BOLD}As a GitHub Action:${NC}
    Called by .github/workflows/x-check.yml as: bash .github/scripts/x-precommit.sh --ci origin/main

${BOLD}Bypass (precommit only):${NC}
    git commit --no-verify  # use sparingly - defeats the purpose
EOF
}

print_patterns() {
    cat <<EOF
${BOLD}x-precommit.sh enforces these critical rules from .claude/rules.md:${NC}

${RED}🔴 BLOCKING (commit refused):${NC}
  S-01  Hardcoded Google API keys (AIzaSy...)
  S-01  Hardcoded Stripe keys (sk_live_, sk_test_, pk_...)
  S-01  Hardcoded GitHub Personal Access Tokens (ghp_...)
  S-01  Hardcoded GitLab Personal Access Tokens (glpat-...)
  S-01  Generic API keys / secrets in env-like assignments
  S-02  Committed .env files (other than example.env)
  S-03  Drizzle SQL logger ON without env gate
  A-03  Auth tokens stored in localStorage
  A-03  JWTs stored in plaintext Hive boxes
  A-04  Math.random() in auth/OTP/password code
  Q-08  Drizzle .where() using JS && instead of and()
  Q-13  AI hidden characters (em-dash, en-dash, ellipsis, smart quotes, zero-width, BOM)
  Q-13  Decorative HTML entities (&mdash;, &ndash;, &hellip;)
  X-02  Asset ownership bypass (OR createdBy IS NULL)
  P-01  New escrow code (escrow is OUT of MVP scope)

${YELLOW}🟡 WARNINGS (don't block, just flag):${NC}
  Q-01  TypeScript : any
  Q-02  Empty catch blocks
  Q-03  console.log / print() in committed code
  Q-07  FormData.fromMap (verify no un-awaited Futures)
  S-13  Raw error.message / toString() leaked to user (Node, Flutter, React)

For full rule details: /Users/mac/Projects/mine/stitchub/.claude/rules.md
EOF
}

# Read file content based on mode.
# precommit mode: read STAGED content via `git show :file` (what's about to commit)
# ci mode:        read working-tree content via `cat file` (what's in the PR HEAD)
read_file_content() {
    local file="$1"
    if [ "$MODE" = "ci" ]; then
        cat "$file" 2>/dev/null || true
    else
        git show ":${file}" 2>/dev/null || true
    fi
}

# Emit a violation. Args: severity, rule_id, title, file, line, snippet, fix
emit_violation() {
    local severity="$1"
    local rule="$2"
    local title="$3"
    local file="$4"
    local line="$5"
    local snippet="$6"
    local fix="$7"

    if [ "$severity" = "CRITICAL" ]; then
        printf "${RED}${BOLD}🔴 %s %s${NC}\n" "$rule" "$title"
        VIOLATIONS=$((VIOLATIONS + 1))
    else
        printf "${YELLOW}${BOLD}🟡 %s %s${NC}\n" "$rule" "$title"
        WARNINGS=$((WARNINGS + 1))
    fi
    printf "   ${BLUE}%s:%s${NC}\n" "$file" "$line"
    printf "   %s\n" "$snippet"
    printf "   ${BOLD}Fix:${NC} %s\n\n" "$fix"
}

# Scan the staged version of files for a regex pattern.
# Args: severity, rule_id, title, regex, file_filter_regex, fix_hint, [exclude_regex]
scan_pattern() {
    local severity="$1"
    local rule="$2"
    local title="$3"
    local pattern="$4"
    local file_filter="$5"
    local fix="$6"
    local exclude_pattern="${7:-}"

    local target_files
    if [ -z "$file_filter" ]; then
        target_files="$CODE_FILES"
    else
        target_files=$(printf "%s\n" "$CODE_FILES" | grep -E "$file_filter" 2>/dev/null || true)
    fi

    [ -z "$target_files" ] && return 0

    while IFS= read -r file; do
        [ -z "$file" ] && continue

        local matches
        # Read file content (mode-aware: STAGED in precommit, working-tree in CI)
        if [ -n "$exclude_pattern" ]; then
            matches=$(read_file_content "$file" | grep -nE "$pattern" 2>/dev/null | grep -vE "$exclude_pattern" 2>/dev/null || true)
        else
            matches=$(read_file_content "$file" | grep -nE "$pattern" 2>/dev/null || true)
        fi

        if [ -n "$matches" ]; then
            while IFS= read -r match; do
                local line snippet
                line=$(printf "%s" "$match" | cut -d: -f1)
                snippet=$(printf "%s" "$match" | cut -d: -f2- | sed 's/^[[:space:]]*//' | cut -c1-100)
                emit_violation "$severity" "$rule" "$title" "$file" "$line" "$snippet" "$fix"
            done <<< "$matches"
        fi
    done <<< "$target_files"
}

# ============================================================
# Argument parsing
# ============================================================

case "${1:-}" in
    --help|-h)
        print_help
        exit 0
        ;;
    --list|-l)
        print_patterns
        exit 0
        ;;
    --ci)
        MODE="ci"
        CI_BASE_REF="${2:-}"
        if [ -z "$CI_BASE_REF" ]; then
            echo "${RED}--ci requires a base ref argument (e.g. --ci origin/main)${NC}" >&2
            exit 2
        fi
        ;;
    --test)
        echo "${BOLD}Test mode not yet implemented.${NC}"
        echo "To verify the hook works: cd <repo>, create a test file with a known violation, git add it, git commit. Should be blocked."
        exit 0
        ;;
esac

# ============================================================
# Determine the file set
# ============================================================

# Make sure we're in a git repo
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "${RED}x-precommit: not inside a git repo${NC}" >&2
    exit 1
fi

# Get the file set based on mode
if [ "$MODE" = "ci" ]; then
    # CI mode: files changed in the PR / push (since base ref)
    # Verify base ref exists
    if ! git rev-parse --verify "$CI_BASE_REF" >/dev/null 2>&1; then
        echo "${RED}--ci base ref does not exist: ${CI_BASE_REF}${NC}" >&2
        echo "Run 'git fetch origin' first, or use --ci HEAD~1 for testing" >&2
        exit 2
    fi
    STAGED_FILES=$(git diff --name-only --diff-filter=ACMR "$CI_BASE_REF"...HEAD 2>/dev/null)
else
    # precommit mode: staged files (ACMR = added, copied, modified, renamed)
    if git rev-parse --verify HEAD >/dev/null 2>&1; then
        STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR 2>/dev/null)
    else
        # First commit - no HEAD yet
        STAGED_FILES=$(git ls-files --cached 2>/dev/null)
    fi
fi

# Filter to scannable code files (exclude lockfiles, generated, binary, configs)
CODE_FILES=$(printf "%s\n" "$STAGED_FILES" | grep -Ev '\.(lock|lockb|png|jpg|jpeg|svg|ico|gif|webp|woff|woff2|ttf|otf|eot|pdf|zip|tar|gz|g\.dart|freezed\.dart)$|^(node_modules|\.next|build|\.dart_tool|\.gradle|dist|coverage|\.git)/' 2>/dev/null || true)

if [ -z "$CODE_FILES" ]; then
    if [ "$MODE" = "ci" ]; then
        printf "${GREEN}✓ x-precommit: no scannable code files changed since %s${NC}\n" "$CI_BASE_REF"
    else
        printf "${GREEN}✓ x-precommit: no scannable code files staged${NC}\n"
    fi
    exit 0
fi

FILE_COUNT=$(printf "%s\n" "$CODE_FILES" | grep -c . 2>/dev/null || echo 0)
if [ "$MODE" = "ci" ]; then
    printf "${BOLD}x-precommit (CI mode): checking %s changed file(s) since %s against critical rules...${NC}\n\n" "$FILE_COUNT" "$CI_BASE_REF"
else
    printf "${BOLD}x-precommit: checking %s staged file(s) against critical rules...${NC}\n\n" "$FILE_COUNT"
fi

# ============================================================
# Auto-format (precommit mode only - best-effort, language-aware)
# ============================================================
# Skip silently if the relevant tool isn't installed in this repo -
# the rule scan still runs. JS/TS auto-format is handled by husky +
# lint-staged in repos that use them (weft); this block covers PHP +
# Python so warp + fitscan get the same "fix-on-commit" UX.

if [ "$MODE" = "precommit" ]; then
    PHP_FILES=$(printf "%s\n" "$CODE_FILES" | grep -E '\.php$' 2>/dev/null || true)
    PY_FILES=$(printf "%s\n" "$CODE_FILES" | grep -E '\.py$' 2>/dev/null || true)

    if [ -n "$PHP_FILES" ] && [ -x "vendor/bin/pint" ]; then
        printf "${BLUE}auto-format: pint on %s PHP file(s)${NC}\n" "$(printf "%s\n" "$PHP_FILES" | grep -c .)"
        printf "%s\n" "$PHP_FILES" | xargs vendor/bin/pint --format agent >/dev/null 2>&1 || true
        printf "%s\n" "$PHP_FILES" | xargs git add 2>/dev/null || true
    fi

    if [ -n "$PY_FILES" ]; then
        BLACK="" ; RUFF=""
        for cand in venv/bin/black .venv/bin/black; do
            [ -x "$cand" ] && BLACK="$cand" && break
        done
        for cand in venv/bin/ruff .venv/bin/ruff; do
            [ -x "$cand" ] && RUFF="$cand" && break
        done
        [ -z "$BLACK" ] && command -v black >/dev/null 2>&1 && BLACK="black"
        [ -z "$RUFF" ] && command -v ruff >/dev/null 2>&1 && RUFF="ruff"

        if [ -n "$BLACK" ]; then
            printf "${BLUE}auto-format: black on %s Python file(s)${NC}\n" "$(printf "%s\n" "$PY_FILES" | grep -c .)"
            printf "%s\n" "$PY_FILES" | xargs "$BLACK" --quiet 2>/dev/null || true
        fi
        if [ -n "$RUFF" ]; then
            printf "${BLUE}auto-format: ruff --fix on %s Python file(s)${NC}\n" "$(printf "%s\n" "$PY_FILES" | grep -c .)"
            printf "%s\n" "$PY_FILES" | xargs "$RUFF" check --fix --quiet 2>/dev/null || true
        fi
        if [ -n "$BLACK" ] || [ -n "$RUFF" ]; then
            printf "%s\n" "$PY_FILES" | xargs git add 2>/dev/null || true
        fi
    fi
fi

# ============================================================
# CRITICAL RULES (block commit)
# ============================================================

# S-01: Hardcoded Google API keys
scan_pattern "CRITICAL" "S-01" "Hardcoded Google API key" \
    'AIza[0-9A-Za-z_-]{35}' \
    '' \
    "Move to env var. Read via dart-define (Flutter) or process.env (Node). Rotate the leaked key in Google Cloud Console."

# S-01: Stripe keys
scan_pattern "CRITICAL" "S-01" "Hardcoded Stripe key" \
    '(sk|pk)_(test|live)_[0-9a-zA-Z]{20,}' \
    '' \
    "Move to env var. Rotate the leaked key in Stripe dashboard."

# S-01: GitHub Personal Access Token
scan_pattern "CRITICAL" "S-01" "Hardcoded GitHub PAT" \
    'ghp_[0-9a-zA-Z]{36}' \
    '' \
    "Move to env var. Revoke + regenerate the token in GitHub Settings > Developer Settings > Personal access tokens."

# S-01: GitLab PAT
scan_pattern "CRITICAL" "S-01" "Hardcoded GitLab PAT" \
    'glpat-[0-9a-zA-Z_-]{20,}' \
    '' \
    "Move to env var. Revoke + regenerate the token in GitLab User Settings > Access Tokens."

# S-01: Generic API key / secret in env-like assignments (TS/JS/Dart)
scan_pattern "CRITICAL" "S-01" "Likely hardcoded secret in code" \
    '(api_key|apikey|api-key|secret_key|secretkey|secret-key|private_key|access_key)[[:space:]]*[=:][[:space:]]*["'"'"'][a-zA-Z0-9_-]{20,}["'"'"']' \
    '\.(ts|tsx|js|jsx|dart|kt|swift|py)$' \
    "Move to env var. Don't commit secrets even in test files." \
    'process\.env|dotenv|String\.fromEnvironment|placeholder|EXAMPLE|YOUR_|XXX|<.*>|x{20,}'

# A-04: Math.random() for auth/OTP/password/token
scan_pattern "CRITICAL" "A-04" "Math.random() forbidden in security-sensitive code" \
    'Math\.random\(\)' \
    'auth|otp|password|token|crypto|verify|reset' \
    "Use crypto.randomBytes() (Node) or Random.secure() (Dart). Math.random() is NOT cryptographically secure."

# X-02: Asset ownership bypass via OR createdBy IS NULL
scan_pattern "CRITICAL" "X-02" "Asset ownership bypass (OR createdBy IS NULL)" \
    'or\([^)]*createdBy[^)]*isNull|createdBy[^=]*OR[[:space:]]+[^[:space:]]+[[:space:]]+IS[[:space:]]+NULL|isNull\([^)]*createdBy' \
    '\.(ts|tsx)$' \
    "Drop the OR createdBy IS NULL clause. Ownership query should be createdBy = ? only. See backend audit X-02."

# A-03: Auth token in localStorage (XSS-readable)
scan_pattern "CRITICAL" "A-03" "Auth token in localStorage (XSS-readable)" \
    'localStorage\.(setItem|getItem)\([[:space:]]*["'"'"']?(auth_?token|jwt|access_?token|refresh_?token|bearer)' \
    '\.(ts|tsx|js|jsx)$' \
    "Use HttpOnly + Secure + SameSite cookies set server-side. Never store auth tokens in localStorage."

# A-03: JWT in plaintext Hive box
scan_pattern "CRITICAL" "A-03" "JWT in plaintext Hive box" \
    'Hive\.box[^.]*\.put\([[:space:]]*["'"'"'](auth_?token|jwt|access_?token|refresh_?token|bearer)' \
    '\.dart$' \
    "Use flutter_secure_storage instead. Hive is not encrypted by default."

# S-03: Drizzle SQL logger ON without env gate
scan_pattern "CRITICAL" "S-03" "Drizzle SQL logger enabled without env gate" \
    'drizzle\([^)]*logger:[[:space:]]*true' \
    '\.(ts|tsx)$' \
    "Wrap with env check: drizzle({ logger: process.env.NODE_ENV !== 'production' })"

# Q-08: Drizzle .where() with JS && instead of and()
scan_pattern "CRITICAL" "Q-08" "Drizzle where() uses && instead of and()" \
    '\.where\([^)]*&&' \
    '\.(ts|tsx)$' \
    "Import { and } from 'drizzle-orm' and wrap conditions: and(condA, condB) - JS && breaks the query. See backend audit."

# P-01: Escrow tokens in NEW code (legal-copy pages are exempt - they say "does not escrow")
LEGAL_PAGE_PATTERN='app/(terms|privacy|cookies|data-deletion)/'
P01_FILES=$(printf "%s\n" "$CODE_FILES" | grep -E '\.(ts|tsx|dart|sql)$' | grep -vE "$LEGAL_PAGE_PATTERN" 2>/dev/null || true)
if [ -n "$P01_FILES" ]; then
    while IFS= read -r file; do
        [ -z "$file" ] && continue
        matches=$(read_file_content "$file" | grep -nE '(escrow|escrowStatus|escrow_status|releaseEscrow|release_escrow|paymentHeld|payment_held|holdPayment|hold_payment)' 2>/dev/null || true)
        if [ -n "$matches" ]; then
            while IFS= read -r match; do
                line=$(printf "%s" "$match" | cut -d: -f1)
                snippet=$(printf "%s" "$match" | cut -d: -f2- | sed 's/^[[:space:]]*//' | cut -c1-100)
                emit_violation "CRITICAL" "P-01" "Escrow code added (escrow is OUT of MVP scope)" "$file" "$line" "$snippet" \
                    "Snad confirmed escrow is removed from MVP. Drop the field/endpoint/UI section. Phase 2 may bring it back via Paystack."
            done <<< "$matches"
        fi
    done <<< "$P01_FILES"
fi

# ============================================================
# WARNINGS (don't block commit, but flag)
# ============================================================

# Q-03: console.log in committed TS/JS code
scan_pattern "WARNING" "Q-03" "console.log in committed code" \
    'console\.(log|debug)\(' \
    '\.(ts|tsx|js|jsx)$' \
    "Use the structured logger (NestJS Logger / pino / etc.). console.log is for ad-hoc debugging only." \
    'src/test|\.test\.|\.spec\.|tests/|__tests__|next\.config|playwright\.config'

# Q-03: print() in Dart files (non-test)
scan_pattern "WARNING" "Q-03" "print() in Dart code" \
    '^[[:space:]]*print\(' \
    '\.dart$' \
    "Use a logger package (logger, talker, etc.). print() is for tests/debug only." \
    'test/|_test\.dart|\.g\.dart|\.freezed\.dart'

# Q-07: FormData.fromMap (manual verification needed for Future bug - mobile audit critical)
scan_pattern "WARNING" "Q-07" "FormData.fromMap - verify no un-awaited Futures" \
    'FormData\.fromMap' \
    '\.dart$' \
    "Mobile audit critical: passing Future<MultipartFile> to FormData.fromMap silently breaks uploads. Verify all values are awaited BEFORE the map is built."

# S-13: Raw error message leakage to API responses (Node/NestJS)
scan_pattern "WARNING" "S-13" "Raw error.message exposed in API response" \
    '(res|response)\.(json|send|status\([^)]*\)\.(json|send))\([^)]*err(or)?\.(message|stack)|throw new HttpException\([^,]*err(or)?\.(message|stack)' \
    '\.(ts|tsx|js|jsx)$' \
    "Wrap with env gate: in dev/testing expose detail+stack, in production return a generic 'Something went wrong' message. ALWAYS log full error server-side. See S-13 in .claude/rules.md and feedback_seniority_and_workflow.md section 3."

# S-13: Raw error in mobile UI (Flutter)
scan_pattern "WARNING" "S-13" "Raw error.toString() shown in mobile UI" \
    '(showSnackBar|showDialog|Text|SnackBar)\([^)]*\$?\{?[a-zA-Z_]+\.toString\(\)\}?[^)]*\)' \
    '\.dart$' \
    "Use kDebugMode gate: 'kDebugMode ? \"DEV: \$e\" : \"Something went wrong\"'. Log via logger.e() always. See S-13 in .claude/rules.md." \
    'logger\.|debugPrint|print\('

# S-13: Raw error in React (admin dashboard)
scan_pattern "WARNING" "S-13" "Raw error.message in toast/UI (React)" \
    '(toast\.(error|warning|info)|setError|alert)\([^)]*err(or)?\.message' \
    '\.(ts|tsx|jsx)$' \
    "Use a formatErrorForUser() helper that env-gates the detail. In production, return a generic message; in dev/testing, show the detail. See S-13 in .claude/rules.md."

# Q-02: Empty catch blocks
scan_pattern "WARNING" "Q-02" "Empty catch block (errors silently swallowed)" \
    'catch[[:space:]]*\([^)]*\)[[:space:]]*\{[[:space:]]*\}|catch[[:space:]]*\{[[:space:]]*\}' \
    '\.(ts|tsx|js|jsx|dart)$' \
    "At minimum log the error. Re-throw if you can't handle it. Silent swallows hide bugs forever."

# Q-01: TypeScript : any (excluded in tests + .d.ts)
scan_pattern "WARNING" "Q-01" "TypeScript : any" \
    ':[[:space:]]*any[^a-zA-Z0-9_]|:[[:space:]]*any$|as[[:space:]]+any[^a-zA-Z0-9_]|as[[:space:]]+any$' \
    '\.(ts|tsx)$' \
    "Define a proper type or use unknown + a type guard." \
    '\.test\.|\.spec\.|\.d\.ts$|tests/|__tests__'

# ============================================================
# Q-13: AI hidden characters (em-dash, en-dash, ellipsis, smart quotes,
# zero-width, BOM) and decorative HTML entities (&mdash;/&ndash;/&hellip;)
# in committed code. Critical-tier; blocks the commit.
#
# BSD grep on macOS can't do Unicode classes, so we shell out to Python.
# Python ships with macOS + every Linux distro we deploy on, so it's safe
# to depend on. If Python isn't on PATH we silently skip Q-13 (the
# LLM-driven /x-check still catches it).
# ============================================================

if command -v python3 >/dev/null 2>&1; then
    # Exclude carrier files: the precommit script itself + the workflow YAML
    # both quote the offending characters legitimately (as detection
    # patterns / examples). Markdown is already filtered above; the rules /
    # memory files that document Q-13 fall under that exclusion.
    Q13_FILES=$(printf "%s\n" "$CODE_FILES" | grep -Ev '\.(md|markdown)$|x-precommit\.sh$|x-check\.ya?ml$' 2>/dev/null || true)
    if [ -n "$Q13_FILES" ]; then
        while IFS= read -r file; do
            [ -z "$file" ] && continue
            # Python reads the file content directly. In precommit mode
            # we'd ideally read STAGED content via git show, but the
            # working-tree copy is what the user just wrote and the
            # hook runs synchronously after their save; the diff vs
            # working tree is rarely meaningful here.
            content=$(read_file_content "$file")
            [ -z "$content" ] && continue
            hits=$(printf "%s" "$content" | python3 -c '
import re, sys
pat = re.compile(r"[–—…‘’“”​‌‍﻿]")
for i, line in enumerate(sys.stdin, 1):
    if pat.search(line):
        ch = pat.search(line).group()
        print(f"{i}:U+{ord(ch):04X}:{line.rstrip()[:120]}")
' 2>/dev/null || true)
            if [ -n "$hits" ]; then
                while IFS= read -r hit; do
                    line=$(printf "%s" "$hit" | cut -d: -f1)
                    cp=$(printf "%s" "$hit" | cut -d: -f2)
                    snippet=$(printf "%s" "$hit" | cut -d: -f3- | sed 's/^[[:space:]]*//' | cut -c1-100)
                    emit_violation "CRITICAL" "Q-13" "AI hidden character ($cp)" "$file" "$line" "$snippet" \
                        "Replace with plain ASCII: em-dash to comma/period/semicolon; smart quote to straight quote; zero-width/BOM to deletion. See .claude/rules.md Q-13."
                done <<< "$hits"
            fi
        done <<< "$Q13_FILES"
    fi
fi

# Q-13: HTML entities used as decoration (&mdash;, &ndash;, &hellip;).
# Legit in markdown / docs; only flag in code files.
scan_pattern "CRITICAL" "Q-13" "Decorative HTML entity (&mdash;/&ndash;/&hellip;)" \
    '&(mdash|ndash|hellip);' \
    '\.(ts|tsx|js|jsx|dart|kt|swift|py|php|graphql|html|svelte|vue|astro)$' \
    "Replace with plain ASCII. &mdash; -> period/comma/semicolon; &hellip; -> three ASCII dots or restructure. See Q-13."

# ============================================================
# S-02: Committed .env files (special-case: filename check, not content)
# ============================================================

ENV_FILES=$(printf "%s\n" "$CODE_FILES" | grep -E '(^|/)\.env($|\.|[^/]*$)' | grep -vE '\.example|example\.env|\.env\.template|\.env\.test$|\.env\.testing$' || true)
if [ -n "$ENV_FILES" ]; then
    while IFS= read -r file; do
        [ -z "$file" ] && continue
        printf "${RED}${BOLD}🔴 S-02 .env file committed${NC}\n"
        printf "   ${BLUE}%s${NC}\n" "$file"
        printf "   ${BOLD}Fix:${NC} Add to .gitignore. Use example.env for the schema (no real values).\n\n"
        VIOLATIONS=$((VIOLATIONS + 1))
    done <<< "$ENV_FILES"
fi

# ============================================================
# Report
# ============================================================

printf "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

if [ "$VIOLATIONS" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
    printf "${GREEN}${BOLD}✅ x-precommit: PASSED - no critical rule violations${NC}\n"
    exit 0
fi

if [ "$WARNINGS" -gt 0 ]; then
    printf "${YELLOW}${BOLD}⚠  %s warning(s) - review but not blocking${NC}\n" "$WARNINGS"
fi

if [ "$VIOLATIONS" -gt 0 ]; then
    printf "${RED}${BOLD}❌ x-precommit: BLOCKED - %s critical violation(s)${NC}\n\n" "$VIOLATIONS"
    printf "${BOLD}Options:${NC}\n"
    printf "  1. Fix the violations above and try the commit again\n"
    printf "  2. In Claude Code, run /x-implement or /x-check for full LLM-based check + fixes\n"
    printf "  3. Bypass (NOT recommended): git commit --no-verify\n"
    exit 1
fi

# Warnings only - commit allowed
exit 0
