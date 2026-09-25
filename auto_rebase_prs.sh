#!/usr/bin/env bash
#
# auto_rebase_prs.sh — Auto-rebase open PRs by @kuehnberger whose base advanced
#
# VPS-side rebase automation: discovers all open PRs by @kuehnberger,
# checks each for merge conflicts / new base commits, and rebases
# in isolated worktrees. Targeted tests are run after rebase. Result is
# STAGED only — the worktree is left in a rebased state. Final push decision
# is left to the user after review (per user specification).
#
# Output: prints a summary of actions taken. Silent on no-op.
#
# Env knobs:
#   AUTHOR          GitHub login to scan           (default kuehnberger)
#   MAIN_REPO_DIR   clone that holds the worktrees (default $WORKTREE_DIR/../repo)
#   WORKTREE_DIR    where per-PR worktrees live    (default <repo>/.worktrees)
#   LOG_DIR         detail/rebase/test logs        (default ~/.hermes/logs/auto-rebase)
#   TEST_TIMEOUT    per-PR test budget, seconds    (default 900)
#   DRY_RUN         1 = detect and print only, no worktree/rebase/tests
#
# History: the 2026-09-20 version never completed one run (19/19 exit 128).
# It read `.head.ref` off the SEARCH payload (which carries no head/base objects)
# and built the detail object with `head: {ref, sha}`, which jq resolves against
# the ROOT of the PR, not `.head` — so both refs came out null and the script ran
# `git fetch origin None`. It also fetched PR head branches from upstream
# (they live in the fork) and ran the full suite with system python3, which has
# none of the repo's dependencies.
#
set -euo pipefail

AUTHOR="${AUTHOR:-kuehnberger}"
# Canonical host layout (WSL vs VPS differ — see ~/.hermes/scripts/repo_env.sh for the
# history of the two silent failures this prevents). It exports REPO_ROOT, WT_ROOT,
# VENV_PY and GH_BIN; the ${...:-} defaults below keep this script standalone-runnable.
HERMES_ROOT="${HERMES_ROOT:-$HOME/.hermes/hermes-agent}"
# shellcheck disable=SC1091
[ -f "$HOME/.hermes/scripts/repo_env.sh" ] && source "$HOME/.hermes/scripts/repo_env.sh"
WORKTREE_DIR="${WORKTREE_DIR:-${WT_ROOT:-$HERMES_ROOT/.worktrees}}"
MAIN_REPO_DIR="${MAIN_REPO_DIR:-${REPO_ROOT:-$WORKTREE_DIR/../repo}}"
LOG_DIR="${LOG_DIR:-$HOME/.hermes/logs/auto-rebase}"
TEST_TIMEOUT="${TEST_TIMEOUT:-900}"
DRY_RUN="${DRY_RUN:-0}"

mkdir -p "$LOG_DIR" "$WORKTREE_DIR"

# --- gh environment setup (VPS profile auth) ---
export PATH="$HOME/bin:$PATH"
if [ -f "$HOME/.hermes/profiles/nous-watch/.gh_env" ]; then
    # shellcheck disable=SC1091
    source "$HOME/.hermes/profiles/nous-watch/.gh_env"
fi

if ! command -v gh &>/dev/null; then
    echo "ERROR: gh not found on PATH" >&2
    exit 1
fi
if ! gh auth status &>/dev/null; then
    echo "ERROR: gh not authenticated (source ~/.hermes/profiles/nous-watch/.gh_env)" >&2
    exit 1
fi
# Resolve the binary path at runtime: workers that hard-coded /usr/bin/gh silently
# failed to authenticate (gh lives in ~/bin on the VPS) and every push died with
# "could not read Username for 'https://github.com'" while the wrapper exited 0.
GH_BIN="${GH_BIN:-$(command -v gh)}"

# --- Transient API retry with explicit failure state ---
gh_api_retry() {
    local url="$1" jq_filter="$2" attempts="${3:-3}" delay="${4:-5}" out="" err=""
    for try in $(seq 1 "$attempts"); do
        out=$(gh api "$url" --jq "$jq_filter" 2>/dev/null) && { printf '%s' "$out"; return 0; }
        err=$(gh api "$url" --jq "$jq_filter" 2>&1 >/dev/null) || true
        case "$err" in
            *rate*|*Rate*|*403*|*timeout*|*timed*|*connection*|*refused*)
                echo "  API retry $try/$attempts for $url: $err" >&2
                sleep "$delay";;
            *) printf '%s' "$err"; return 1;;
        esac
    done
    echo "  API retry exhausted for $url" >&2
    return 1
}

# Mergeability is computed lazily: the first read of a quiet PR returns
# "unknown" and only triggers the computation. Re-ask a couple of times.
mergeable_state_with_retry() {
    local repo="$1" number="$2" attempts="${3:-3}" state=""
    for _ in $(seq 1 "$attempts"); do
        state=$(gh_api_retry "repos/${repo}/pulls/${number}" '.mergeable_state // "unknown"' 2>/dev/null || echo "unknown")
        [ "$state" != "unknown" ] && { printf '%s' "$state"; return 0; }
        sleep 3
    done
    printf 'unknown'
}

# --- Discover all open PRs by AUTHOR across all repos ---
DISCOVERY_LOG="$LOG_DIR/discovery.jsonl"

echo "Discovering open PRs by @$AUTHOR..."
gh api "/search/issues?q=author:${AUTHOR}+type:pr+is:open&per_page=100" \
    --jq '.items[]' \
    > "$DISCOVERY_LOG" 2>&1 || {
    echo "ERROR: GitHub search API failed" >&2
    cat "$DISCOVERY_LOG" >&2
    exit 1
}

PR_COUNT=$(grep -c . "$DISCOVERY_LOG" || true)
if [ -z "$PR_COUNT" ] || [ "$PR_COUNT" -eq 0 ]; then
    echo "No open PRs by @$AUTHOR found."
    exit 0
fi

echo "Found $PR_COUNT open PRs."
echo "---"

REBASED=0
SKIPPED=0
FAILED=0
PROCESSED=0
CURRENT_INDEX=0

# Search results carry number/title/url/draft/repository_url only — head & base
# come from the per-PR detail call below.
while IFS= read -r line; do
    [ -z "$line" ] && continue
    CURRENT_INDEX=$((CURRENT_INDEX + 1))

    read -r PR_NUMBER REPO_FULL PR_URL DRAFT < <(python3 - "$line" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
repo = d.get("repository_url", "")
parts = repo.rstrip("/").split("/repos/")
name = parts[1] if len(parts) > 1 else ""
print(d.get("number", ""), name, d.get("html_url", ""), d.get("draft", False))
PY
)
    PR_TITLE=$(python3 - "$line" <<'PY'
import json, sys
print(json.loads(sys.argv[1]).get("title", "(no title)")[:80])
PY
)

    echo "[$CURRENT_INDEX/$PR_COUNT] PR $REPO_FULL#$PR_NUMBER: \"$PR_TITLE\""
    echo "  URL: $PR_URL"
    echo "  Draft: $DRAFT"

    if [ -z "$REPO_FULL" ] || [ -z "$PR_NUMBER" ]; then
        echo "  FAIL: could not parse repo/number from search payload"
        FAILED=$((FAILED + 1)); PROCESSED=$((PROCESSED + 1)); echo "---"; continue
    fi

    if [ "$DRAFT" = "True" ]; then
        echo "  SKIP: draft PR"
        SKIPPED=$((SKIPPED + 1)); PROCESSED=$((PROCESSED + 1)); echo "---"; continue
    fi

    # Only handle hermes-agent PRs — the main repo
    if [ "$REPO_FULL" != "NousResearch/hermes-agent" ]; then
        echo "  SKIP: not NousResearch/hermes-agent repo"
        SKIPPED=$((SKIPPED + 1)); PROCESSED=$((PROCESSED + 1)); echo "---"; continue
    fi

    # --- Per-PR detail: refs must be selected with an explicit path (.head.ref),
    # `head: {ref}` would read the ROOT object's ref/sha and yield null. ---
    echo "  Fetching PR details..."
    PR_DETAIL_LOG="$LOG_DIR/pr${PR_NUMBER}_detail.json"
    gh api "repos/${REPO_FULL}/pulls/${PR_NUMBER}" \
        --jq '{state, mergeable, mergeable_state, merged, title, draft, html_url,
               head_ref: .head.ref, head_sha: .head.sha, head_repo: .head.repo.full_name,
               base_ref: .base.ref, base_sha: .base.sha}' \
        > "$PR_DETAIL_LOG" 2>&1 || {
        echo "  FAIL: could not fetch PR details"
        FAILED=$((FAILED + 1)); PROCESSED=$((PROCESSED + 1)); echo "---"; continue
    }

    read -r PR_STATE PR_MERGED HEAD_REF BASE_REF BASE_SHA_API HEAD_REPO < <(python3 - "$PR_DETAIL_LOG" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(d.get("state", "open"), d.get("merged", False), d.get("head_ref") or "",
      d.get("base_ref") or "", d.get("base_sha") or "", d.get("head_repo") or "")
PY
)
    MERGEABLE_STATE=$(mergeable_state_with_retry "$REPO_FULL" "$PR_NUMBER" 3)

    echo "  Branch: $HEAD_REF ($HEAD_REPO) -> $BASE_REF"
    echo "  mergeable_state: $MERGEABLE_STATE"
    echo "  state: $PR_STATE, merged: $PR_MERGED"

    # Never fall through to `git fetch origin None` again.
    if [ -z "$HEAD_REF" ] || [ -z "$BASE_REF" ] || [ -z "$HEAD_REPO" ]; then
        echo "  FAIL: incomplete PR refs (head='$HEAD_REF' base='$BASE_REF' repo='$HEAD_REPO')"
        FAILED=$((FAILED + 1)); PROCESSED=$((PROCESSED + 1)); echo "---"; continue
    fi

    if [ "$PR_STATE" != "open" ] || [ "$PR_MERGED" = "True" ]; then
        echo "  SKIP: PR not open or already merged"
        SKIPPED=$((SKIPPED + 1)); PROCESSED=$((PROCESSED + 1)); echo "---"; continue
    fi

    NEEDS_REBASE=false
    case "$MERGEABLE_STATE" in
        clean)
            echo "  STATUS: clean — no rebase needed"
            SKIPPED=$((SKIPPED + 1)); PROCESSED=$((PROCESSED + 1)); echo "---"; continue
            ;;
        dirty)
            echo "  STATUS: dirty — merge conflict, needs rebase"
            NEEDS_REBASE=true
            ;;
        unstable|blocked|has_hooks|unknown)
            echo "  STATUS: $MERGEABLE_STATE — checking base branch relationship..."
            ;;
        *)
            echo "  STATUS: $MERGEABLE_STATE"
            NEEDS_REBASE=true
            ;;
    esac

    # --- Repo that hosts the worktrees ---
    MAIN_REPO_DIR="$(cd "$(dirname "$MAIN_REPO_DIR")" && pwd)/$(basename "$MAIN_REPO_DIR")" 2>/dev/null || true
    if [ ! -d "$MAIN_REPO_DIR/.git" ]; then
        echo "  Cloning $REPO_FULL into $MAIN_REPO_DIR..."
        gh repo clone "$REPO_FULL" "$MAIN_REPO_DIR" 2>&1 | tail -2
    fi
    cd "$MAIN_REPO_DIR"
    git config credential.helper "!$GH_BIN auth git-credential"

    # PR head branches live in the FORK, which is not `origin` (upstream).
    HEAD_OWNER="${HEAD_REPO%%/*}"
    if ! git remote get-url "$HEAD_OWNER" &>/dev/null; then
        git remote add "$HEAD_OWNER" "https://github.com/${HEAD_REPO}.git"
    fi
    git fetch --no-tags "$HEAD_OWNER" "$HEAD_REF" 2>&1 | tail -1

    if [ "$NEEDS_REBASE" = "false" ]; then
        echo "  Fetching latest $BASE_REF from origin..."
        git fetch --no-tags origin "$BASE_REF" 2>&1 | tail -1

        BASE_LATEST=$(git rev-parse "origin/$BASE_REF" 2>/dev/null || echo "")
        if [ -n "$BASE_LATEST" ] && [ "$BASE_LATEST" != "$BASE_SHA_API" ]; then
            echo "  Base advanced: ${BASE_SHA_API:0:12} -> ${BASE_LATEST:0:12} — rebase needed"
            NEEDS_REBASE=true
        elif [ -z "$BASE_LATEST" ]; then
            echo "  FAIL: could not resolve origin/$BASE_REF"
            FAILED=$((FAILED + 1)); PROCESSED=$((PROCESSED + 1)); echo "---"; continue
        else
            echo "  Base unchanged — no rebase needed"
            SKIPPED=$((SKIPPED + 1)); PROCESSED=$((PROCESSED + 1)); echo "---"; continue
        fi
    fi

    if [ "$DRY_RUN" = "1" ]; then
        echo "  [DRY_RUN] would rebase $HEAD_REF ($HEAD_REPO) onto origin/$BASE_REF in $WORKTREE_DIR/pr${PR_NUMBER}"
        REBASED=$((REBASED + 1)); PROCESSED=$((PROCESSED + 1)); echo "---"; continue
    fi

    # --- Perform rebase in an isolated worktree ---
    WT_DIR="$WORKTREE_DIR/pr${PR_NUMBER}"
    if [ -d "$WT_DIR" ]; then
        echo "  Reusing existing worktree: $WT_DIR"
        cd "$WT_DIR"
        git checkout -q "$HEAD_REF" 2>&1 | tail -1 || true
        git reset --hard "$HEAD_OWNER/$HEAD_REF" 2>&1 | tail -1
    else
        echo "  Creating worktree: $WT_DIR"
        cd "$MAIN_REPO_DIR"
        git worktree add -B "$HEAD_REF" "$WT_DIR" "$HEAD_OWNER/$HEAD_REF" 2>&1 | tail -1
        cd "$WT_DIR"
    fi

    git config user.email "$(gh api user --jq '.email // .login' 2>/dev/null || echo 'gk@example.com')"
    git config user.name "Hermes Agent"
    git config credential.helper "!$GH_BIN auth git-credential"

    echo "  Rebasing $HEAD_REF onto origin/$BASE_REF..."
    REBASE_LOG="$LOG_DIR/pr${PR_NUMBER}_rebase.log"
    if git rebase "origin/$BASE_REF" > "$REBASE_LOG" 2>&1; then
        echo "  Rebase: SUCCESS"
    else
        echo "  Rebase: CONFLICTS detected — leaving worktree for manual resolution"
        tail -5 "$REBASE_LOG"
        FAILED=$((FAILED + 1)); PROCESSED=$((PROCESSED + 1)); echo "---"; continue
    fi

    # --- Targeted tests: only the test files this PR touches, via the repo's own
    # runner (system python3 has none of the dependencies; the full suite does not
    # fit the VPS budget). ---
    TEST_LOG="$LOG_DIR/pr${PR_NUMBER}_tests.log"
    TEST_FILES=$(git diff --name-only "origin/$BASE_REF...HEAD" 2>/dev/null | grep -E '^tests/.*\.py$' || true)
    if [ -z "$TEST_FILES" ]; then
        echo "  No test files touched by this PR — skipping tests"
        echo "no test files in diff" > "$TEST_LOG"
    elif [ -x "./scripts/run_tests.sh" ] || [ -x "$MAIN_REPO_DIR/scripts/run_tests.sh" ]; then
        if [ -x "./scripts/run_tests.sh" ]; then RUNNER="./scripts/run_tests.sh"; else RUNNER="$MAIN_REPO_DIR/scripts/run_tests.sh"; fi
        echo "  Running tests ($RUNNER): $(echo "$TEST_FILES" | tr '\n' ' ')"
        if timeout "$TEST_TIMEOUT" "$RUNNER" $TEST_FILES > "$TEST_LOG" 2>&1; then
            echo "  Tests: PASSED"
        else
            echo "  Tests: FAILED (or timed out) — see $TEST_LOG"
            tail -5 "$TEST_LOG" | sed 's/^/    /'
        fi
    else
        echo "  No test runner at $MAIN_REPO_DIR/scripts/run_tests.sh — skipping tests"
        echo "no runner at $MAIN_REPO_DIR/scripts/run_tests.sh" > "$TEST_LOG"
    fi

    echo "  Worktree ready at: $WT_DIR"
    echo "  NOT PUSHED — final push is user's decision after review"
    REBASED=$((REBASED + 1))
    PROCESSED=$((PROCESSED + 1))
    echo "---"
done < "$DISCOVERY_LOG"

echo ""
echo "=== SUMMARY ==="
echo "Total PRs processed: $PROCESSED"
echo "Rebased: $REBASED"
echo "Skipped: $SKIPPED"
echo "Failed: $FAILED"
[ "$DRY_RUN" = "1" ] && echo "(DRY_RUN — nothing was rebased or tested)"

if [ "$REBASED" -gt 0 ] && [ "$DRY_RUN" != "1" ]; then
    echo ""
    echo "REBASE_ALERT: $REBASED PR(s) rebased and staged. Review + push manually."
    echo "Worktrees: $(ls -d "$WORKTREE_DIR"/pr* 2>/dev/null || echo 'none')"
fi

exit 0