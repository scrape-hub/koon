#!/bin/bash
# koon pre-release test suite
# Usage: bash todo/pre-release/run-all.sh [--proxy http://user:pass@host:port]
#
# Runs all binding tests and prints a combined summary.
# Exit code 0 = all passed, 1 = failures detected.

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR/../.."

# Add R to PATH if available on Windows
for rdir in "/c/Program Files/R"/R-*/bin/x64; do
  [ -d "$rdir" ] && export PATH="$rdir:$PATH" && break
done

# Ensure global npm packages are resolvable by Node.js require()
if [ -z "$NODE_PATH" ]; then
  export NODE_PATH="$(npm root -g 2>/dev/null)"
fi

# Parse --proxy flag
if [ "$1" = "--proxy" ] && [ -n "$2" ]; then
  export KOON_TEST_PROXY="$2"
  echo "Proxy: $KOON_TEST_PROXY"
fi

TOTAL_PASS=0
TOTAL_FAIL=0
SUITE_RESULTS=""
ANY_FAIL=0

run_suite() {
  local name="$1"
  local cmd="$2"
  local output
  local exit_code=0

  # Brief pause between suites to avoid httpbin.org rate limiting
  [ -n "$SUITE_RESULTS" ] && sleep 3

  output=$(eval "$cmd" 2>&1) || exit_code=$?
  echo "$output"

  # Extract summary line
  local summary_line=$(echo "$output" | grep "^=== " | tail -1)
  SUITE_RESULTS="$SUITE_RESULTS\n  $summary_line"

  if [ $exit_code -ne 0 ]; then
    ANY_FAIL=1
  fi
}

echo ""
echo "========================================"
echo "  koon pre-release test suite"
echo "========================================"

# ── Node.js ────────────────────────────────────────────────────
if command -v node &>/dev/null; then
  run_suite "node" "node '$DIR/test-node.mjs'"
else
  echo "  [SKIP] Node.js not available"
fi

# ── Python async ──────────────────────────────────────────────
if command -v python &>/dev/null; then
  run_suite "python-async" "python '$DIR/test-python-async.py'"
else
  echo "  [SKIP] Python not available"
fi

# ── Python sync ───────────────────────────────────────────────
if command -v python &>/dev/null; then
  run_suite "python-sync" "python '$DIR/test-python-sync.py'"
fi

# ── R ─────────────────────────────────────────────────────────
if command -v Rscript &>/dev/null; then
  run_suite "r" "Rscript '$DIR/test-r.R'"
else
  echo "  [SKIP] R not available"
fi

# ── CLI ───────────────────────────────────────────────────────
run_suite "cli" "bash '$DIR/test-cli.sh'"

# ── Combined Summary ─────────────────────────────────────────
echo ""
echo "========================================"
echo "  SUMMARY"
echo "========================================"
echo -e "$SUITE_RESULTS"
echo ""

if [ $ANY_FAIL -ne 0 ]; then
  echo "RESULT: FAILURES DETECTED"
  exit 1
else
  echo "RESULT: ALL PASSED"
  exit 0
fi
