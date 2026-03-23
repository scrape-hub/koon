#!/bin/bash
# Pre-release test: CLI
echo ""
echo "=== CLI ==="
echo ""

PASSED=0
FAILED=0
SKIPPED=0
KOON="koon"

ok() {
  if [ "$2" = "true" ]; then
    echo "  [PASS] $1"
    ((PASSED++))
  else
    echo "  [FAIL] $1"
    ((FAILED++))
  fi
}

skip() {
  echo "  [SKIP] $1"
  ((SKIPPED++))
}

# Check if koon CLI is available
if ! command -v $KOON &>/dev/null; then
  # Try local build
  if [ -f "../../target/release/koon.exe" ]; then
    KOON="../../target/release/koon.exe"
  elif [ -f "../../target/release/koon" ]; then
    KOON="../../target/release/koon"
  else
    echo "  [FAIL] koon CLI not found"
    echo ""
    echo "=== cli: 0/0 passed, 1 FAILED ==="
    exit 1
  fi
fi

# ── Basic Profiles ─────────────────────────────────────────────
echo "-- Basic Profiles --"
for profile in chrome145 firefox148 safari183; do
  STATUS=$($KOON -b $profile --json https://httpbin.org/get 2>/dev/null | grep -o '"status": *[0-9]*' | head -1 | grep -o '[0-9]*')
  ok "$profile GET status=200" "$([ "$STATUS" = "200" ] && echo true || echo false)"
done

# ── HTTP Methods ───────────────────────────────────────────────
echo "-- HTTP Methods --"
BODY=$($KOON -b chrome145 -X POST -d "cli body test" https://httpbin.org/post 2>/dev/null)
ok "POST echoes body" "$(echo "$BODY" | grep -q 'cli body test' && echo true || echo false)"

STATUS=$($KOON -b chrome145 -X HEAD --json https://httpbin.org/get 2>/dev/null | grep -o '"status": *[0-9]*' | head -1 | grep -o '[0-9]*')
ok "HEAD status=200" "$([ "$STATUS" = "200" ] && echo true || echo false)"

# ── Custom Headers ─────────────────────────────────────────────
echo "-- Custom Headers --"
RESULT=$($KOON -b chrome145 -H "X-Koon-Test: cli-test" https://httpbin.org/headers 2>/dev/null)
ok "custom header sent" "$(echo "$RESULT" | grep -q 'cli-test' && echo true || echo false)"

# ── Session Save/Load ─────────────────────────────────────────
echo "-- Session --"
TMPFILE=$(mktemp)
$KOON -b chrome145 --save-session "$TMPFILE" https://httpbin.org/cookies/set/clikey/clival 2>/dev/null
ok "save-session creates file" "$([ -s "$TMPFILE" ] && echo true || echo false)"

COOKIES=$($KOON -b chrome145 --load-session "$TMPFILE" https://httpbin.org/cookies 2>/dev/null)
ok "load-session restores cookies" "$(echo "$COOKIES" | grep -q 'clikey' && echo true || echo false)"
rm -f "$TMPFILE"

# ── List Browsers ─────────────────────────────────────────────
echo "-- Utility --"
BROWSERS=$($KOON --list-browsers 2>/dev/null)
ok "list-browsers has chrome" "$(echo "$BROWSERS" | grep -q 'chrome145' && echo true || echo false)"
ok "list-browsers has firefox" "$(echo "$BROWSERS" | grep -q 'firefox148' && echo true || echo false)"

# ── Proxy ─────────────────────────────────────────────────────
echo "-- Proxy --"
if [ -n "$KOON_TEST_PROXY" ]; then
  STATUS=$($KOON -b chrome145 --proxy "$KOON_TEST_PROXY" --json https://httpbin.org/ip 2>/dev/null | grep -o '"status": *[0-9]*' | head -1 | grep -o '[0-9]*')
  ok "proxy via CLI" "$([ "$STATUS" = "200" ] && echo true || echo false)"
else
  skip "proxy (KOON_TEST_PROXY not set)"
fi

# ── WAF Smoke ─────────────────────────────────────────────────
echo "-- WAF Smoke (soft-fail) --"
for site in "https://nowsecure.nl Cloudflare" "https://www.nike.com Akamai"; do
  URL=$(echo $site | cut -d' ' -f1)
  NAME=$(echo $site | cut -d' ' -f2)
  STATUS=$($KOON -b chrome145 --json "$URL" 2>/dev/null | grep -o '"status": *[0-9]*' | head -1 | grep -o '[0-9]*')
  if [ "$STATUS" = "200" ]; then
    echo "  [PASS] $NAME -> 200"
    ((PASSED++))
  else
    echo "  [WARN] $NAME -> ${STATUS:-ERR}"
  fi
done

# ── Summary ──────────────────────────────────────────────────
TOTAL=$((PASSED + FAILED))
MSG="=== cli: ${PASSED}/${TOTAL} passed"
[ $FAILED -gt 0 ] && MSG="$MSG, ${FAILED} FAILED"
[ $SKIPPED -gt 0 ] && MSG="$MSG, ${SKIPPED} skipped"
MSG="$MSG ==="
echo ""
echo "$MSG"
echo ""
[ $FAILED -gt 0 ] && exit 1 || exit 0
