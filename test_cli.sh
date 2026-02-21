#!/bin/bash
# Unified koon test suite — CLI tool.
set -o pipefail

KOON="./target/release/koon.exe"
PASS=0
FAIL=0
TMPDIR="${TMPDIR:-/tmp}"

ok() {
  local name="$1" cond="$2" detail="$3"
  if [ "$cond" = "true" ]; then
    PASS=$((PASS + 1))
    echo "  [PASS] $name${detail:+  ($detail)}"
  else
    FAIL=$((FAIL + 1))
    echo "  [FAIL] $name${detail:+  ($detail)}"
  fi
}

echo "=== koon CLI Test Suite ==="
echo

# --- 1. Browser profiles GET ---
echo "[Browsers]"

OUT=$($KOON -b chrome145 --json https://httpbin.org/get 2>&1)
STATUS=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
ok "1. Chrome 145 GET httpbin" "$([ "$STATUS" = "200" ] && echo true)" "$STATUS"

OUT=$($KOON -b firefox147 --json https://httpbin.org/get 2>&1)
STATUS=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
ok "2. Firefox 147 GET httpbin" "$([ "$STATUS" = "200" ] && echo true)" "$STATUS"

OUT=$($KOON -b safari18.3 --json https://httpbin.org/get 2>&1)
STATUS=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
ok "3. Safari 18.3 GET httpbin" "$([ "$STATUS" = "200" ] && echo true)" "$STATUS"

OUT=$($KOON -b edge145 --json https://httpbin.org/get 2>&1)
STATUS=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
ok "4. Edge 145 GET httpbin" "$([ "$STATUS" = "200" ] && echo true)" "$STATUS"

OUT=$($KOON -b opera127 --json https://httpbin.org/get 2>&1)
STATUS=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
ok "5. Opera 127 GET httpbin" "$([ "$STATUS" = "200" ] && echo true)" "$STATUS"

# --- 2. HTTP methods ---
echo
echo "[HTTP Methods]"

OUT=$($KOON -b chrome145 -X POST -d 'hello from cli' --json https://httpbin.org/post 2>&1)
ECHO=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['body'])" 2>/dev/null | python -c "import sys,json; print(json.load(sys.stdin).get('data',''))" 2>/dev/null)
ok "6. POST with body" "$([ "$ECHO" = "hello from cli" ] && echo true)" "echo: \"$ECHO\""

OUT=$($KOON -b chrome145 -X PUT -d 'put data' --json https://httpbin.org/put 2>&1)
STATUS=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
ok "7. PUT with body" "$([ "$STATUS" = "200" ] && echo true)" "$STATUS"

OUT=$($KOON -b chrome145 -X DELETE --json https://httpbin.org/delete 2>&1)
STATUS=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
ok "8. DELETE" "$([ "$STATUS" = "200" ] && echo true)" "$STATUS"

OUT=$($KOON -b chrome145 -X PATCH -d 'patch data' --json https://httpbin.org/patch 2>&1)
STATUS=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
ok "9. PATCH with body" "$([ "$STATUS" = "200" ] && echo true)" "$STATUS"

OUT=$($KOON -b chrome145 -X HEAD --json https://httpbin.org/get 2>&1)
STATUS=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
ok "10. HEAD" "$([ "$STATUS" = "200" ] && echo true)" "$STATUS"

# --- 3. Features ---
echo
echo "[Features]"

OUT=$($KOON -b chrome145 -H "X-Koon-Test: cli-binding" --json https://httpbin.org/headers 2>&1)
HAS=$(echo "$OUT" | python -c "import sys,json; d=json.load(sys.stdin); print('cli-binding' in json.dumps(d))" 2>/dev/null)
ok "11. Custom headers" "$([ "$HAS" = "True" ] && echo true)"

# Cookie: the redirect from /cookies/set includes Set-Cookie, and within the same client
# the cookie jar should persist. But CLI is one request, so we test via --json.
OUT=$($KOON -b chrome145 --json https://httpbin.org/cookies/set/clitest/clivalue 2>&1)
HAS=$(echo "$OUT" | python -c "import sys,json; d=json.load(sys.stdin); print('clitest' in d['body'])" 2>/dev/null)
ok "12. Cookie in redirect" "$([ "$HAS" = "True" ] && echo true)"

# Session save/load
SESSION_FILE="$TMPDIR/koon_cli_test_session.json"
$KOON -b chrome145 --save-session "$SESSION_FILE" --json https://httpbin.org/cookies/set/savecli/saveval >/dev/null 2>&1
ok "13. Session save" "$([ -f "$SESSION_FILE" ] && echo true)"

OUT=$($KOON -b chrome145 --load-session "$SESSION_FILE" --json https://httpbin.org/cookies 2>&1)
rm -f "$SESSION_FILE"
HAS=$(echo "$OUT" | python -c "import sys,json; d=json.load(sys.stdin); print('savecli' in d['body'])" 2>/dev/null)
ok "14. Session load" "$([ "$HAS" = "True" ] && echo true)"

# Profile export
OUT=$($KOON --export-profile chrome145 2>&1)
HAS_CIPHER=$(echo "$OUT" | python -c "import sys; print('cipher_list' in sys.stdin.read())" 2>/dev/null)
ok "15. Profile export" "$([ "$HAS_CIPHER" = "True" ] && echo true)"

# Randomize
OUT=$($KOON -b chrome145 --randomize --json https://httpbin.org/get 2>&1)
STATUS=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
ok "16. Randomize" "$([ "$STATUS" = "200" ] && echo true)" "$STATUS"

# OS suffixes
OUT=$($KOON -b chrome145-macos --json https://httpbin.org/get 2>&1)
STATUS=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
ok "17. OS suffix (-macos)" "$([ "$STATUS" = "200" ] && echo true)" "$STATUS"

OUT=$($KOON -b firefox147-linux --json https://httpbin.org/get 2>&1)
STATUS=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
ok "18. OS suffix (-linux)" "$([ "$STATUS" = "200" ] && echo true)" "$STATUS"

# --- 4. TLS Fingerprint ---
echo
echo "[Fingerprint]"

OUT=$($KOON -b chrome145 https://tls.browserleaks.com/json 2>&1)
JA3N=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['ja3n_hash'])" 2>/dev/null)
JA4=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['ja4'])" 2>/dev/null)
AKAMAI=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['akamai_hash'])" 2>/dev/null)
ok "19. Chrome JA3N" "$([ "$JA3N" = "8e19337e7524d2573be54efb2b0784c9" ] && echo true)" "$JA3N"
ok "20. Chrome JA4" "$([ "$JA4" = "t13d1516h2_8daaf6152771_d8a2da3f94cd" ] && echo true)" "$JA4"
ok "21. Chrome Akamai" "$([ "$AKAMAI" = "52d84b11737d980aef856699f885ca86" ] && echo true)" "$AKAMAI"

OUT=$($KOON -b firefox147 https://tls.browserleaks.com/json 2>&1)
JA3N=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['ja3n_hash'])" 2>/dev/null)
ok "22. Firefox JA3N" "$([ "$JA3N" = "e4147a4860c1f347354f0a84d8787c02" ] && echo true)" "$JA3N"

OUT=$($KOON -b safari18.3 https://tls.browserleaks.com/json 2>&1)
JA3=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['ja3_hash'])" 2>/dev/null)
ok "23. Safari JA3" "$([ "$JA3" = "773906b0efdefa24a7f2b8eb6985bf37" ] && echo true)" "$JA3"

# --- 5. Anti-Bot Sites ---
echo
echo "[Anti-Bot]"

OUT=$($KOON -b chrome145 --json https://nowsecure.nl 2>&1)
STATUS=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
ok "24. nowsecure.nl (Cloudflare)" "$([ "$STATUS" = "200" ] && echo true)" "$STATUS"

OUT=$($KOON -b firefox147 --json https://www.ticketmaster.com 2>&1)
STATUS=$(echo "$OUT" | python -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
ok "25. ticketmaster.com" "$([ "$STATUS" = "200" ] && echo true)" "$STATUS"

# --- 6. Output modes ---
echo
echo "[Output Modes]"

OUTFILE="$TMPDIR/koon_cli_test_output.bin"
$KOON -b chrome145 -o "$OUTFILE" https://httpbin.org/bytes/1024 2>&1
SIZE=$(wc -c < "$OUTFILE" 2>/dev/null | tr -d ' ')
rm -f "$OUTFILE"
ok "26. Output to file (-o)" "$([ "$SIZE" = "1024" ] && echo true)" "${SIZE}b"

OUT=$($KOON -b chrome145 --json https://httpbin.org/get 2>&1)
HAS=$(echo "$OUT" | python -c "import sys,json; d=json.load(sys.stdin); print('status' in d and 'headers' in d and 'body' in d)" 2>/dev/null)
ok "27. JSON output (--json)" "$([ "$HAS" = "True" ] && echo true)"

# List browsers
OUT=$($KOON --list-browsers 2>&1)
HAS=$(echo "$OUT" | grep -c "Chrome" 2>/dev/null)
ok "28. List browsers" "$([ "$HAS" -gt 0 ] && echo true)"

# --- Summary ---
TOTAL=$((PASS + FAIL))
echo
if [ "$FAIL" -gt 0 ]; then
  echo "=== CLI: $PASS/$TOTAL passed, $FAIL FAILED ==="
  exit 1
else
  echo "=== CLI: $PASS/$TOTAL passed ==="
fi
