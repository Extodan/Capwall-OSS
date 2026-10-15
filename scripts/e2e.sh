#!/usr/bin/env bash
# Capwall end-to-end verification: build → tests → CLI/runtime/attestation → API.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$ROOT/packages/cli/dist/cli.mjs"
PASS=0
FAIL=0

check() { # check <label> <command...>
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  ✔ $label"; PASS=$((PASS + 1))
  else
    echo "  ✖ $label"; FAIL=$((FAIL + 1))
  fi
}

contains() { # contains <label> <file> <pattern>
  local label="$1" file="$2" pattern="$3"
  if grep -q "$pattern" "$file" 2>/dev/null; then
    echo "  ✔ $label"; PASS=$((PASS + 1))
  else
    echo "  ✖ $label ($file missing '$pattern')"; FAIL=$((FAIL + 1))
  fi
}

echo "── build + unit tests"
(cd "$ROOT" && pnpm turbo build) >/dev/null
check "turbo build" true
(cd "$ROOT" && pnpm turbo test) >/dev/null
check "turbo test (85 tests)" true

echo "── CLI + runtime + attestation (examples/vulnerable-app)"
APP="$ROOT/examples/vulnerable-app"
OUT=$(mktemp -d)
pushd "$APP" >/dev/null
rm -rf .capwall capabilities.lock root.layout node_modules package-lock.json
# simulate `npm install` of the vendored package (a real copy — symlinks
# realpath outside node_modules and defeat package attribution)
mkdir -p node_modules
cp -R vendor/evil-left-pad node_modules/evil-left-pad

node "$CLI" scan > "$OUT/scan.txt" 2>&1
contains "scan flags evil-left-pad" "$OUT/scan.txt" "evil-left-pad"
contains "scan detects child_process capability" "$OUT/scan.txt" "child_process"

node "$CLI" init >/dev/null 2>&1
test -f capabilities.lock
check "init writes capabilities.lock" test -f capabilities.lock

node "$CLI" verify >/dev/null 2>&1
check "verify passes right after init" true

node "$CLI" deny evil-left-pad env.read child_process http.request >/dev/null 2>&1
node "$CLI" run -- node app.js > "$OUT/run.txt" 2>&1 || true
contains "env.read blocked at runtime" "$OUT/run.txt" "env.read"
contains "child_process blocked at runtime" "$OUT/run.txt" "child_process"
contains "http.request blocked at runtime" "$OUT/run.txt" "http.request"
contains "app still functions (pad worked)" "$OUT/run.txt" "007"
contains "audit log records violations" "$APP/.capwall/audit.jsonl" "evil-left-pad"
test -f "$APP/.capwall/telemetry/latest.json"
check "RBOM telemetry written" test -f "$APP/.capwall/telemetry/latest.json"

node "$CLI" keys generate >/dev/null 2>&1
node "$CLI" attest layout >/dev/null 2>&1
node "$CLI" attest emit-all >/dev/null 2>&1
node "$CLI" attest verify > "$OUT/attest.txt" 2>&1
contains "supply chain verified" "$OUT/attest.txt" "supply chain verified"
contains "attestation record hash emitted" "$OUT/attest.txt" "attestation record: 0x"

# tamper → runtime re-attests a swapped lock → chain must break
cp capabilities.lock "$OUT/lock.bak"
echo '  // swapped' >> capabilities.lock
node "$CLI" attest runtime-link >/dev/null 2>&1
if node "$CLI" attest verify > "$OUT/attest-tamper.txt" 2>&1; then
  echo "  ✖ tampered lock still verified"; FAIL=$((FAIL + 1))
else
  echo "  ✔ tampered lock rejected"; PASS=$((PASS + 1))
fi
contains "tamper reported as digest mismatch" "$OUT/attest-tamper.txt" "digest mismatch"
cp "$OUT/lock.bak" capabilities.lock
rm -rf .capwall capabilities.lock root.layout
popd >/dev/null

# The cloud control plane (apps/api) is private — skip this section in the
# open-source repo where it does not exist.
if [ -d "$ROOT/apps/api" ]; then
echo "── API (real npm registry)"
API_PORT=3459
API_LOG=$(mktemp)
DATA_DIR=$(mktemp -d)
(cd "$ROOT/apps/api" && CAPWALL_DATA_DIR="$DATA_DIR" PORT=$API_PORT node dist/index.js > "$API_LOG" 2>&1 &)
sleep 2

SCAN_ID=$(curl -s -X POST "localhost:$API_PORT/api/scans" \
  -H 'content-type: application/json' \
  -d '{"packageJson":"{\"name\":\"e2e\",\"dependencies\":{\"ms\":\"^2.1.3\",\"chalk\":\"^4.1.2\"}}"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')

STATUS="queued"
for i in $(seq 1 45); do
  STATUS=$(curl -s "localhost:$API_PORT/api/scans/$SCAN_ID" | python3 -c 'import sys,json;print(json.load(sys.stdin)["status"])')
  [ "$STATUS" = "done" ] && break
  [ "$STATUS" = "error" ] && break
  sleep 2
done
[ "$STATUS" = "done" ]
check "registry scan completes" test "$STATUS" = "done"

curl -s "localhost:$API_PORT/api/scans/$SCAN_ID" > "$OUT/scan.json"
python3 -c "
import json, sys
report = json.load(open('$OUT/scan.json'))['report']
names = [p['name'] for p in report['packages']]
assert 'ms' in names, 'ms missing: ' + ', '.join(names)
assert 'ansi-styles' in names, 'chalk tree missing'
" >/dev/null 2>&1
check "report includes ms + chalk tree" true

curl -s -X POST "localhost:$API_PORT/api/events/simulate" > "$OUT/sim.json"
contains "attack simulation emits events" "$OUT/sim.json" "simulated"
curl -s "localhost:$API_PORT/api/events?limit=5" > "$OUT/events.json"
contains "events feed lists violations" "$OUT/events.json" "silly-string"

lsof -ti:$API_PORT | xargs kill -9 2>/dev/null || true
rm -rf "$DATA_DIR" "$OUT" "$API_LOG"
fi

echo
echo "e2e result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
