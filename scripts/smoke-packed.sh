#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; OUT=$(mktemp -d); trap 'rm -rf "$OUT"' EXIT
echo "── pack (workspace deps normalized to 0.1.0 for tarball resolution)"
for p in core scanner runtime-node attestation agent-shield cli; do
  (cd "$ROOT/packages/$p" && python3 -c "
import json; d=json.load(open('package.json'))
d['dependencies']={k:('0.1.0' if v.startswith('workspace:') else v) for k,v in d.get('dependencies',{}).items()}
json.dump(d, open('package.json','w'), indent=2)" && pnpm pack --pack-destination "$OUT" >/dev/null)
  (cd "$ROOT/packages/$p" && python3 -c "
import json; d=json.load(open('package.json'))
d['dependencies']={k:('workspace:*' if k.startswith('@extodan/capwall-') else v) for k,v in d.get('dependencies',{}).items()}
json.dump(d, open('package.json','w'), indent=2)")
done
echo "  tarballs: $(ls "$OUT"/*.tgz | wc -l | tr -d ' ')"
echo "── pristine npm install from tarballs"
PROJ="$OUT/proj"; mkdir -p "$PROJ"; cd "$PROJ"; npm init -y >/dev/null
npm install --no-audit --no-fund "$OUT"/core-*.tgz "$OUT"/scanner-*.tgz "$OUT"/runtime-node-*.tgz "$OUT"/attestation-*.tgz "$OUT"/agent-shield-*.tgz "$OUT"/cli-*.tgz >/dev/null
CW="$PROJ/node_modules/.bin/capwall"
echo "── npx-equivalent CLI from packed tarball"
APP="$OUT/app"; mkdir -p "$APP/node_modules"
cp -R "$ROOT/examples/vulnerable-app/vendor/evil-left-pad" "$APP/node_modules/"
echo '{"name":"t","version":"1.0.0","dependencies":{"evil-left-pad":"file:./node_modules/evil-left-pad"}}' > "$APP/package.json"
cd "$APP"
node "$CW" init >/dev/null 2>&1 && echo "  ✔ init (packed)"
node "$CW" verify >/dev/null && echo "  ✔ verify clean (packed)"
node "$CW" deny evil-left-pad env.read child_process http.request >/dev/null
node "$CW" run -- node "$ROOT/examples/vulnerable-app/app.js" 2>&1 | grep -q "BLOCK" && echo "  ✔ runtime enforcement blocks attacks (packed)" || { echo "  ✖ NOT blocked"; exit 1; }
echo "SMOKE OK"
