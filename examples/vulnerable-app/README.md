# vulnerable-app — watch Capwall block three attacks live

A fake "left-pad" dependency that tries to (1) read your environment, (2) spawn
a child process, and (3) exfiltrate over HTTP — all blocked by the Capwall
runtime hook.

## Run the demo

From the repo root (`$CLI` is `packages/cli/dist/cli.mjs`):

```bash
cd examples/vulnerable-app

# 1. See what the scanner finds — evil-left-pad lights up CRITICAL
node ../../packages/cli/dist/cli.mjs scan

# 2. Baseline the lock (grants everything the AST scan detects)
node ../../packages/cli/dist/cli.mjs init

# 3. Revoke what you don't trust — everything, for this demo
node ../../packages/cli/dist/cli.mjs deny evil-left-pad env.read child_process http.request

# 4. Run WITHOUT Capwall — attacks succeed (comment the import to try)
node app.js

# 5. Run UNDER Capwall — every attack is blocked, violations logged
node ../../packages/cli/dist/cli.mjs run -- node app.js
```

Expected output under Capwall:

```
pad("7", 3) → 007
  ⛔ capwall BLOCK evil-left-pad@1.3.37 → env.read
  ⛔ capwall BLOCK evil-left-pad@1.3.37 → child_process
  ⛔ capwall BLOCK evil-left-pad@1.3.37 → http.request
✓ env read blocked: ERR_CAPWALL_CAPABILITY_DENIED
✓ child_process blocked: ERR_CAPWALL_CAPABILITY_DENIED
✓ fetch exfil blocked: ERR_CAPWALL_CAPABILITY_DENIED
```

Afterwards inspect the evidence:

```bash
cat .capwall/audit.jsonl        # every violation, JSONL
cat .capwall/telemetry/latest.json  # RBOM: loaded packages + exercised capabilities + lock digest
```

## Attest the run

```bash
node ../../packages/cli/dist/cli.mjs keys generate
node ../../packages/cli/dist/cli.mjs attest layout
node ../../packages/cli/dist/cli.mjs attest emit-all
node ../../packages/cli/dist/cli.mjs attest verify
# ✔ supply chain verified — capabilities.lock chained end-to-end
#   attestation record: 0x…
```

Tamper with `capabilities.lock` and re-run `attest runtime-link` + `attest verify`
to watch the SHA-256 chain break.
