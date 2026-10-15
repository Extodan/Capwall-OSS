# Capwall usage guide — from zero to enforced

Every workflow below uses the published CLI. No clone needed.

```bash
npm i -D @extodan/capwall     # once — then `npx capwall …` works everywhere
# or skip install entirely: npx @extodan/capwall <command>
```

---

## The mental model (30 seconds)

```
your code  ──imports──▶  their packages  ──▶  your secrets / shell / network
                                │
                        capabilities.lock  ← one JSON file decides what passes
```

1. **`init`** scans every package in `node_modules` (nothing runs) and writes `capabilities.lock` — one grant per package, exactly what its code actually uses.
2. **You review the lock** in a PR. Deny what looks wrong. Scope what looks too broad.
3. **`run`** starts your app under a V8 hook. Any package that touches a capability it wasn't granted → `ERR_CAPWALL_CAPABILITY_DENIED` — the process stops before a byte leaves.

Your own code is never restricted. Only `node_modules` is gated.

---

## Workflow 1: Protect an existing app

```bash
cd your-app

# 1. Scan — see what each package actually does
npx capwall scan
```

```
  CRITICAL  95 [██████████] next@16.4.1
           child_process dynamic-code env.read fs.read fs.write http.request …
  HIGH      65 [███████···] typescript@5.9.3
           child_process env.read fs.read fs.write net.connect …
  MEDIUM    20 [██········] react@19.3.0
           env.read
  LOW        0 [··········] clsx@2.1.1
           no sensitive capabilities
```

> **Reading the output:** every package gets a score 0–100. CRITICAL doesn't mean malicious — `next` legitimately needs 10 capabilities to be a web server. The point is you can now *see* it, and revoke it if it stops being legit.

```bash
# 2. Write the lock (this is the baseline — grants = what the scan found)
npx capwall init
```

```json
// capabilities.lock — plain JSON, review it in a PR
{
  "version": 1,
  "defaults": { "unrecognized": "warn" },
  "packages": {
    "next@16.4.1":   { "capabilities": ["child_process","env.read","fs.read", …] },
    "react@19.3.0":  { "capabilities": ["env.read"] },
    "clsx@2.1.1":    { "capabilities": [] }
  }
}
```

```bash
# 3. Run under enforcement — for a Node.js app:
npx capwall run -- node app.js

#    for a Next.js / npm-script app:
npx capwall run -- npm run dev

#    for any framework (the CLI injects the hook via NODE_OPTIONS):
npx capwall run -- npx next start
```

```
[capwall] enforcing capabilities.lock (19 packages)
▲ Next.js 15 ready in 412ms     ← your app runs normally
```

Now try `npm install some-suspicious-package` and import it — if it reads `.env` or spawns a shell:

```
  ⛔ capwall BLOCKED
  evil-package@1.0.0 → env.read
     process.env.STRIPE_SECRET_KEY
     grant: capwall allow evil-package env.read
✓ blocked: ERR_CAPWALL_CAPABILITY_DENIED
```

---

## Workflow 2: Safe rollout (audit → enforce)

Don't enforce on day one. Watch first:

```bash
# Audit mode: logs everything, blocks nothing — run in staging or even prod
npx capwall run --mode=audit -- npm start
```

Every capability use lands in `.capwall/audit.jsonl`:

```json
{"pkg":"next","capability":"env.read","action":"warned","detail":"process.env.NODE_ENV"}
{"pkg":"next","capability":"http.request","action":"warned","detail":"import 'node:http'"}
```

After a few days, check the diff — what did packages use that the lock doesn't grant?

```bash
npx capwall verify     # exit 0 = no drift, exit 1 = something changed
```

When you're satisfied, flip to enforce (just drop `--mode=audit`).

---

## Workflow 3: Scoped grants (least privilege per argument)

A blanket `env.read` is too broad for a Stripe SDK — it only needs one variable. Scope it:

```json
"stripe@12.0.0": {
  "capabilities": ["env.read", "http.request"],
  "scopes": {
    "env":   ["STRIPE_SECRET_KEY"],
    "hosts": ["api.stripe.com"]
  }
}
```

Now `process.env.STRIPE_SECRET_KEY` passes, `process.env.DATABASE_URL` is blocked, `fetch("https://api.stripe.com")` passes, `fetch("https://evil.example")` is blocked — all with the same `ERR_CAPWALL_CAPABILITY_DENIED`.

Edit grants from the CLI:

```bash
npx capwall allow stripe env.read http.request
npx capwall deny next child_process        # revoke (keeps a zero-trust entry → blocks)
npx capwall show                           # print current grants
```

---

## Workflow 4: CI — gate every PR

```yaml
# .github/workflows/capwall.yml
- run: npm ci
- run: npx capwall init
- run: npx capwall verify     # exit 1 if the lock doesn't match the tree
```

A new dependency bumps in, the scan finds it uses `child_process` → `verify` fails → the PR shows the drift. A maintainer reviews, adds the grant (or rejects the dep), merge proceeds.

---

## Workflow 5: Wrap an AI coding agent (Claude Code, Cursor, MCP)

```bash
# Wrap Claude Code in the DIFC reference monitor
npx capwall wrap -- claude

# Wrap any MCP server (stdio JSON-RPC proxy with schema pinning)
npx capwall wrap --agent=mcp -- node ./mcp-server.js

# Audit an MCP server's tools/list for implicit tool poisoning
npx capwall mcp scan ./mcp.json
npx capwall mcp scan evil-mcp -- node server.js

# Pin the schema digest (blocks rug-pull mutations)
npx capwall mcp lock evil-mcp -- node server.js

# Claude Code PreToolUse hook (blocks secret reads + pipe-to-shell)
npx capwall agent install claude

# See what's tainted across agent sessions
npx capwall taint status
```

---

## Workflow 6: Attest your supply chain (in-toto + DSSE)

Proves the `capabilities.lock` running in production is bit-identical (SHA-256) to what the scanner produced in CI.

```bash
npx capwall keys generate           # local keystore: root + dev/ci/runtime Ed25519 keys
npx capwall init                    # produce the lock
npx capwall attest layout           # create + sign root.layout
npx capwall attest emit-all         # emit 4 signed links (checkout → scan → build → runtime)
npx capwall attest verify           # verify signatures + artifact chaining
```

```
  ✔ step_git_checkout
  ✔ step_ast_capability_scan
  ✔ step_build_package
  ✔ step_runtime_enforcement

  ✔ supply chain verified — capabilities.lock chained end-to-end
  attestation record: 0xccccdcee79a031864f…
```

```bash
npx capwall sbom export --format=cyclonedx    # DSSE-signed CycloneDX SBOM
```

---

## Workflow 7: See attacks blocked live

```bash
git clone https://github.com/Extodan/Capwall-OSS
cd Capwall-OSS/examples/zero-day-hijack-demo
npm run demo:attack
```

```
│ 1  direct secret theft (process.env.STRIPE_SECRET_KEY)   │ BLOCKED │ env.read
│ 2  async-context evasion (setTimeout → fetch exfil)      │ BLOCKED │ http.request
│ 3  GHunter prototype gadget (Object.prototype.shell)     │ BLOCKED │ hardening
│ 4  NodeShield lateral import (child_process)             │ BLOCKED │ import edge
│ 5  MCP-ITP poisoned tools/list (~/.ssh coercion)         │ BLOCKED │ ITP scan
```

---

## Command cheat sheet

```
scan [dir] [-v]                        capability + risk report (no writes)
init [dir]                             write capabilities.lock
verify [dir]                           lock vs tree drift (exit 1 = CI fail)
run [--mode=enforce|audit] -- <cmd>    enforce / observe
allow|deny <pkg> <cap…>                edit grants
show                                   print the lock
capabilities                           list the 12 capabilities + hardening tiers

wrap [--agent=claude|cursor|codex|mcp] -- <cmd>   agent/MCP DIFC shield
mcp scan|lock <name> [-- <cmd>|file.json]         ITP audit + schema pin
taint status|clear                                 cross-session taint ledger
agent install claude                               PreToolUse hook

keys generate                         Ed25519 keystore
attest layout|emit-all|verify         in-toto + DSSE supply chain
sbom export --format=cyclonedx        signed CycloneDX SBOM
```

## Troubleshooting

| problem | fix |
|---|---|
| `command not found: capwall` | `npm i -D @extodan/capwall` first, or use `npx @extodan/capwall <cmd>` |
| `Cannot find module app.js` | point `run --` at your actual entry: `node dist/server.js`, `npm run dev`, `npx next start` |
| `no keystore found` | `npx capwall keys generate` (needed for `attest` + `sbom` only) |
| `unknown option '--layout'` | subcommands are positional: `npx capwall attest layout` (no `--`) |
| `wrap` exits silently | for non-MCP agents it injects via `NODE_OPTIONS` — the wrapped tool must be a Node process or npm script |
| everything WARNs, nothing blocks | the lock has `defaults.unrecognized: "warn"` — set `"block"` or `npx capwall deny <pkg> <cap>` |
| audit.jsonl is growing | it's append-only telemetry — safe to delete or `.gitignore` `.capwall/` |
