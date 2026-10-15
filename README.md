# Capwall

**The capability firewall for npm dependencies — Android-style runtime permissions for `node_modules`.**

Every `npm install` pulls in packages you've never read. Any of them can read `process.env`, spawn child processes, and open sockets — the exact powers behind every npm supply-chain attack to date. Capwall makes those powers explicit:

```bash
npx @capwall/cli init                    # AST-scan node_modules → capabilities.lock
capwall deny some-package child_process # revoke what you don't trust
capwall run -- node app.js              # enforce: unauthorized use is BLOCKED
```

- **11 capabilities** — `env.read`, `env.write`, `child_process`, `net.connect`, `net.listen`, `http.request`, `dns.resolve`, `fs.read`, `fs.write`, `dynamic-code`, `worker_threads`
- **Fail-closed** — a recognized package stepping outside its grant throws `ERR_CAPWALL_CAPABILITY_DENIED`. Host application code is never restricted.
- **Sound-by-construction scanning** — capability-relevant dataflow (alias tracking, base64 de-obfuscation, cross-file taint) with conservative escapes; obfuscated access is flagged, never missed silently.
- **Bootstrap hardening** — opt-in primordials freezing (SES-style), prototype-pollution gadget sanitization (GHunter), tamper-proof stack attribution, first-loader guarantee.
- **AI agents too** — `capwall wrap` puts coding agents and MCP servers behind a two-axis taint lattice with schema pinning and implicit-tool-poisoning detection.
- **Attested supply chain** — every step emits Ed25519-signed in-toto/DSSE attestations; `capwall attest verify` proves the enforced `capabilities.lock` is bit-identical to the scanned one.

## Packages

| package | what |
|---|---|
| `@capwall/core` | capability model, `capabilities.lock` schema, risk scoring |
| `@capwall/scanner` | AST + dataflow analysis: local trees, registry tarballs, GitHub repos |
| `@capwall/runtime-node` | `node --import` enforcement hook + hardening |
| `@capwall/attestation` | in-toto v1.0 + DSSE, artifact rules, zkSBOM commitments |
| `@capwall/agent-shield` | AI-agent/MCP reference monitor, taint lattice, MCP-ITP defense |
| `@capwall/cli` | `capwall` — scan/init/verify/run/wrap/allow/deny/attest/sbom/mcp/taint |
| `@capwall/exploit-sim-lab` | air-gapped exploit lab + split-screen demo (`pnpm sim:demo`) |

## Develop

```bash
pnpm install
pnpm build && pnpm test        # 159 tests
pnpm e2e                       # runtime blocking + attestation tamper + registry scan
pnpm sim:demo                  # 3 landmark 2026 attack patterns, pwned vs blocked
```

Quick demo: `cd examples/vulnerable-app` (see its README).

Apache-2.0. Node ≥ 20.6 (agent-shield attestation flows ≥ 22.5).
