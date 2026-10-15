<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/svg/capwall-logo-dark.svg">
    <img src="docs/brand/svg/capwall-logo-light.svg" alt="Capwall" width="320">
  </picture>
</p>

<h3 align="center">The open-source engine behind <a href="https://github.com/Extodan/Capwall">Capwall</a> · zero-trust runtime permissions for Node.js, AI agents and MCP servers</h3>

<p align="center">
  <a href="https://www.npmjs.com/package/@extodan/capwall"><img src="https://img.shields.io/npm/v/@extodan/capwall?color=10B981" alt="npm version"></a>
  <img src="https://img.shields.io/badge/Latency-%3C0.05ms-10B981" alt="latency">
  <img src="https://img.shields.io/badge/Spec-Mir_%2B_in--toto-8B5CF6" alt="spec">
  <img src="https://img.shields.io/badge/License-Apache_2.0-blue" alt="license">
</p>

<p align="center"><strong>72.9%</strong> of npm packages need zero system capabilities ·<br>yet <strong>100%</strong> run with full access to your secrets, your shell, and your network.</p>

## 30-Second Quickstart

```bash
# 1. Scan your node_modules & generate a least-privilege capabilities.lock
npx @extodan/capwall init

# 2. Run your app under the V8 capability membrane (blocks unauthorized .env/net/fs/exec)
npx @extodan/capwall run -- node dist/server.js

# 3. Wrap Claude Code / Cursor / MCP servers in the DIFC Reference Monitor
npx @extodan/capwall wrap -- claude
```

## See it stop five attacks

```bash
cd examples/zero-day-hijack-demo && npm run demo:attack
```

```
│ 1  direct secret theft (process.env.STRIPE_SECRET_KEY)   │ BLOCKED │ env.read
│ 2  async-context evasion (setTimeout → fetch exfil)      │ BLOCKED │ http.request
│ 3  GHunter prototype gadget (Object.prototype.shell)     │ BLOCKED │ hardening
│ 4  NodeShield lateral import (child_process)             │ BLOCKED │ import edge
│ 5  MCP-ITP poisoned tools/list (~/.ssh coercion)         │ BLOCKED │ ITP scan
```

## What it is

| module | ground truth |
|---|---|
| `runtime-node` · `node --import` V8 hook | **Mir** RWXi (MIT CSAIL, CCS'21) · **GHunter** gadget isolation (USENIX'24) · **NodeShield** import edges (CCS'25) |
| `scanner` · AST + dataflow analysis | **Defensive Capability Analysis** (ASE'26) · capability-root escape tracking, base64 de-obfuscation, cross-file taint |
| `agent-shield` · DIFC reference monitor | **Runtime Contracts** (arXiv:2608.11274) · **VIGIL/AgentSpec** · **MCP-ITP** · **FIDES** selective information hiding |
| `attestation` · in-toto + DSSE + zkSBOM | **in-toto** (USENIX'19) · Ed25519 signed supply-chain proofs · zero-knowledge set commitments |
| `cli` · `scan · init · verify · run · wrap · mcp · taint · attest · sbom` | 12 capabilities, scoped predicates (`env:["STRIPE_KEY"]`, `hosts:["api.stripe.com"]`), audit→enforce rollout |

## Try it on a repo right now

Point the free scanner at `github.com/Extodan/Capwall-OSS/tree/main/examples/risky-app` · eight popular packages (ssh2, esbuild, cross-spawn…), every stat honestly non-zero. Or try `examples/compromised-app` · pinned real incident versions, and a lesson in what npm already purged.

## Develop

```bash
pnpm install && pnpm build && pnpm test    # 150+ tests
pnpm e2e                                   # live blocking, tamper rejection, registry scan
pnpm sim:demo                              # split-screen: pwned vs blocked, 3 attack patterns
```

## Honest boundaries

A capability **gate**, not a cryptographic sandbox: it stops the standard attack paths at the module boundary (env reads, exfil, prototype gadgets, lateral imports), refuses to promise enforcement when it can't prove it loaded first, and says so loudly.

Apache-2.0 · Node ≥ 20.6 · [github.com/Extodan/Capwall-OSS](https://github.com/Extodan/Capwall-OSS)
