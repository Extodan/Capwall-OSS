# @capwall/cli

`capwall` — scan, lock, enforce, wrap agents, and attest.

```
CORE DEPENDENCY FIREWALL (Mir RWXi + NodeShield)
  capwall scan [dir] [-v]            AST-scan node_modules + dataflow escape report
  capwall init [dir]                 Write capabilities.lock from detected RWXi + import graph
  capwall verify [dir]               Verify lock vs tree drift; exit 1 on drift (CI)
  capwall run [--mode=enforce|audit] -- <cmd>
                                     Run a Node/npm process under the @capwall/runtime-node
                                     V8 hook (audit = observe-only, nothing blocks)
  capwall allow <pkg> <cap…>         Grant capability (bare names resolve versioned keys)
  capwall deny <pkg> <cap…>          Revoke (retains explicit zero-privilege entry → blocks)
  capwall show                       Print current capabilities.lock
  capwall capabilities               List the 11 RWXi capabilities + hardening tiers

AI AGENT, MCP & SKILL.MD SHIELD (@capwall/agent-shield)
  capwall wrap [--agent=claude|cursor|codex|mcp] [--mode=enforce|audit] -- <cmd>
                                     Wrap an AI agent, MCP server (stdio) or lifecycle
                                     script: capability firewall + DIFC taint lattice
                                     (SECRET env reads gate fetch sinks), MCP stdio
                                     interception with pinning + ITP rewriting
  capwall mcp scan <server> -- <cmd> Audit a live tools/list for Implicit Tool Poisoning
                                     (learned TRUSTDESC + symbolic rules), prints the pin
  capwall mcp lock <server> -- <cmd> Pin the tools/list SHA-256 (.capwall/mcp-pins.json)
                                     — remote rug-pull drift is then blocked by the shim
  capwall taint status | clear       Inspect/clear the persisted SPA taint ledger

CRYPTOGRAPHIC RBOM, SBOM & IN-TOTO ATTESTATION
  capwall keys generate              Keystore: root + developer/ci/runtime Ed25519 (0600)
  capwall attest layout | emit-all | verify
                                     in-toto + DSSE supply chain (bit-identical lock chain)
  capwall attest scan-link | build-link | runtime-link | checkout-link
  capwall sbom export [--format=cyclonedx]
                                     DSSE-signed CycloneDX 1.6 with capwall:rwx properties
```

Exit codes: `verify`, `attest verify` and `mcp scan` exit 1 on findings — CI-ready.
Programmatic API: `import { initLock, verifyLock, runWithHook, wrapCommand, mcpScan, mcpLock, taintStatus, attestVerify, exportCycloneDxSbom } from '@capwall/cli'`.
