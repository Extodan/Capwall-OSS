<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/svg/capwall-logo-dark.svg">
    <img src="docs/brand/svg/capwall-logo-light.svg" alt="Capwall" width="360">
  </picture>
</p>

# Capwall OSS

The open-source engine behind [Capwall](https://github.com/Extodan/Capwall) —
per-package runtime permissions for `node_modules`, AI agents, and MCP servers.

> Your app imports 1,000+ packages you've never read. Capwall makes each one
> ask permission: **11 capabilities** (`env.read`, `child_process`, `http.request`,
> `net.*`, `fs.*`, `dynamic-code`, …) scanned statically, locked in a reviewed
> `capabilities.lock`, and enforced fail-closed inside V8 before userland runs.

```bash
npx @extodan/capwall init                 # scan node_modules → least-privilege capabilities.lock
npx @extodan/capwall run -- node dist/server.js   # enforce: unauthorized .env/net/fs/exec is blocked
npx @extodan/capwall wrap -- claude        # AI agents + MCP under the DIFC reference monitor
```

## This repository

| package | role |
|---|---|
| `@extodan/capwall-core` | capability model, `capabilities.lock` schema (zod + JSON-schema), risk scoring |
| `@extodan/capwall-scanner` | acorn AST + capability dataflow: local trees, registry tarballs, GitHub manifests — nothing executes |
| `@extodan/capwall-runtime-node` | `--import` enforcement: ESM resolve gating, CJS `Module._load` patch, env/fetch membranes, GHunter gadget sanitizer, primordials freezing, first-loader guarantee |
| `@extodan/capwall-attestation` | in-toto v1.0 Layout/Link + DSSE Ed25519, artifact rules, supply-chain verifier, zkSBOM commitments |
| `@extodan/capwall-agent-shield` | two-axis DIFC taint lattice, MCP schema pinning, implicit-tool-poisoning detector, evidential contracts |
| `@extodan/capwall` | `scan · init · verify · run · wrap · mcp · taint · attest · sbom` |
| `@extodan/capwall-exploit-sim-lab` | air-gapped lab reproducing three 2026 attack patterns; split-screen pwned-vs-blocked table (`pnpm sim:demo`) |

## Try it in 60 seconds

```bash
pnpm install && pnpm build && pnpm test   # 160+ tests
pnpm e2e                                  # live blocking, tamper rejection, registry scan
pnpm sim:demo                             # the launch-video demo table
```

Scan targets you can point any Capwall scanner at:

- `github.com/Extodan/Capwall-OSS/tree/main/examples/risky-app` — every stat non-zero (legit packages: ssh2, esbuild, cross-spawn…)
- `github.com/Extodan/Capwall-OSS/tree/main/examples/compromised-app` — pinned real incident versions (and an honest lesson in what npm already purged)

## Honest boundaries

The runtime is a capability **gate**, not a cryptographic sandbox: it stops the
standard attack paths (builtin imports, env reads, fetch exfil, prototype
gadgets) at the module boundary and refuses to promise enforcement when it
can't prove it loaded first. Full details in each package's README.

## Contributing

Small PRs welcome — CI runs `build → test → e2e → attest-verify → packed-tarball smoke`.
Everything ships with tests; a fix without a failing test will be asked for one.

Apache-2.0 (see `LICENSE`). Node ≥ 20.6.
