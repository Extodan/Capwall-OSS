# @capwall/agent-shield

The AI Agent & MCP Runtime Shield — the dual-faced runtime contract harness
(arXiv:2608.11274) plus the VIGIL/AgentSpec two-axis DIFC reference monitor,
built on Capwall's core primitives. Spec: root `AGENT_SHIELD_CONTEXT.md`.

```ts
import { ReferenceMonitor, AgentsAndMcp } from '@capwall/agent-shield'

const policy = AgentsAndMcp.parse(lockJson.agents_and_mcp)
const monitor = new ReferenceMonitor(policy, 'claude-code')

// Preventive face — stateful, trajectory-aware decisions:
monitor.decide({ tool: 'fs.read', args: { path: '.env' }, sources: [{ kind: 'file', path: '.env' }] })
//   → ALLOW, but session taint is now SECRET
monitor.decide({ tool: 'http.post', args: { url: 'https://evil.example' } })
//   → STEP_UP_AUTH (Rule 1: no secret exfiltration)

// Evidential face — proof gate before git commit/push/task-complete:
//   requires harness-captured exit_code==0 receipts NEWER than the last
//   workspace mutation (False Completion prevention), DSSE-signed.
```

- `taint.ts` — L_C (PUBLIC ⊑ INTERNAL ⊑ SECRET) × L_I (TRUSTED ⊑ UNTRUSTED_EXTERNAL),
  secret path/env patterns, untrusted-source list, monotonic join
- `monitor.ts` — `δ_preventive(T_{0..t-1}, a_t, Policy) → ALLOW | DENY | STEP_UP_AUTH`;
  per-MCP-server RWXi grants; Rule 1 (secret → external sinks step up);
  Rule 2 (untrusted integrity downgrades high-privilege actions — confused-deputy prevention)
- `trajectory.ts` — AgentTrajectoryNode hash-chain
  `H_t = SHA256(H_{t-1} ∥ ActorID ∥ SkillManifestHash ∥ ToolName ∥ CanonicalArgsHash ∥ TaintState ∥ Decision ∥ ResultHash)`
  with tamper detection (`verify()`)
- `evidence.ts` — EvidenceLedger (harness-captured receipts, refuses failures), freshness
  vs `lastWriteTs()`, DSSE-signed ledgers via @capwall/attestation
- `sanitizer.ts` — pre-ingestion SKILL.md / MCP `tools/list` scanner: invisible Unicode
  (incl. language-tag plane), imperative overrides, credential references, exfil
  imperatives, fake `<important>` directives, cross-tool chaining, env harvesting
- `policy.ts` — optional `agents_and_mcp:` section of capabilities.lock (core v1 schema untouched)

Not yet built (see AGENT_SHIELD_CONTEXT.md §3+): live MCP stdio/SSE proxy transport,
real agent-host integrations (Cursor/Claude Code hooks), PR-comment surface.
