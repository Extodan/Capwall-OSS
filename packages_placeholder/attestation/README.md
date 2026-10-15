# @capwall/attestation

in-toto Layout & Link metadata (spec v1.0 / attestation framework) + DSSE signing,
implemented with `node:crypto` Ed25519 — no external dependencies.

- **Layout** (`https://in-toto.io/Layout/v1`) — ordered steps, authorized functionary keyids,
  artifact rules; signed by the org security owner (root key).
- **Links** — in-toto Statement v1 payload (`materials` / `products` SHA-256 maps,
  `byproducts` incl. Capwall SBOM/RBOM predicates, `environment`, `command`) wrapped in a
  **DSSE envelope** (`DSSEv1` pre-authentication encoding, Ed25519 signature, keyid =
  SHA-256 of the canonical public key record). Filename convention `<step>.<keyid8>.link`.
- **Artifact rules** — full v1.0 engine: `ALLOW`, `DISALLOW`, `MATCH [IN] WITH (PRODUCTS|MATERIALS) FROM`,
  `CREATE`, `MODIFY`, `DELETE`, with glob patterns and artifact-queue semantics (leftovers fail).
- **Verifier** (`verifySupplyChain`) — root signature under a trusted key → expiry → per-step
  functionary authorization → rule chaining across steps.
- **`pipeline.ts`** — the Capwall four-step chain (`git_checkout → ast_capability_scan → build →
  runtime_enforcement`) with default rules; the spine guarantees the enforced `capabilities.lock`
  is SHA-256-identical to the scanned one. RWXi mapping: R(env/fs.read) W(fs/env.write) X(child_process/dynamic-code) i(net/http/dns).
- **`registry.ts`** — the **Base seam**: a frozen-schema `AttestationRecord` and its deterministic
  canonical-JSON SHA-256 (`attestationRecordHash` → `0x…`). The Foundry contract on Base only
  needs to store that digest; no chain code yet by design.

```ts
import { generateKeyPair, signEnvelope, verifyEnvelope } from '@capwall/attestation'
const key = generateKeyPair('ci')
const env = signEnvelope(payload, key)
verifyEnvelope(env, { [key.keyid]: key.publicHex }).valid // true
```
