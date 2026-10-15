import { createHash, randomUUID } from 'node:crypto'
import { signEnvelope, verifyEnvelope, canonicalJson, type Envelope } from '@capwall/attestation'
import type { KeyPair } from '@capwall/attestation'
import type { TrajectoryChain, EvidentialDecision } from './trajectory.js'
import type { EvidentialContract } from './policy.js'

/**
 * The Evidential Face — post-action cryptographic proof gate.
 * An agent may not execute a terminal transition (git commit/push, PR merge,
 * task-complete) until the harness itself captured proof that e.g. tests
 * passed AFTER the last file mutation. "Trust receipts, not claims."
 */

export type EvidenceKind = 'test_pass' | 'lint_pass' | 'build_pass' | 'capability_diff_clean'

export interface EvidenceReceipt {
  id: string
  kind: EvidenceKind
  command: string[]
  exitCode: number
  capturedAt: number
  /** Digest of the workspace files the receipt covers (canonical JSON map). */
  workspaceDigest: string
  harness: string
}

/** The harness (not the agent) records what actually ran and what it returned. */
export class EvidenceLedger {
  private receipts: EvidenceReceipt[] = []

  capture(input: {
    kind: EvidenceKind
    command: string[]
    exitCode: number
    files?: Record<string, string>
    harness?: string
    at?: number
  }): EvidenceReceipt {
    if (input.exitCode !== 0) throw new Error('refusing to receipt a failing run as evidence')
    const receipt: EvidenceReceipt = {
      id: randomUUID(),
      kind: input.kind,
      command: input.command,
      exitCode: input.exitCode,
      capturedAt: input.at ?? Date.now(),
      workspaceDigest: createHash('sha256')
        .update(canonicalJson(input.files ?? {}))
        .digest('hex'),
      harness: input.harness ?? 'capwall-agent-shield',
    }
    this.receipts.push(receipt)
    return receipt
  }

  /** DSSE-sign the ledger — receipts are portable, tamper-evident artifacts. */
  sign(signer: KeyPair): Envelope {
    return signEnvelope({ receipts: this.receipts }, signer)
  }

  receiptsOf(kind: EvidenceKind): EvidenceReceipt[] {
    return this.receipts.filter((r) => r.kind === kind)
  }
}

export interface EvidentialVerdict {
  decision: EvidentialDecision
  reasons: string[]
}

/**
 * δ_evidential(T_{0..t}, RequiredEvidence):
 * VERIFIED only when a harness-captured `exit_code == 0` receipt of every
 * required kind exists, is unexpired, and postdates the trajectory's last
 * permitted file mutation — otherwise REJECT_UNPROVEN.
 */
export function verifyEvidentialContract(
  contract: EvidentialContract,
  ledger: EvidenceLedger,
  chain: TrajectoryChain,
  now = Date.now(),
): EvidentialVerdict {
  const reasons: string[] = []

  if (contract.require_fresh_test_pass) {
    const tests = ledger.receiptsOf('test_pass')
    if (tests.length === 0) {
      reasons.push('no harness-captured test receipt exists')
    } else {
      const latest = tests.reduce((a, b) => (a.capturedAt > b.capturedAt ? a : b))
      if (latest.exitCode !== 0) reasons.push('latest test receipt is a failure')
      const lastWrite = chain.lastWriteTs()
      if (latest.capturedAt <= lastWrite) {
        reasons.push(
          `test receipt is stale: captured at ${latest.capturedAt} but workspace was last mutated at ${lastWrite}`,
        )
      }
      if (now - latest.capturedAt > contract.max_receipt_age_ms) {
        reasons.push('test receipt exceeds max age')
      }
    }
  }

  if (contract.require_clean_capability_diff) {
    const diff = ledger.receiptsOf('capability_diff_clean')
    if (diff.length === 0) {
      reasons.push('no clean capability-diff receipt (run `capwall verify` under the harness)')
    } else {
      const latest = diff.reduce((a, b) => (a.capturedAt > b.capturedAt ? a : b))
      const lastWrite = chain.lastWriteTs()
      if (latest.capturedAt <= lastWrite) {
        reasons.push('capability-diff receipt predates the last workspace mutation')
      }
    }
  }

  return { decision: reasons.length === 0 ? 'VERIFIED' : 'REJECT_UNPROVEN', reasons }
}

/** Verify a signed ledger envelope (control-plane side). */
export function verifySignedLedger(envelope: Envelope, publicHexByKeyid: Record<string, string>):
  | { valid: true; receipts: EvidenceReceipt[] }
  | { valid: false; error: string } {
  const check = verifyEnvelope(envelope, publicHexByKeyid)
  if (!check.valid) return { valid: false, error: check.error ?? 'invalid signature' }
  const payload = check.payload as { receipts?: EvidenceReceipt[] }
  return { valid: true, receipts: payload.receipts ?? [] }
}
