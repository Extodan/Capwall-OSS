import { canonicalJson, sha256Hex } from './keys.js'
import type { VerificationResult } from './verify.js'
import { envelopePayloadDigest, type Envelope } from './dsse.js'

/**
 * The seam for the Foundry Attestation Registry contract on Base.
 *
 * Nothing here talks to a chain. The contract (future `foundry/` workspace)
 * only needs to store `attestationRecordHash(record)` — a deterministic
 * SHA-256 over the canonical JSON below — plus the record itself on IPFS.
 * Schema is therefore frozen: fields may be added but never renamed or
 * repurposed, so historical hashes stay verifiable forever.
 */

export interface AttestationRecord {
  /** Frozen schema tag. */
  schema: 'capwall.attestation/v1'
  /** SHA-256 of the layout payload the chain was verified against. */
  layoutDigest: string
  /** The step this record attests (e.g. step_runtime_enforcement). */
  stepName: string
  /** SHA-256 of the step's DSSE payload (the in-toto Statement). */
  statementDigest: string
  /** Signer keyids that produced the verified links. */
  signerKeyids: string[]
  /** Subject artifact digests the record covers (name → sha256). */
  subjectDigests: Record<string, string>
  verifiedAt: string
  result: 'verified' | 'rejected'
  /** Human-readable verification summary. */
  summary: string
}

export function buildAttestationRecord(params: {
  layoutEnvelope: Envelope
  stepName: string
  stepEnvelope: Envelope
  verification: VerificationResult
  subjectDigests?: Record<string, string>
  verifiedAt?: string
}): AttestationRecord {
  const stepOk = params.verification.steps.find((s) => s.name === params.stepName)?.ok ?? false
  const record: AttestationRecord = {
    schema: 'capwall.attestation/v1',
    layoutDigest: envelopePayloadDigest(params.layoutEnvelope),
    stepName: params.stepName,
    statementDigest: envelopePayloadDigest(params.stepEnvelope),
    signerKeyids: params.verification.steps.find((s) => s.name === params.stepName)?.signers ?? [],
    subjectDigests: params.subjectDigests ?? {},
    verifiedAt: params.verifiedAt ?? new Date().toISOString(),
    result: params.verification.ok && stepOk ? 'verified' : 'rejected',
    summary: params.verification.ok
      ? `supply chain verified: ${params.verification.steps.length} steps chained`
      : `verification failed: ${[...params.verification.errors, ...params.verification.steps.flatMap((s) => s.errors)].join('; ').slice(0, 200)}`,
  }
  return record
}

/** Deterministic on-chain identity of a record — what the Base registry stores. */
export function attestationRecordHash(record: AttestationRecord): `0x${string}` {
  return `0x${sha256Hex(canonicalJson(record))}`
}

/** Implementations submit verified records somewhere (chain, IPFS, log). */
export interface AttestationSink {
  submit(record: AttestationRecord, hash: `0x${string}`): Promise<void>
}

export const consoleSink: AttestationSink = {
  async submit(record, hash) {
    console.log(
      `[capwall:attestation] ${record.result} ${record.stepName} ${hash.slice(0, 18)}… (${record.signerKeyids.length} signer(s))`,
    )
  },
}

export const noopSink: AttestationSink = {
  async submit() {},
}
