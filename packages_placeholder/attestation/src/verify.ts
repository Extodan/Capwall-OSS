import { verifyEnvelope, type Envelope } from './dsse.js'
import { isLinkPredicate, type DigestMap, type LinkPredicate } from './statement.js'
import type { Layout } from './layout.js'
import { applyRules } from './rules.js'

/**
 * in-toto verification ("in-toto-verify"):
 *  1. root Layout signature validates under a trusted root key, and hasn't expired
 *  2. every step has a Link validly signed by a functionary authorized *for that step*
 *  3. artifact rules chain continuously (materials of step N+1 match products of step N)
 */

export interface StepVerification {
  name: string
  ok: boolean
  /** keyids that validly signed links for this step. */
  signers: string[]
  errors: string[]
}

export interface VerificationResult {
  ok: boolean
  steps: StepVerification[]
  /** Global errors: root signature, expiry, missing/malformed links. */
  errors: string[]
}

export interface VerifyInput {
  layoutEnvelope: Envelope
  /** Signed link envelopes for the steps. */
  links: Envelope[]
  /** Trusted root public keys (raw hex) — the org security owner's keys. */
  trustedRootKeys: string[]
  now?: Date
}

interface ValidLink {
  stepName: string
  materials: DigestMap
  products: DigestMap
  signers: string[]
}

export function verifySupplyChain(input: VerifyInput): VerificationResult {
  const errors: string[] = []
  const now = input.now ?? new Date()

  // 1. Root layout: signature under a trusted root key.
  const layoutCheck = verifyWithAnyKey(input.layoutEnvelope, input.trustedRootKeys)
  if (!layoutCheck.valid) {
    errors.push(`root layout signature invalid: ${layoutCheck.error ?? 'no trusted root key signature'}`)
    return { ok: false, steps: [], errors }
  }
  const layout = layoutCheck.payload as Layout
  if (layout?._type !== 'https://in-toto.io/Layout/v1' || !Array.isArray(layout.steps)) {
    errors.push('payload is not an in-toto Layout')
    return { ok: false, steps: [], errors }
  }

  // 2. Expiry.
  const expiresAt = new Date(layout.expires)
  if (Number.isNaN(expiresAt.getTime())) errors.push(`layout has invalid expires value: ${layout.expires}`)
  else if (expiresAt.getTime() < now.getTime()) errors.push(`layout expired at ${layout.expires}`)

  // Layout functionary keys by keyid.
  const functionaryKeys: Record<string, string> = {}
  for (const [keyid, record] of Object.entries(layout.keys ?? {})) {
    functionaryKeys[keyid] = record.keyval.public
  }

  // 3. Link signatures + step attribution.
  const linksByStep = new Map<string, ValidLink[]>()
  for (const envelope of input.links) {
    const check = verifyEnvelope(envelope, functionaryKeys)
    if (!check.valid) {
      errors.push(`link rejected: ${check.error ?? 'invalid signature'}`)
      continue
    }
    const predicate = (check.payload as { predicate?: unknown })?.predicate
    if (!isLinkPredicate(predicate)) {
      errors.push('link payload is not an in-toto Link statement')
      continue
    }
    const stepName = predicate.name
    const existing = linksByStep.get(stepName) ?? []
    existing.push({
      stepName,
      materials: predicate.materials ?? {},
      products: predicate.products ?? {},
      signers: check.verifiedKeyids,
    })
    linksByStep.set(stepName, existing)
  }

  const steps: StepVerification[] = []
  const validLinksByStep: Record<string, { materials: DigestMap; products: DigestMap }> = {}
  for (const step of layout.steps) {
    const stepErrors: string[] = []
    const links = linksByStep.get(step.name) ?? []
    if (links.length === 0) {
      stepErrors.push('no valid link for this step')
    }
    const signers: string[] = []
    const materials: DigestMap = {}
    const products: DigestMap = {}
    for (const link of links) {
      for (const keyid of link.signers) {
        signers.push(keyid)
        if (!step.authorizedKeyids.includes(keyid)) {
          stepErrors.push(`functionary ${keyid.slice(0, 8)} is not authorized for step "${step.name}"`)
        }
      }
      Object.assign(materials, link.materials)
      Object.assign(products, link.products)
    }
    validLinksByStep[step.name] = { materials, products }
    steps.push({ name: step.name, ok: stepErrors.length === 0, signers, errors: stepErrors })
  }

  // 4. Artifact rules, chained across steps.
  for (const [i, step] of layout.steps.entries()) {
    const stepResult = steps[i]!
    if (!stepResult.ok) continue // rule results would be noise if the link itself is untrusted
    const { materials, products } = validLinksByStep[step.name]!
    const evaluation = applyRules(step.artifactRules ?? [], materials, products, validLinksByStep)
    if (!evaluation.ok) {
      stepResult.ok = false
      stepResult.errors.push(...evaluation.violations)
    }
  }

  const ok =
    errors.length === 0 && steps.every((s) => s.ok) && layout.steps.every((s) => (linksByStep.get(s.name) ?? []).length > 0)
  return { ok, steps, errors }
}

/** Verify an envelope against a list of raw public keys (any one succeeding is enough). */
function verifyWithAnyKey(envelope: Envelope, publicKeysHex: string[]) {
  for (const hex of publicKeysHex) {
    for (const sig of envelope.signatures ?? []) {
      const check = verifyEnvelope({ ...envelope, signatures: [sig] }, { [sig.keyid]: hex })
      if (check.valid) return check
    }
  }
  return { valid: false as const, verifiedKeyids: [] as string[], error: 'no signature verifies under any trusted root key' }
}

export type { LinkPredicate }
