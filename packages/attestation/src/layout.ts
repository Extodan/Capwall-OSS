import { signEnvelope, type Envelope } from './dsse.js'
import { publicKeyRecord, type KeyPair, type PublicKeyRecord } from './keys.js'
import type { Rule } from './rules.js'

/**
 * in-toto Layout (spec v1.0): the signed root of the supply chain.
 * Defines ordered Steps, authorized functionary keys, and artifact rules.
 */

export const LAYOUT_TYPE = 'https://in-toto.io/Layout/v1'

export interface LayoutStep {
  name: string
  /** Prefix of the command expected to run (informational + audit). */
  expectedCommand?: string[]
  /** keyids of functionaries authorized to sign this step's links. */
  authorizedKeyids: string[]
  artifactRules: Rule[]
}

export interface Layout {
  _type: typeof LAYOUT_TYPE
  /** Functionary public keys by keyid — links must be signed by these. */
  keys: Record<string, PublicKeyRecord>
  steps: LayoutStep[]
  /** ISO timestamp — verification fails after this instant. */
  expires: string
  /** Free-form supply-chain README carried alongside the policy. */
  readme?: string
}

export function createLayout(
  input: {
    steps: LayoutStep[]
    functionaries: KeyPair[]
    expires?: Date | string
    readme?: string
  },
  rootSigner: KeyPair,
): { layout: Layout; envelope: Envelope } {
  const keys: Record<string, PublicKeyRecord> = {}
  const declared = new Set<string>()
  for (const step of input.steps) {
    for (const keyid of step.authorizedKeyids) declared.add(keyid)
  }
  for (const key of input.functionaries) {
    keys[key.keyid] = publicKeyRecord(key.publicHex)
  }
  for (const keyid of declared) {
    if (!keys[keyid]) throw new Error(`step authorizes keyid ${keyid} but no matching functionary key was provided`)
  }

  const expires =
    typeof input.expires === 'string' ? input.expires : (input.expires ?? new Date(Date.now() + 90 * 864e5)).toISOString()
  const layout: Layout = {
    _type: LAYOUT_TYPE,
    keys,
    steps: input.steps,
    expires,
    readme: input.readme,
  }
  return { layout, envelope: signEnvelope(layout, rootSigner) }
}
