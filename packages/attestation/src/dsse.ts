import { sha256Hex, signEd25519, verifyEd25519, type KeyPair } from './keys.js'

/**
 * DSSE — Dead Simple Signing Envelope (securesignatures.org).
 * Signature is computed over the pre-authentication encoding (PAE), not the
 * raw payload, which binds payloadType + payload together.
 */

export const IN_TOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json'

export interface Signature {
  keyid: string
  /** base64 */
  sig: string
}

export interface Envelope {
  payloadType: string
  /** base64 of the JSON-serialized payload */
  payload: string
  signatures: Signature[]
}

/** DSSEv1 pre-authentication encoding: "DSSEv1 <len(T)> T <len(P)> P" (lengths in bytes). */
export function pae(payloadType: string, payload: Buffer): Buffer {
  const typeBuf = Buffer.from(payloadType, 'utf8')
  return Buffer.concat([
    Buffer.from('DSSEv1 '),
    Buffer.from(String(typeBuf.length)),
    Buffer.from(' '),
    typeBuf,
    Buffer.from(' '),
    Buffer.from(String(payload.length)),
    Buffer.from(' '),
    payload,
  ])
}

/** Serialize payload, sign its PAE, and wrap in a DSSE envelope. */
export function signEnvelope(payload: unknown, signer: KeyPair, payloadType = IN_TOTO_PAYLOAD_TYPE): Envelope {
  const payloadBuf = Buffer.from(JSON.stringify(payload), 'utf8')
  const sig = signEd25519(pae(payloadType, payloadBuf), signer.privatePem)
  return {
    payloadType,
    payload: payloadBuf.toString('base64'),
    signatures: [{ keyid: signer.keyid, sig: sig.toString('base64') }],
  }
}

export interface EnvelopeVerification {
  valid: boolean
  /** Decoded payload (parsed JSON) when the envelope is well-formed. */
  payload?: unknown
  /** keyids whose signature verified successfully. */
  verifiedKeyids: string[]
  error?: string
}

/** Verify a DSSE envelope against a map of trusted public keys (hex) by keyid. */
export function verifyEnvelope(envelope: Envelope, publicKeys: Record<string, string>): EnvelopeVerification {
  if (!envelope || typeof envelope.payload !== 'string' || !Array.isArray(envelope.signatures)) {
    return { valid: false, verifiedKeyids: [], error: 'malformed envelope' }
  }
  let payloadBuf: Buffer
  try {
    payloadBuf = Buffer.from(envelope.payload, 'base64')
  } catch {
    return { valid: false, verifiedKeyids: [], error: 'payload is not valid base64' }
  }

  const verified: string[] = []
  for (const sig of envelope.signatures) {
    const publicHex = publicKeys[sig.keyid]
    if (!publicHex) continue // unknown keyid — not necessarily fatal if another signature verifies
    let sigBuf: Buffer
    try {
      sigBuf = Buffer.from(sig.sig, 'base64')
    } catch {
      continue
    }
    if (verifyEd25519(pae(envelope.payloadType, payloadBuf), sigBuf, publicHex)) {
      verified.push(sig.keyid)
    }
  }
  if (verified.length === 0) {
    return { valid: false, verifiedKeyids: [], error: 'no valid signature from a known key' }
  }

  let payload: unknown
  try {
    payload = JSON.parse(payloadBuf.toString('utf8'))
  } catch {
    return { valid: false, verifiedKeyids: verified, error: 'payload is not valid JSON' }
  }
  return { valid: true, payload, verifiedKeyids: verified }
}

/** Digest of the raw payload bytes — stable statement identity for registry records. */
export function envelopePayloadDigest(envelope: Envelope): string {
  return sha256Hex(Buffer.from(envelope.payload, 'base64'))
}
