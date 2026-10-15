import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto'

/**
 * Ed25519 functionary keys (in-toto "functionaries" + the root layout owner).
 * keyid follows the in-toto convention: SHA-256 of the canonical key record.
 */

export interface KeyPair {
  keyid: string
  keyType: 'ed25519'
  scheme: 'ed25519'
  /** Raw 32-byte public key, lowercase hex. */
  publicHex: string
  /** PKCS#8 PEM — treat as a secret. */
  privatePem: string
  publicPem: string
  label: string
  createdAt: string
}

export function sha256Hex(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex')
}

/** Canonical JSON: sorted keys, no insignificant whitespace — stable hashing. */
export function canonicalJson(value: unknown): string {
  const sort = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(sort)
    if (v && typeof v === 'object') {
      return Object.fromEntries(
        Object.entries(v as Record<string, unknown>)
          .filter(([, val]) => val !== undefined)
          .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
          .map(([k, val]) => [k, sort(val)]),
      )
    }
    return v
  }
  return JSON.stringify(sort(value))
}

function rawPublicKeyHex(publicKey: KeyObject): string {
  const jwk = publicKey.export({ format: 'jwk' }) as { x?: string }
  if (!jwk.x) throw new Error('key is not an Ed25519 public key')
  return Buffer.from(jwk.x, 'base64url').toString('hex')
}

function publicKeyFromHex(hex: string): KeyObject {
  return createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(hex, 'hex').toString('base64url') },
    format: 'jwk',
  })
}

/** in-toto keyid: sha256 of the canonical key record JSON. */
export function keyidForPublicHex(publicHex: string): string {
  return sha256Hex(
    canonicalJson({
      keytype: 'ed25519',
      keyval: { public: publicHex },
      scheme: 'ed25519',
    }),
  )
}

export function generateKeyPair(label = `key-${randomUUID().slice(0, 8)}`): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const publicHex = rawPublicKeyHex(publicKey)
  return {
    keyid: keyidForPublicHex(publicHex),
    keyType: 'ed25519',
    scheme: 'ed25519',
    publicHex,
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    label,
    createdAt: new Date().toISOString(),
  }
}

export function signEd25519(data: Buffer, privatePem: string): Buffer {
  return cryptoSign(null, data, createPrivateKey(privatePem))
}

export function verifyEd25519(data: Buffer, signature: Buffer, publicHex: string): boolean {
  try {
    return cryptoVerify(null, data, publicKeyFromHex(publicHex), signature)
  } catch {
    return false
  }
}

/** The public key record embedded in a Layout (in-toto `keys` dict). */
export interface PublicKeyRecord {
  keytype: 'ed25519'
  scheme: 'ed25519'
  keyval: { public: string }
}

export function publicKeyRecord(publicHex: string): PublicKeyRecord {
  return { keytype: 'ed25519', scheme: 'ed25519', keyval: { public: publicHex } }
}

/** Strip the private half — safe to embed a KeyPair in links/layouts output. */
export function publicOnly(key: KeyPair): KeyPair {
  return { ...key, privatePem: '' }
}
