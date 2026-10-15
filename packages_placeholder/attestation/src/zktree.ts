import { createHash } from 'node:crypto'

/**
 * zkSBOM gap-closer: hiding commitments via a SALTED SPARSE MERKLE TREE.
 *
 * Keys are sha256(package ref); leaves are H(ref ‖ salt) so leaf hashes are
 * randomized commitments. The tree has the full 256-level shape with a
 * zero-hash default, so one proof format serves both directions:
 *
 *  - inclusion:  leaf at key = H(ref ‖ salt), root recomputes → member
 *  - exclusion:  leaf at key = ZERO,          root recomputes → NOT a member
 *
 * A proof reveals only sibling HASHES on the queried key's path — no other
 * member, no bracketing neighbors, no tree-size shape. That is the
 * hiding property zkSBOM needs: an auditor verifies "package X was (never)
 * in production" while the enterprise dependency graph stays concealed.
 * (Perfect ZK simulation is not claimed; computational hiding via salt is.)
 */

const sha256 = (data: Buffer | string) => createHash('sha256').update(data).digest()

const ZERO: Buffer[] = [Buffer.alloc(32)]
for (let i = 1; i <= 256; i++) ZERO[i] = Buffer.from(sha256(Buffer.concat([ZERO[i - 1]!, ZERO[i - 1]!])))

const keyOf = (ref: string): Buffer => sha256(ref)
const leafOf = (ref: string, salt: string): Buffer => sha256(`${ref}|${salt}`)

function parentOf(left: Buffer, right: Buffer): Buffer {
  return sha256(Buffer.concat([left, right]))
}

export interface ZkSet {
  root: string
  /** hex key → hex salted leaf hash (prover-side; never shared wholesale). */
  leaves: Map<string, string>
  salt: string
}

function pad64(n: bigint): string {
  return n.toString(16).padStart(64, '0')
}

export interface ZkProof {
  /** The claimed leaf value at the queried key: salted hash, or zero. */
  leafHex: string
  /** Sibling hashes bottom-up (hex); 256 entries for a full-shape tree. */
  siblings: string[]
}

export function zkCommit(
  packages: { name: string; version: string; capabilities: string[] }[],
  salt = createHash('sha256').update(`salt|${Date.now()}|${packages.length}`).digest('hex'),
): ZkSet {
  const leaves = new Map<string, string>()
  for (const p of packages) {
    const ref = `${p.name}@${p.version}:${p.capabilities.join('+')}`
    leaves.set(keyOf(ref).toString('hex'), leafOf(ref, salt).toString('hex'))
  }
  return { root: nodeAt(leaves, 256, 0n).toString('hex'), leaves, salt }
}

/** Canonical SMT node: hash of the subtree covering [prefix, prefix+2^depth). */
function nodeAt(leaves: Map<string, string>, depth: number, prefix: bigint): Buffer {
  if (leaves.size === 0) return ZERO[depth]!
  if (depth === 0) return Buffer.from(leaves.get(pad64(prefix)) ?? '', 'hex').length === 32
    ? (Buffer.from(leaves.get(pad64(prefix))!, 'hex') as Buffer)
    : ZERO[0]!
  const half = 1n << BigInt(depth - 1)
  const left: Map<string, string> = new Map()
  const right: Map<string, string> = new Map()
  for (const [k, v] of leaves) (BigInt(`0x${k}`) < prefix + half ? left : right).set(k, v)
  return parentOf(nodeAt(left, depth - 1, prefix), nodeAt(right, depth - 1, prefix + half))
}

export function zkProve(set: ZkSet, ref: string): ZkProof {
  const keyValue = BigInt(`0x${keyOf(ref).toString('hex')}`)
  const leaf = set.leaves.get(pad64(keyValue)) ?? ZERO[0]!.toString('hex')
  const siblings: string[] = []
  let prefix = 0n
  let levelLeaves = new Map(set.leaves)
  for (let depth = 256; depth > 0; depth--) {
    const half = 1n << BigInt(depth - 1)
    const goLeft = keyValue < prefix + half
    const side = new Map<string, string>()
    const next = new Map<string, string>()
    for (const [k, v] of levelLeaves) {
      const n = BigInt(`0x${k}`)
      const nLeft = n < prefix + half
      if (nLeft === goLeft) next.set(k, v)
      else side.set(k, v)
    }
    siblings.push(nodeAt(side, depth - 1, goLeft ? prefix + half : prefix).toString('hex'))
    levelLeaves = next
    if (!goLeft) prefix += half
  }
  return { leafHex: leaf, siblings }
}

/** Verify membership (leaf is salted member hash) or exclusion (leaf is zero). */
export function zkVerify(setRoot: string, ref: string, proof: ZkProof): { included: boolean; valid: boolean } {
  const key = keyOf(ref)
  let node = Buffer.from(proof.leafHex, 'hex')
  let index = BigInt(`0x${key.toString('hex')}`)
  // proof.siblings[0] is the TOP-level split; fold bottom-up from the end
  for (let level = proof.siblings.length - 1; level >= 0; level--) {
    const sibling = Buffer.from(proof.siblings[level]!, 'hex')
    const goLeft = (index & 1n) === 0n
    node = Buffer.from(goLeft ? parentOf(node, sibling) : parentOf(sibling, node))
    index >>= 1n
  }
  const valid = node.toString('hex') === setRoot
  return { included: valid && proof.leafHex !== ZERO[0]!.toString('hex'), valid }
}
