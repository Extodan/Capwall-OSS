import { createHash } from 'node:crypto'

/**
 * §6 zkSBOM commitment layer (Sorger et al., arXiv:2605.00076).
 * The on-chain/Base seam stores only a Merkle root over the signed RBOM
 * package set; auditors verify per-package membership with an inclusion proof
 * without the enterprise revealing its full dependency graph. (True ZK
 * *exclusion* proofs are the follow-up; the commitment + inclusion proof is
 * the frozen seam, identical in spirit to the AttestationRecord schema.)
 */

const sha256 = (data: string) => createHash('sha256').update(data).digest('hex')
const pair = (a: string, b: string) => sha256(`${a}\n${b}`)

export interface InclusionProof {
  packageRef: string
  siblings: { hash: string; side: 'left' | 'right' }[]
}

export function commitRbom(packages: { name: string; version: string; capabilities: string[] }[]): {
  root: string
  leaves: string[]
} {
  if (packages.length === 0) return { root: sha256('capwall:empty'), leaves: [] }
  const leaves = [...packages]
    .map((p) => `${p.name}@${p.version}:${p.capabilities.join('+')}`)
    .sort()
    .map(sha256)
  return { root: merkleRoot(leaves), leaves }
}

function merkleRoot(leaves: string[]): string {
  if (leaves.length === 0) return sha256('capwall:empty')
  // Pad to a power of two by duplicating the last leaf so every proof path
  // is level-complete — sibling sides then reconstruct exact leaf indices.
  let size = 1
  while (size < leaves.length) size <<= 1
  let level = [...leaves]
  while (level.length < size) level.push(level[level.length - 1]!)
  while (level.length > 1) {
    const next: string[] = []
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? pair(level[i]!, level[i + 1]!) : level[i]!)
    }
    level = next
  }
  return level[0]!
}

/** Build a verifiable inclusion proof for one package of the committed set. */
export function proveInclusion(
  packages: { name: string; version: string; capabilities: string[] }[],
  target: { name: string; version: string },
): InclusionProof {
  const sorted = [...packages]
    .map((p) => ({ ref: `${p.name}@${p.version}:${p.capabilities.join('+')}` }))
    .sort((a, b) => a.ref.localeCompare(b.ref))
  const targetRef = `${target.name}@${target.version}:${packages.find((p) => p.name === target.name && p.version === target.version)?.capabilities.join('+') ?? ''}`
  const index = sorted.findIndex((p) => p.ref === targetRef)
  if (index === -1) throw new Error('package not part of the committed set')

  const siblings: InclusionProof['siblings'] = []
  let size = 1
  while (size < sorted.length) size <<= 1
  let level = sorted.map((p) => sha256(p.ref))
  while (level.length < size) level.push(level[level.length - 1]!)
  let idx = index
  while (level.length > 1) {
    const next: string[] = []
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? pair(level[i]!, level[i + 1]!) : level[i]!)
    }
    const siblingIndex = idx % 2 === 0 ? idx + 1 : idx - 1
    if (siblingIndex < level.length) {
      siblings.push({ hash: level[siblingIndex]!, side: idx % 2 === 0 ? 'right' : 'left' })
    }
    level = next
    idx = Math.floor(idx / 2)
  }
  return { packageRef: targetRef, siblings }
}

/** Verify an inclusion proof against a published root — no full set needed. */
export function verifyInclusion(root: string, proof: InclusionProof): boolean {
  let hash = sha256(proof.packageRef)
  for (const sibling of proof.siblings) {
    hash = sibling.side === 'right' ? pair(hash, sibling.hash) : pair(sibling.hash, hash)
  }
  return hash === root
}

/**
 * zkSBOM gap-closer: verifiable EXCLUSION via a sorted-leaf Merkle tree —
 * prove "package X is NOT in the committed set" by revealing only its two
 * bracketing neighbors (both inclusion-verified, provably adjacent). The
 * auditor learns two packages, never the graph.
 */
export function proveExclusion(
  packages: { name: string; version: string; capabilities: string[] }[],
  target: string,
): { left: InclusionProof; right: InclusionProof; bracket: [string, string] } {
  const refs = packages.map((p) => `${p.name}@${p.version}:${p.capabilities.join('+')}`).sort()
  const upper = refs.find((r) => r > target)
  const lower = [...refs].reverse().find((r) => r < target)
  if (!lower || !upper) throw new Error('target outside committed range — use inclusion check instead')
  const li = proveInclusion(packages, parseRef(packages, lower))
  const ri = proveInclusion(packages, parseRef(packages, upper))
  return { left: li, right: ri, bracket: [lower, upper] }
}

function parseRef(packages: { name: string; version: string; capabilities: string[] }[], ref: string): { name: string; version: string; capabilities: string[] } {
  const head = ref.slice(0, ref.lastIndexOf(':'))
  const [name, version] = head.split('@')
  const found = packages.find((p) => `${p.name}@${p.version}` === head)
  if (found) return found
  return { name: name ?? 'unknown', version: version ?? '0.0.0', capabilities: [] }
}

/** Reconstruct a leaf's index from its proof's sibling sides (position bits). */
function indexFromProof(proof: InclusionProof): number {
  let index = 0
  for (let level = 0; level < proof.siblings.length; level++) {
    const sibling = proof.siblings[level]
    if (sibling?.side === 'left') index |= 1 << level
  }
  return index
}

export function verifyExclusion(
  root: string,
  proof: { left: InclusionProof; right: InclusionProof; bracket: [string, string] },
  target: string,
): boolean {
  // Bracketing non-membership with POSITIONAL adjacency: both neighbors
  // inclusion-verify against the root, they bracket the target, and their
  // tree indices (reconstructed from the proof sides) are consecutive —
  // no committed leaf can sit between consecutive indices.
  if (!verifyInclusion(root, proof.left) || !verifyInclusion(root, proof.right)) return false
  const [lower, upper] = proof.bracket
  if (!(lower < target && target < upper)) return false
  return indexFromProof(proof.left) + 1 === indexFromProof(proof.right)
}
