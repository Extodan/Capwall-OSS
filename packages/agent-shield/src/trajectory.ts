import { createHash, randomUUID } from 'node:crypto'
import { canonicalJson } from '@extodan/capwall-attestation'
import type { TaintState } from './taint.js'

/**
 * Formal AgentTrajectoryNode hash-chain (arXiv:2608.11274 §3):
 *   H_t = SHA256(H_{t-1} ∥ ActorID ∥ SkillManifestHash ∥ ToolName ∥
 *                 CanonicalArgsHash ∥ TaintState_t ∥ Decision ∥ ResultHash)
 * Tamper-evident session log; any mutation of a historical node breaks the chain.
 */

export type Decision = 'ALLOW' | 'DENY' | 'STEP_UP_AUTH'
export type EvidentialDecision = 'VERIFIED' | 'REJECT_UNPROVEN'

export interface AgentTrajectoryNode {
  t: number
  id: string
  actorId: string
  skillManifestHash: string
  toolName: string
  args: unknown
  canonicalArgsHash: string
  taint: TaintState
  decision: Decision | EvidentialDecision
  resultHash: string | null
  /** Wall-clock ms — freshness anchor for the evidential face. */
  ts: number
  parentHash: string | null
  hash: string
}

const sha256 = (data: string) => createHash('sha256').update(data).digest('hex')

export function canonicalArgsHash(args: unknown): string {
  return sha256(canonicalJson(args ?? null))
}

export function resultHashOf(result: unknown): string {
  return sha256(canonicalJson(result ?? null))
}

export function computeNodeHash(node: Omit<AgentTrajectoryNode, 'hash'>): string {
  return sha256(
    [
      node.parentHash ?? '',
      node.actorId,
      node.skillManifestHash,
      node.toolName,
      node.canonicalArgsHash,
      `${node.taint.confidentiality}:${node.taint.integrity}`,
      node.decision,
      node.resultHash ?? '',
    ].join('\u0000'),
  )
}

export class TrajectoryChain {
  private nodes: AgentTrajectoryNode[] = []
  private head: string | null = null

  constructor(
    public readonly actorId: string,
    public readonly skillManifestHash = sha256('no-skill-manifest'),
  ) {}

  append(input: {
    toolName: string
    args?: unknown
    taint: TaintState
    decision: Decision | EvidentialDecision
    result?: unknown
    ts?: number
  }): AgentTrajectoryNode {
    const base: Omit<AgentTrajectoryNode, 'hash'> = {
      t: this.nodes.length,
      id: randomUUID(),
      actorId: this.actorId,
      skillManifestHash: this.skillManifestHash,
      toolName: input.toolName,
      args: input.args ?? null,
      canonicalArgsHash: canonicalArgsHash(input.args),
      taint: input.taint,
      decision: input.decision,
      resultHash: input.result === undefined ? null : resultHashOf(input.result),
      ts: input.ts ?? Date.now(),
      parentHash: this.head,
    }
    const node: AgentTrajectoryNode = { ...base, hash: computeNodeHash(base) }
    this.nodes.push(node)
    this.head = node.hash
    return node
  }

  /** Full session trajectory for the preventive face's δ(T_{0..t-1}, a_t). */
  trajectory(): readonly AgentTrajectoryNode[] {
    return this.nodes
  }

  headHash(): string | null {
    return this.head
  }

  /** Timestamp of the most recent mutation of workspace state (fs.write / shell / git tools). */
  lastWriteTs(): number {
    let latest = 0
    for (const node of this.nodes) {
      const mutates = /^(fs\.write|shell\.|child_process\.|git\.(commit|push)|package\.)/.test(node.toolName)
      if (mutates && node.decision === 'ALLOW' && node.ts > latest) latest = node.ts
    }
    return latest
  }

  /** Recompute the chain; returns the first tampered index, or null when intact. */
  verify(): number | null {
    let parent: string | null = null
    for (let i = 0; i < this.nodes.length; i++) {
      const node = this.nodes[i]!
      const { hash: _recorded, ...fields } = node
      if (node.parentHash !== parent) return i
      if (_recorded !== computeNodeHash(fields)) return i
      parent = _recorded
    }
    return null
  }

  toJSON(): AgentTrajectoryNode[] {
    return this.nodes
  }

  static fromJSON(nodes: AgentTrajectoryNode[], actorId: string): TrajectoryChain {
    const chain = new TrajectoryChain(actorId)
    for (const node of nodes) {
      chain.nodes.push(node)
      chain.head = node.hash
    }
    return chain
  }
}
