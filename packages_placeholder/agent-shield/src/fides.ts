import { createHash, randomUUID } from 'node:crypto'
import { canonicalJson } from '@capwall/attestation'
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { joinTaint, type Confidentiality, type Integrity, type TaintState } from './taint.js'

/**
 * §5 FIDES selective information hiding + SPA persistent taint ledger.
 */

/* ---------- FIDES labeled handles ---------- */

export interface LabeledHandle {
  id: string
  label: TaintState
  handle: string
}

export class HandleVault {
  private store = new Map<string, { value: unknown; label: TaintState }>()

  /** Store a raw SECRET/UNTRUSTED value out of the LLM context; return a handle. */
  sequester(value: unknown, label: TaintState): LabeledHandle {
    const id = randomUUID().slice(0, 8)
    const handle = `$capwall_handle_${id}[C:${label.confidentiality}, I:${label.integrity}]`
    this.store.set(handle, { value, label })
    return { id, label, handle }
  }

  /**
   * Dereference at a sink tool: allowed only when the sink's accepted labels
   * cover the handle's (exact label checks — FIDES).
   */
  dereference(handle: string, sinkAccepts: { confidentiality: Confidentiality[]; integrity: Integrity[] }): unknown {
    const entry = this.store.get(handle)
    if (!entry) throw new Error(`unknown or already-consumed handle: ${handle}`)
    if (!sinkAccepts.confidentiality.includes(entry.label.confidentiality)) {
      throw new Error(`handle label C:${entry.label.confidentiality} exceeds sink confidentiality`)
    }
    if (!sinkAccepts.integrity.includes(entry.label.integrity)) {
      throw new Error(`handle label I:${entry.label.integrity} exceeds sink integrity`)
    }
    this.store.delete(handle) // single-use
    return entry.value
  }
}

/* ---------- SPA persistent disk taint ledger ---------- */

export interface LedgerEntry {
  path: string
  sha256: string
  label: TaintState
  recordedAt: string
}

export class TaintLedger {
  private entries = new Map<string, LedgerEntry>()
  constructor(private ledgerPath: string | null = null) {
    if (ledgerPath && existsSync(ledgerPath)) {
      try {
        for (const entry of JSON.parse(readFileSync(ledgerPath, 'utf8')) as LedgerEntry[]) {
          this.entries.set(entry.path, entry)
        }
      } catch {
        /* corrupt ledger — start clean */
      }
    }
  }

  /** Record (or refresh) a persisted label for a file written under taint. */
  record(path: string, content: string | Buffer, label: TaintState): LedgerEntry {
    const entry: LedgerEntry = {
      path,
      sha256: createHash('sha256').update(content).digest('hex'),
      label,
      recordedAt: new Date().toISOString(),
    }
    this.entries.set(path, entry)
    this.flush()
    return entry
  }

  /** On any later session's file read: does this exact content carry a label? */
  lookup(path: string, content: string | Buffer): TaintState | null {
    const entry = this.entries.get(path)
    if (!entry) return null
    const digest = createHash('sha256').update(content).digest('hex')
    if (digest !== entry.sha256) return null // file changed since — label expires
    return entry.label
  }

  private flush(): void {
    if (!this.ledgerPath) return
    try {
      mkdirSync(join(this.ledgerPath, '..'), { recursive: true })
      writeFileSync(this.ledgerPath, JSON.stringify([...this.entries.values()], null, 2))
    } catch {
      /* best effort */
    }
  }
}

export function openDefaultLedger(cwd: string): TaintLedger {
  return new TaintLedger(join(cwd, '.capwall', 'taint-ledger.json'))
}

/* ---------- §6 compositional monitor gating ---------- */

export interface TerminalVerdict {
  permit: boolean
  reasons: string[]
  preventive: string
  evidential: string
}

/**
 * Permit(T, a_t) ⟺ M_prev(T, a_t) = ALLOW ∧ M_evid(T) = VERIFIED — the
 * formal conjunction on terminal actions (git commit/push, PR create).
 * `lastWriteTs` comes from the trajectory chain; receipts must postdate it.
 */
export function permitTerminal(input: {
  preventiveOk: boolean
  preventiveReason?: string
  evidential: { decision: string; reasons: string[] }
}): TerminalVerdict {
  const reasons: string[] = []
  if (!input.preventiveOk) reasons.push(`preventive monitor: ${input.preventiveReason ?? 'DENY/STEP_UP'}`)
  if (input.evidential.decision !== 'VERIFIED') reasons.push(...input.evidential.reasons.map((r) => `evidential: ${r}`))
  return {
    permit: reasons.length === 0,
    reasons,
    preventive: input.preventiveOk ? 'ALLOW' : (input.preventiveReason ?? 'DENY'),
    evidential: input.evidential.decision,
  }
}

void canonicalJson

/** FIDES gap-closer: automatic label inference across tool-call graphs. */
export function inferOutputLabel(sources: { label: TaintState }[]): TaintState {
  let acc: TaintState = { confidentiality: 'PUBLIC', integrity: 'TRUSTED' }
  for (const s of sources) acc = joinTaint(acc, s.label)
  return acc
}

export function shouldSequester(label: TaintState): boolean {
  return label.confidentiality === 'SECRET' || label.integrity === 'UNTRUSTED_EXTERNAL'
}
