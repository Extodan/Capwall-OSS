import { randomUUID } from 'node:crypto'
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Capability, ViolationEvent } from '@extodan/capwall-core'
import type { PkgRef } from './attribute.js'
import type { Policy } from './policy.js'

const ANSI = {
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  dim: '\x1b[2m',
  reset: '\x1b[0m',
}
const colorize = (color: string, text: string) =>
  process.stderr.isTTY && !process.env.NO_COLOR ? `${color}${text}${ANSI.reset}` : text

export interface ReporterOptions {
  cwd: string
  collectorUrl?: string
  collectorToken?: string
  telemetryDir?: string
}

/**
 * Collects violations + exercised-capability telemetry (RBOM input) and
 * fans out to console, .capwall/audit.jsonl, telemetry files and the
 * optional cloud collector.
 */
export class Reporter {
  violations: ViolationEvent[] = []
  exercised = new Map<string, Set<Capability>>()
  loadedPackages = new Set<string>()
  private collectorQueue: ViolationEvent[] = []
  private flushed = false
  /** Captured before the env proxy installs — never read process.env later. */
  private readonly host: string | undefined

  constructor(
    public policy: Policy,
    private options: ReporterOptions,
  ) {
    this.host = typeof process.env.HOSTNAME === 'string' ? process.env.HOSTNAME : undefined
    try {
      mkdirSync(join(options.cwd, '.capwall'), { recursive: true })
    } catch {
      /* read-only cwd — telemetry degraded, enforcement unaffected */
    }
    // Best-effort collector flushing while the process lives; final state goes to disk on exit.
    const timer = setInterval(() => this.flushCollector(), 5000)
    timer.unref?.()
  }

  violation(input: {
    pkg: PkgRef
    capability: Capability
    kind: 'import' | 'runtime'
    detail: string
    stack?: string
    blocked: boolean
  }): void {
    const event: ViolationEvent = {
      id: randomUUID(),
      ts: new Date().toISOString(),
      pkg: input.pkg.name,
      pkgVersion: input.pkg.version,
      capability: input.capability,
      kind: input.kind,
      action: input.blocked ? 'blocked' : 'warned',
      detail: input.detail,
      stack: input.stack?.split('\n').slice(0, 12).join('\n'),
      host: this.host,
      cwd: this.options.cwd,
      node: process.version,
    }
    this.violations.push(event)
    this.collectorQueue.push(event)

    const verb = input.blocked ? 'BLOCKED' : 'WARN'
    const grant = input.pkg.name
    console.error(
      [
        colorize(ANSI.red, `  ⛔ capwall ${verb}`),
        `${input.pkg.name}@${input.pkg.version} → ${input.capability}`,
        colorize(ANSI.dim, `     ${input.detail}`),
        colorize(ANSI.dim, `     grant: capwall allow ${grant} ${input.capability}`),
      ].join('\n'),
    )

    try {
      appendFileSync(
        join(this.options.cwd, '.capwall', 'audit.jsonl'),
        `${JSON.stringify(event)}\n`,
      )
    } catch {
      /* best effort */
    }
  }

  exercise(pkg: PkgRef, capability: Capability): void {
    const key = `${pkg.name}@${pkg.version}`
    let set = this.exercised.get(key)
    if (!set) {
      set = new Set()
      this.exercised.set(key, set)
    }
    set.add(capability)
  }

  trackLoad(pkg: PkgRef | null): void {
    if (pkg) this.loadedPackages.add(`${pkg.name}@${pkg.version}`)
  }

  /** Telemetry snapshot shaped for @extodan/capwall-attestation's RBOM predicate. */
  snapshot(): {
    loadedPackages: string[]
    exercised: Record<string, Capability[]>
    violations: ViolationEvent[]
    lockDigest: string | null
  } {
    return {
      loadedPackages: [...this.loadedPackages].sort(),
      exercised: Object.fromEntries([...this.exercised].map(([k, v]) => [k, [...v].sort()])),
      violations: this.violations,
      lockDigest: this.policy.lockDigest,
    }
  }

  /** Synchronous final flush — wired to process exit. */
  flush(): void {
    if (this.flushed) return
    this.flushed = true
    try {
      const dir = join(this.options.cwd, '.capwall', 'telemetry')
      mkdirSync(dir, { recursive: true })
      const file = join(dir, `run-${process.pid}-${Date.now()}.json`)
      writeFileSync(file, JSON.stringify(this.snapshot(), null, 2))
      const marker = join(this.options.cwd, '.capwall', 'telemetry', 'latest.json')
      writeFileSync(marker, JSON.stringify(this.snapshot()))
    } catch {
      /* best effort */
    }
    // No collector flush here: a fetch inside process exit would itself run
    // through the guarded global with a misleading stack. The 5s interval
    // drains the queue during normal operation.
  }

  private flushCollector(): void {
    const url = this.options.collectorUrl
    if (!url || this.collectorQueue.length === 0) return
    const batch = this.collectorQueue.splice(0, this.collectorQueue.length)
    const headers: Record<string, string> = { 'content-type': 'application/json' }
    if (this.options.collectorToken) headers.authorization = `Bearer ${this.options.collectorToken}`
    fetch(url, { method: 'POST', headers, body: JSON.stringify({ events: batch }) }).catch(() => {
      /* collector down — audit.jsonl remains the source of truth */
    })
  }
}
