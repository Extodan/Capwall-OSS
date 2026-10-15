import type { Capability } from '@extodan/capwall-core'
import type { PkgRef } from './attribute.js'
import type { Policy } from './policy.js'
import type { Reporter } from './report.js'

export const DENIED_CODE = 'ERR_CAPWALL_CAPABILITY_DENIED'

export class CapabilityDeniedError extends Error {
  code = DENIED_CODE
  constructor(
    public pkg: PkgRef,
    public capability: Capability,
    public detail: string,
  ) {
    super(
      `[capwall] package "${pkg.name}@${pkg.version}" is not allowed to use capability ` +
        `"${capability}" (${detail}).\n` +
        `  Fix: run  capwall allow ${pkg.name} ${capability}  and review why it needs this.`,
    )
    // NB: no `this.name =` — strict-mode assignment to the inherited,
    // potentially-frozen Error.prototype.name throws under deep hardening.
    // `code` (own class field) is the machine-readable identity.
  }
}

export interface CheckContext {
  policy: Policy
  reporter: Reporter
  /** Cached at install time — guards must never read process.env (own proxy!). */
  importGraphMode: 'off' | 'warn' | 'strict'
}

export type CheckResult = 'allow' | 'warn' | 'block'

/**
 * Evaluate one capability use for a managed package. Records telemetry and
 * violations; returns the action. Throws nothing — callers decide (import
 * gates throw immediately, global guards throw at the access site).
 */
export function checkCapability(
  ctx: CheckContext,
  pkg: PkgRef,
  capability: Capability,
  kind: 'import' | 'runtime',
  detail: string,
  stack?: string,
): CheckResult {
  const decision = ctx.policy.decide(pkg, capability)
  if (decision.action === 'allow') {
    if (decision.granted) ctx.reporter.exercise(pkg, capability)
    return 'allow'
  }
  ctx.reporter.violation({ pkg, capability, kind, detail, stack, blocked: decision.action === 'block' })
  return decision.action
}
