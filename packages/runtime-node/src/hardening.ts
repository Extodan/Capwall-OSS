import { readFileSync } from 'node:fs'

/**
 * Bootstrap hardening (spec: "primordials frozen via --import before userland
 * code loaded"). Scoped to what a preload hook can guarantee without breaking
 * the ecosystem:
 *
 *  - freezePrototypes: Object.freeze(Object.prototype) — the prototype-
 *    pollution class dies here (assignments silently fail; strict mode throws).
 *  - prepareStackTrace is not frozen globally (source-map-support etc. rely on
 *    replacing it); instead the attribution module snapshots + restores it, so
 *    OUR stack parsing can never be fed a lie.
 *
 * Flags live in capabilities.lock:
 *   { "version": 1, "hardening": { "freezePrototypes": true }, ... }
 * Env override: CAPWALL_FREEZE_PROTOTYPES=1 (or =0 to disable).
 */

export interface HardeningFlags {
  freezePrototypes: boolean
  /** SES-style: freeze constructors + prototypes of the full intrinsic set. */
  freezePrimordials: boolean
}

/** Intrinsics frozen by the deep tier. globalThis is deliberately NOT frozen
 *  (Node and userland legitimately add globals); error types inherit via eval
 *  loop below. Frozen = properties/prototypes become read-only before userland. */
const INTRINSICS: unknown[] = [
  Object, Function, Array, String, Number, Boolean, Symbol, BigInt, Math, JSON,
  Date, RegExp, Error, Promise, Map, Set, WeakMap, WeakSet, Reflect,
  ArrayBuffer, DataView,
]

function intrinsicNames(): string[] {
  return [
    'EvalError', 'RangeError', 'ReferenceError', 'SyntaxError', 'TypeError', 'URIError',
    'AggregateError', 'FinalizationRegistry', 'WeakRef',
    'Int8Array', 'Uint8Array', 'Uint8ClampedArray', 'Int16Array', 'Uint16Array',
    'Int32Array', 'Uint32Array', 'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array',
  ]
}

function freezeIntrinsic(value: unknown): void {
  try {
    if (typeof value === 'function') {
      Object.freeze(value)
      if (value.prototype) Object.freeze(value.prototype)
    } else if (value && typeof value === 'object') {
      Object.freeze(value)
    }
  } catch {
    /* already frozen or non-standard — skip */
  }
}

export function readHardening(lockPath: string | null): HardeningFlags {
  const flags: HardeningFlags = { freezePrototypes: false, freezePrimordials: false }
  const env = process.env.CAPWALL_FREEZE_PRIMORDIALS ?? process.env.CAPWALL_FREEZE_PROTOTYPES
  if (env === '1' || env === 'true') {
    const deep = process.env.CAPWALL_FREEZE_PRIMORDIALS !== undefined
    return { freezePrototypes: true, freezePrimordials: deep }
  }
  if (env === '0' || env === 'false') return flags
  if (lockPath) {
    try {
      const raw = JSON.parse(readFileSync(lockPath, 'utf8')) as {
        hardening?: { freezePrototypes?: boolean; freezePrimordials?: boolean }
      }
      if (raw.hardening?.freezePrimordials === true) {
        flags.freezePrototypes = true
        flags.freezePrimordials = true
      } else if (raw.hardening?.freezePrototypes === true) {
        flags.freezePrototypes = true
      }
    } catch {
      /* unreadable lock — hardening stays off */
    }
  }
  return flags
}

export function installHardening(flags: HardeningFlags): void {
  if (!flags.freezePrototypes && !flags.freezePrimordials) return
  try {
    Object.freeze(Object.prototype)
  } catch {
    /* ignore */
  }
  if (!flags.freezePrimordials) return
  for (const intrinsic of INTRINSICS) freezeIntrinsic(intrinsic)
  const globalScope = globalThis as Record<string, unknown>
  for (const name of intrinsicNames()) {
    if (globalScope[name] !== undefined) freezeIntrinsic(globalScope[name])
  }
}
