import { z } from 'zod'
import { CAPABILITIES, isCapability, type Capability } from './capabilities.js'

export const LOCKFILE_NAME = 'capabilities.lock'
export const LOCKFILE_SCHEMA_URL =
  'https://raw.githubusercontent.com/capwall/capwall/main/packages/core/schema/capabilities.lock.v1.json'

export const UnrecognizedMode = z.enum(['block', 'warn', 'allow'])
export type UnrecognizedMode = z.infer<typeof UnrecognizedMode>

const PackageEntry = z.object({
  capabilities: z.array(z.string()),
  /**
   * Scoped grants (argument predicates): env: ["NODE_ENV"] → may read only
   * those variables; hosts: ["api.stripe.com"] → may call only those hosts
   * (subdomains included). Absent = unscoped (any var / any host).
   */
  scopes: z
    .object({
      env: z.array(z.string()).optional(),
      hosts: z.array(z.string()).optional(),
    })
    .optional(),
  /** Authorized import set (NodeShield lateral-import graph). */
  deps: z.array(z.string()).optional(),
  /** Override the global failure mode for this package. */
  onViolation: z.enum(['block', 'warn']).optional(),
  /** How this grant was produced. */
  source: z.enum(['scan', 'manual', 'template']).optional(),
  notes: z.string().optional(),
})
export type PackageEntry = z.infer<typeof PackageEntry>

export const LockFile = z.object({
  $schema: z.string().optional(),
  version: z.literal(1),
  defaults: z
    .object({
      /** What happens when a package not listed here violates a capability. */
      unrecognized: UnrecognizedMode.default('warn'),
    })
    .default({ unrecognized: 'warn' }),
  /** Keys are "name@version" (exact) or "name" (any version). */
  packages: z.record(z.string(), PackageEntry),
})
export type LockFile = z.infer<typeof LockFile>

export class LockfileFormatError extends Error {}

export function createLock(packages: LockFile['packages'] = {}): LockFile {
  return {
    $schema: LOCKFILE_SCHEMA_URL,
    version: 1,
    defaults: { unrecognized: 'warn' },
    packages,
  }
}

/** Parse + validate a capabilities.lock document. Throws LockfileFormatError with a readable message. */
export function parseLock(text: string): LockFile {
  let raw: unknown
  try {
    raw = JSON.parse(text)
  } catch (e) {
    throw new LockfileFormatError(`capabilities.lock is not valid JSON: ${(e as Error).message}`)
  }
  const parsed = LockFile.safeParse(raw)
  if (!parsed.success) {
    const issue = parsed.error.issues[0]
    throw new LockfileFormatError(
      `capabilities.lock is invalid at ${issue?.path.join('.') || '(root)'}: ${issue?.message ?? 'unknown error'}`,
    )
  }
  // Validate capability strings (kept loose in the schema so future versions degrade gracefully).
  for (const [key, entry] of Object.entries(parsed.data.packages)) {
    for (const cap of entry.capabilities) {
      if (!isCapability(cap)) {
        throw new LockfileFormatError(`unknown capability "${cap}" on package "${key}"`)
      }
    }
  }
  return parsed.data
}

export function serializeLock(lock: LockFile): string {
  const ordered: LockFile = {
    ...lock,
    packages: Object.fromEntries(
      Object.entries(lock.packages)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([name, entry]) => [
          name,
          { ...entry, capabilities: [...entry.capabilities].sort() } as PackageEntry,
        ]),
    ),
  }
  return `${JSON.stringify(ordered, null, 2)}\n`
}

/** Exact key first ("name@version"), then bare name ("name"). */
export function lookupEntry(lock: LockFile, name: string, version?: string): PackageEntry | undefined {
  if (version && lock.packages[`${name}@${version}`]) return lock.packages[`${name}@${version}`]
  return lock.packages[name]
}

export function grantedCapabilities(lock: LockFile, name: string, version?: string): Capability[] {
  const entry = lookupEntry(lock, name, version)
  return (entry?.capabilities ?? []).filter(isCapability)
}

/** Scoped argument predicates: undefined/absent = unscoped (allow all). */
export function entryScopes(lock: LockFile, name: string, version?: string): { env?: string[]; hosts?: string[] } {
  const entry = lookupEntry(lock, name, version)
  return entry?.scopes ?? {}
}

/** host match: exact or subdomain suffix ("api.stripe.com" allows eu.api.stripe.com) */
export function hostAllowed(host: string, allowed?: string[]): boolean {
  if (!allowed || allowed.length === 0) return true
  return allowed.some((a) => host === a || host.endsWith(`.${a}`))
}

/** env var match (case-sensitive names) */
export function envAllowed(name: string, allowed?: string[]): boolean {
  if (!allowed || allowed.length === 0) return true
  return allowed.includes(name)
}

export function isRecognized(lock: LockFile, name: string, version?: string): boolean {
  return lookupEntry(lock, name, version) !== undefined
}

/** Grant capabilities to a package key. Returns a new lock (immutable-ish style). */
export function allowCapabilities(
  lock: LockFile,
  key: string,
  caps: Capability[],
  options: { source?: PackageEntry['source'] } = {},
): LockFile {
  const existing = lock.packages[key]
  const merged = [...new Set([...(existing?.capabilities ?? []), ...caps])].sort()
  return {
    ...lock,
    packages: {
      ...lock.packages,
      [key]: { ...existing, capabilities: merged, source: options.source ?? existing?.source ?? 'manual' },
    },
  }
}

/** Revoke capabilities. Removing the last capability drops the entry. */
export function denyCapabilities(lock: LockFile, key: string, caps: string[]): LockFile {
  const existing = lock.packages[key]
  if (!existing) return lock
  const remaining = existing.capabilities.filter((c) => !caps.includes(c))
  const packages = { ...lock.packages }
  if (remaining.length === 0) delete packages[key]
  else packages[key] = { ...existing, capabilities: remaining.sort() }
  return { ...lock, packages }
}

/** All capability keys referenced by an entry, for UI listing. */
export function lockKeys(lock: LockFile): string[] {
  return Object.keys(lock.packages).sort()
}
