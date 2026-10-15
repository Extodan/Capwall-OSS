import { existsSync, readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, join, parse } from 'node:path'
import {
  grantedCapabilities,
  isRecognized,
  parseLock,
  type Capability,
  type LockFile,
} from '@capwall/core'

export type ViolationAction = 'allow' | 'warn' | 'block'

export interface PolicyDecision {
  action: ViolationAction
  granted: boolean
  recognized: boolean
  /** Lockfile key that matched ("name@version" or "name"). */
  key: string | null
}

/** Compact policy data passed to the loader thread (JSON-serializable). */
export interface PolicyData {
  active: boolean
  lockPath: string | null
  lockDigest: string | null
  unrecognized: 'block' | 'warn' | 'allow'
  /** name@version → caps */
  grantsByVersion: Record<string, { caps: string[]; onViolation?: 'block' | 'warn' }>
  /** name → caps */
  grantsByName: Record<string, { caps: string[]; onViolation?: 'block' | 'warn' }>
}

export class Policy {
  /** Cached pre-proxy: guards must never read process.env at decide time. */
  readonly auditMode: boolean = process.env.CAPWALL_MODE === 'audit'

  constructor(
    public lock: LockFile | null,
    public lockPath: string | null,
    public lockDigest: string | null,
  ) {}

  /** active = a capabilities.lock was found and enforcement is meaningful. */
  get active(): boolean {
    return this.lock !== null
  }

  static load(cwd: string): Policy {
    const override = process.env.CAPWALL_LOCK
    if (override) {
      if (!existsSync(override)) {
        return new Policy(null, null, null)
      }
      return Policy.fromFile(override)
    }
    let dir = cwd
    for (;;) {
      const candidate = join(dir, 'capabilities.lock')
      if (existsSync(candidate)) return Policy.fromFile(candidate)
      const parent = dirname(dir)
      if (parent === dir) break
      dir = parent
    }
    return new Policy(null, null, null)
  }

  private static fromFile(path: string): Policy {
    let lock: LockFile
    try {
      lock = parseLock(readFileSync(path, 'utf8'))
    } catch (err) {
      console.error(`[capwall] ignoring invalid capabilities.lock at ${path}: ${(err as Error).message}`)
      return new Policy(null, path, null)
    }
    const digest = createHash('sha256').update(readFileSync(path)).digest('hex')
    return new Policy(lock, path, digest)
  }

  decide(pkg: { name: string; version?: string }, capability: Capability, internal = false): PolicyDecision {
    if (!this.lock) return { action: 'allow', granted: false, recognized: false, key: null }
    // capwall run --mode=audit: never block, only warn (observe real usage)
    if (!internal && this.auditMode) {
      const d = this.decide(pkg, capability, true)
      return d.action === 'block' ? { ...d, action: 'warn' } : d
    }

    const keyVersion = pkg.version ? `${pkg.name}@${pkg.version}` : null
    const entry = (keyVersion && this.lock.packages[keyVersion]) || this.lock.packages[pkg.name]
    if (!entry) {
      const mode = this.lock.defaults.unrecognized // 'warn' | 'block' | 'allow'
      return { action: mode, granted: false, recognized: false, key: null }
    }
    const granted = entry.capabilities.includes(capability)
    if (granted) return { action: 'allow', granted: true, recognized: true, key: keyVersion ?? pkg.name }
    // Recognized package stepping outside its grant: fail closed (per-entry override supported).
    const action = entry.onViolation ?? 'block'
    return { action, granted: false, recognized: true, key: keyVersion ?? pkg.name }
  }

  grantsFor(pkg: { name: string; version?: string }): string[] {
    if (!this.lock) return []
    return grantedCapabilities(this.lock, pkg.name, pkg.version)
  }

  isRecognized(pkg: { name: string; version?: string }): boolean {
    if (!this.lock) return false
    return isRecognized(this.lock, pkg.name, pkg.version)
  }

  /** Bare OR versioned lock keys (name, name@x.y.z) count as known packages. */
  isKnownPackage(name: string): boolean {
    if (!this.lock) return false
    if (this.lock.packages[name]) return true
    return Object.keys(this.lock.packages).some((k) => k.startsWith(`${name}@`))
  }

  /**
   * §2 NodeShield lateral-import graph: PermitImport(M_caller, S_target) ⟺
   * S_target ∈ I(M_caller). Mode from lock `hardening.importGraph` or
   * CAPWALL_IMPORT_GRAPH ('off' | 'warn' | 'strict'). Only enforced when the
   * caller's lock entry carries its authorized import set (deps).
   */
  permitsImport(caller: { name: string; version?: string }, targetBareName: string): boolean {
    if (!this.lock) return true
    const keyVersion = caller.version ? `${caller.name}@${caller.version}` : null
    const entry = (keyVersion && this.lock.packages[keyVersion]) || this.lock.packages[caller.name]
    if (!entry || entry.deps === undefined) return true // no recorded import set → cannot enforce
    return entry.deps.includes(targetBareName)
  }

  importGraphMode(): 'off' | 'warn' | 'strict' {
    const env = process.env.CAPWALL_IMPORT_GRAPH
    if (env === 'strict' || env === 'warn' || env === 'off') return env
    if (this.lockPath) {
      try {
        const raw = JSON.parse(readFileSync(this.lockPath, 'utf8')) as { hardening?: { importGraph?: string } }
        const mode = raw.hardening?.importGraph
        if (mode === 'strict' || mode === 'warn' || mode === 'off') return mode
      } catch {
        /* unreadable — off */
      }
    }
    return 'off'
  }

  /** Serialize for the loader thread. */
  toData(): PolicyData {
    const grantsByVersion: PolicyData['grantsByVersion'] = {}
    const grantsByName: PolicyData['grantsByName'] = {}
    if (this.lock) {
      for (const [key, entry] of Object.entries(this.lock.packages)) {
        const value = { caps: [...entry.capabilities], onViolation: entry.onViolation }
        if (key.includes('@') && !key.startsWith('@')) grantsByVersion[key] = value
        else grantsByName[key] = value
      }
    }
    return {
      active: this.active,
      lockPath: this.lockPath,
      lockDigest: this.lockDigest,
      unrecognized: this.lock?.defaults.unrecognized ?? 'warn',
      grantsByVersion,
      grantsByName,
    }
  }
}
