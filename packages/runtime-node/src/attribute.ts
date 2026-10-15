import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, sep } from 'node:path'

export interface PkgRef {
  name: string
  version: string
  dir: string
  /** true when the package lives inside node_modules (i.e. not the host app). */
  managed: boolean
}

const cache = new Map<string, PkgRef | null>()

/** Infer name@version from a package.json's name field, or the directory layout for scoped packages. */
function nameFromDir(pkgDir: string): { name: string; scope?: string } {
  const parts = pkgDir.split(sep)
  const idx = parts.lastIndexOf('node_modules')
  if (idx === -1) return { name: parts[parts.length - 1] ?? 'unknown' }
  const after = parts.slice(idx + 1)
  if (after.length >= 2 && after[0]?.startsWith('@')) return { name: `${after[0]}/${after[1]}`, scope: after[0] }
  return { name: after[after.length - 1] ?? 'unknown' }
}

/**
 * Resolve the nearest package.json above a file path.
 * Managed packages are those resolved under a node_modules directory.
 */
export function packageForFile(filePath: string | undefined | null): PkgRef | null {
  if (!filePath) return null
  const normalized = filePath.startsWith('file:') ? filePath.slice(5) : filePath
  const cacheKey = normalized
  if (cache.has(cacheKey)) return cache.get(cacheKey) ?? null

  let dir = dirname(normalized)
  for (;;) {
    const pkgJsonPath = join(dir, 'package.json')
    if (existsSync(pkgJsonPath)) {
      let manifest: { name?: string; version?: string } = {}
      try {
        manifest = JSON.parse(readFileSync(pkgJsonPath, 'utf8'))
      } catch {
        /* unreadable manifest — fall back to path-derived identity */
      }
      const managed = dir.split(sep).includes('node_modules')
      const derived = nameFromDir(dir)
      const ref: PkgRef = {
        name: manifest.name || derived.name,
        version: manifest.version || '0.0.0',
        dir,
        managed,
      }
      cache.set(cacheKey, ref)
      return ref
    }
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  cache.set(cacheKey, null)
  return null
}

const NODE_MODULES_FRAME = /(?:file:\/\/)?(\/[^\s()]+?\/node_modules\/(?:@[^/]+\/)?[^/]+\/[^\s():]*)/g

/** This runtime's own dist directory — its frames never count as "the caller". */
const RUNTIME_DIR = dirname(new URL(import.meta.url).pathname)

/**
 * Attribute a synchronous action to a managed package by stack trace:
 * the first frame whose path lives inside node_modules — skipping this
 * runtime's own frames, which in production installs are themselves in
 * node_modules — is the caller.
 */
export function attributeStack(stack: string | undefined): PkgRef | null {
  if (!stack) return null
  for (const match of stack.matchAll(NODE_MODULES_FRAME)) {
    const file = match[1]
    if (!file) continue
    if (file.startsWith(RUNTIME_DIR)) continue // our own wrapper frames
    const pkg = packageForFile(file)
    if (pkg?.managed) return pkg
  }
  return null
}

/** What prepareStackTrace looked like when we installed — the trusted baseline. */
const BOOTSTRAP_PREPARE_STACK_TRACE = Object.getOwnPropertyDescriptor(Error, 'prepareStackTrace')

/**
 * Tamper-proof stack capture: a malicious package can replace
 * Error.prepareStackTrace with a formatter that hides its own frames
 * (stack-trace evasion). For the duration of the capture we restore the
 * bootstrap descriptor — err.stack formats lazily, so touching it while the
 * trusted formatter is installed yields the real frames — then we put back
 * whatever userland had installed.
 */
export function currentStack(): string | undefined {
  const err = new Error()
  const userland = Object.getOwnPropertyDescriptor(Error, 'prepareStackTrace')
  try {
    if (BOOTSTRAP_PREPARE_STACK_TRACE) {
      Object.defineProperty(Error, 'prepareStackTrace', BOOTSTRAP_PREPARE_STACK_TRACE)
    } else {
      delete (Error as { prepareStackTrace?: unknown }).prepareStackTrace
    }
    return err.stack // materializes NOW, under the trusted formatter
  } catch {
    // Error was frozen by deep hardening → the trusted (bootstrap) formatter is
    // already permanent and userland can never have replaced it. Plain read.
    return err.stack
  } finally {
    try {
      if (userland) Object.defineProperty(Error, 'prepareStackTrace', userland)
      else delete (Error as { prepareStackTrace?: unknown }).prepareStackTrace
    } catch {
      /* Error frozen by deep hardening — trusted formatter is permanent */
    }
  }
}
