import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { builtinCapabilities, normalizeSpecifier, type Capability } from '@capwall/core'
import type { PolicyData } from './policy.js'

/**
 * ESM loader-thread hooks (module.register). Intercepts builtin imports for
 * ESM graphs; attribution comes from `context.parentURL` — deterministic,
 * no stack parsing. Self-contained: policy arrives as serializable data.
 */

let data: PolicyData | null = null

interface PkgRefLite {
  name: string
  version: string
  managed: boolean
}

const pkgCache = new Map<string, PkgRefLite | null>()

function packageForPath(filePath: string): PkgRefLite | null {
  if (pkgCache.has(filePath)) return pkgCache.get(filePath) ?? null
  const segments = filePath.split('/')
  let ref: PkgRefLite | null = null
  // Walk up looking for package.json, remembering the first node_modules package root.
  for (let i = segments.length; i > 0; i--) {
    const dir = `${segments.slice(0, i).join('/')}`
    if (dir.endsWith('/node_modules')) continue
    const pkgJson = `${dir}/package.json`
    if (existsSync(pkgJson)) {
      try {
        const manifest = JSON.parse(readFileSync(pkgJson, 'utf8')) as { name?: string; version?: string }
        const nmIndex = segments.lastIndexOf('node_modules')
        const after = nmIndex === -1 ? [] : segments.slice(nmIndex + 1)
        let name = manifest.name ?? 'unknown'
        if (nmIndex !== -1 && !manifest.name) {
          name = after.length >= 2 && after[0]?.startsWith('@') ? `${after[0]}/${after[1]}` : (after.at(-1) ?? 'unknown')
        }
        ref = { name, version: manifest.version ?? '0.0.0', managed: nmIndex !== -1 }
      } catch {
        ref = null
      }
      break
    }
  }
  pkgCache.set(filePath, ref)
  return ref
}

function decide(pkg: PkgRefLite, capability: Capability): 'allow' | 'warn' | 'block' {
  if (!data?.active) return 'allow'
  const keyVersion = `${pkg.name}@${pkg.version}`
  const entry = data.grantsByVersion[keyVersion] ?? data.grantsByName[pkg.name]
  if (!entry) return data.unrecognized
  if (entry.caps.includes(capability)) return 'allow'
  return entry.onViolation ?? 'block'
}

export async function initialize(policyData: PolicyData) {
  data = policyData
}

export async function resolve(
  specifier: string,
  context: { parentURL?: string | undefined; importAttributes?: unknown },
  nextResolve: (
    specifier: string,
    context: { parentURL?: string | undefined; importAttributes?: unknown },
  ) => Promise<{ url: string; shortCircuit?: boolean; format?: string }>,
) {
  const capabilities = builtinCapabilities(normalizeSpecifier(specifier))
  if (capabilities && data?.active && context.parentURL) {
    let filePath: string | undefined
    try {
      filePath = fileURLToPath(context.parentURL)
    } catch {
      filePath = undefined
    }
    const pkg = filePath ? packageForPath(filePath) : null
    if (pkg?.managed) {
      for (const capability of capabilities as Capability[]) {
        const action = decide(pkg, capability)
        if (action !== 'allow') {
          const err = new Error(
            `[capwall] package "${pkg.name}@${pkg.version}" is not allowed to use capability ` +
              `"${capability}" (import '${specifier}' from ${filePath}).\n` +
              `  Fix: run  capwall allow ${pkg.name} ${capability}  and review why it needs this.`,
          )
          ;(err as Error & { code?: string }).code = 'ERR_CAPWALL_CAPABILITY_DENIED'
          throw err
        }
      }
    }
  }
  return nextResolve(specifier, context)
}
