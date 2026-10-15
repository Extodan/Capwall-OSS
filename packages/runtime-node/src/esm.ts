import { fileURLToPath } from 'node:url'
import { builtinCapabilities, normalizeSpecifier, type Capability } from '@extodan/capwall-core'
import { grantedCapabilities } from '@extodan/capwall-core'
import { packageForFile } from './attribute.js'
import { checkCapability, type CheckContext } from './check.js'

/**
 * ESM import gating via module.registerHooks (in-thread, Node >= 22.15).
 * Attribution from context.parentURL — deterministic, no stack parsing.
 */

export type ResolveHook = (
  specifier: string,
  context: { parentURL?: string | undefined },
  nextResolve: (specifier: string, context: { parentURL?: string | undefined }) => { url: string; format?: string; shortCircuit?: boolean },
) => { url: string; format?: string; shortCircuit?: boolean }

export function makeResolveHook(ctx: CheckContext): ResolveHook {
  return (specifier, context, nextResolve) => {
    const capabilities = builtinCapabilities(normalizeSpecifier(specifier))
    // §3 gap-closer: ESM imports of node:child_process resolve to the
    // gadget-sanitizing namespace shim (CJS already wraps via Module._load).
    const norm = normalizeSpecifier(specifier)
    if (
      (norm === 'child_process' || norm === 'node:child_process') &&
      ctx.policy.active &&
      context.parentURL
    ) {
      let parentPath: string | undefined
      try {
        parentPath = fileURLToPath(context.parentURL)
      } catch {
        parentPath = undefined
      }
      const parentPkg = packageForFile(parentPath)
      const isOurShim = parentPath?.includes('/dist/cp-shim.mjs') ?? false
      if (parentPkg?.managed && !isOurShim) {
        const granted = grantedCapabilities(ctx.policy.lock!, parentPkg.name, parentPkg.version)
        if (granted.includes('child_process')) {
          return { url: new URL('./cp-shim.mjs', import.meta.url).href, shortCircuit: true, format: 'module' }
        }
      }
    }
    if (capabilities && ctx.policy.active && context.parentURL) {
      let filePath: string | undefined
      try {
        filePath = fileURLToPath(context.parentURL)
      } catch {
        filePath = undefined
      }
      const pkg = packageForFile(filePath)
      if (pkg?.managed) {
        for (const capability of capabilities as Capability[]) {
          const action = checkCapability(
            ctx,
            pkg,
            capability,
            'import',
            `import '${specifier}' from ${filePath ?? context.parentURL}`,
          )
          if (action === 'block') {
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
    const resolved = nextResolve(specifier, context)
    // RBOM telemetry: record the package behind whatever just resolved.
    if (resolved.url.startsWith('file:')) {
      try {
        const pkg = packageForFile(fileURLToPath(resolved.url))
        if (pkg?.managed) ctx.reporter.trackLoad(pkg)
      } catch {
        /* non-file URL — ignore */
      }
    }
    return resolved
  }
}
