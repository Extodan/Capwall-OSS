import Module from 'node:module'
import { builtinCapabilities, normalizeSpecifier, type Capability } from '@capwall/core'
import { packageForFile } from './attribute.js'
import { CapabilityDeniedError, checkCapability, type CheckContext } from './check.js'
import { wrapChildProcess } from './gadgets.js'

/**
 * CJS coverage: `require('node:child_process')` etc. go through
 * Module._load, not the ESM resolve chain. Attribution is deterministic —
 * the requesting module is `parent.filename`. A _resolveFilename wrapper
 * records which packages actually loaded (RBOM telemetry).
 */
export function installCjsGuard(ctx: CheckContext): void {
  const anyModule = Module as unknown as {
    _load: (request: string, parent: { filename?: string } | null, isMain: boolean) => unknown
    _resolveFilename: (request: string, parent: { filename?: string } | null, isMain?: boolean) => string
  }
  if ((anyModule._load as unknown as { __capwall__?: boolean }).__capwall__) return

  // Telemetry: resolved filename → owning package.
  const originalResolve = anyModule._resolveFilename
  const patchedResolve = function (request: string, parent: { filename?: string } | null, isMain?: boolean) {
    const filename = originalResolve.call(anyModule, request, parent, isMain)
    const pkg = packageForFile(filename)
    if (pkg?.managed) ctx.reporter.trackLoad(pkg)
    return filename
  } as typeof originalResolve & { __capwall__?: boolean }
  patchedResolve.__capwall__ = true
  anyModule._resolveFilename = patchedResolve

  // Enforcement: gate builtin requires by requesting package.
  const originalLoad = anyModule._load

  const patched = function (request: string, parent: { filename?: string } | null, isMain: boolean) {
    const specifier = normalizeSpecifier(request)
    const capabilities = builtinCapabilities(specifier)
    const pkg = packageForFile(parent?.filename)
    if (pkg?.managed) ctx.reporter.trackLoad(pkg)
    if (capabilities && pkg?.managed) {
      for (const capability of capabilities as Capability[]) {
        const action = checkCapability(
          ctx,
          pkg,
          capability,
          'import',
          `require('${request}') from ${parent?.filename ?? '(unknown)'}`,
        )
        if (action === 'block') {
          throw new CapabilityDeniedError(pkg, capability, `require('${request}')`)
        }
      }
    }
    // §2 NodeShield lateral-import graph: a managed package may only import
    // the packages recorded in its authorized import set.
    if (pkg?.managed && !request.startsWith('.') && !request.startsWith('/')) {
      const target = request.startsWith('@')
        ? request.split('/').slice(0, 2).join('/')
        : request.split('/')[0]!
      const mode = ctx.importGraphMode
      if (mode !== 'off' && ctx.policy.isKnownPackage(target) && !ctx.policy.permitsImport(pkg, target)) {
        if (mode === 'strict') {
          throw new CapabilityDeniedError(pkg, 'dynamic-code', `lateral import ${pkg.name} -> ${target}`)
        }
        ctx.reporter.violation({
          pkg,
          capability: 'dynamic-code',
          kind: 'import',
          detail: `WARN lateral import ${pkg.name} -> ${target} (outside authorized import set)`,
          stack: undefined,
          blocked: false,
        })
      }
    }
    const loaded = originalLoad.call(anyModule, request, parent, isMain)
    // §3 GHunter: granted child_process gets gadget-sanitized options args.
    if (specifier === 'child_process' || specifier === 'node:child_process') {
      return wrapChildProcess(loaded as Record<string, unknown>)
    }
    return loaded
  } as typeof anyModule._load & { __capwall__?: boolean }

  patched.__capwall__ = true
  anyModule._load = patched
}
