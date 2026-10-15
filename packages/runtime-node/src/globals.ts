import type { Capability } from '@extodan/capwall-core'
import { attributeStack, currentStack } from './attribute.js'
import { CapabilityDeniedError, checkCapability, type CheckContext } from './check.js'

/**
 * Globals that bypass module imports entirely: `process.env` and `fetch`.
 * Enforcement is attributed by stack trace; only frames inside node_modules
 * are gated — host application code passes through untouched.
 */

export function installEnvGuard(ctx: CheckContext): void {
  const realEnv = process.env
  const guard = (capability: Capability, name: string): void => {
    if (!ctx.policy.active) return
    const pkg = attributeStack(currentStack())
    if (!pkg) return // host code — unrestricted
    const action = checkCapability(ctx, pkg, capability, 'runtime', `process.env.${name}`, currentStack())
    if (action === 'block') throw new CapabilityDeniedError(pkg, capability, `process.env.${name}`)
    // scoped predicate: granted env.read but var outside scopes.env → block
    if (capability === 'env.read' && action === 'allow' && !ctx.policy.envPermitted(pkg, name)) {
      ctx.reporter.violation({
        pkg, capability, kind: 'runtime',
        detail: `process.env.${name} outside scoped grant`,
        stack: currentStack(), blocked: true,
      })
      throw new CapabilityDeniedError(pkg, capability, `process.env.${name} (outside scoped grant; allowed: ${(ctx.policy.scopesFor(pkg).env ?? []).join(', ') || 'unlisted'})`)
    }
  }

  const proxy = new Proxy(realEnv, {
    get(target, prop, receiver) {
      if (typeof prop === 'string' && prop !== 'Symbol(util.inspect.custom)') {
        guard('env.read', prop)
      }
      return Reflect.get(target, prop, receiver)
    },
    set(target, prop, value, receiver) {
      if (typeof prop === 'string') guard('env.write', prop)
      return Reflect.set(target, prop, value, receiver)
    },
    deleteProperty(target, prop) {
      if (typeof prop === 'string') guard('env.write', prop)
      return Reflect.deleteProperty(target, prop)
    },
    has(target, prop) {
      if (typeof prop === 'string') guard('env.read', prop)
      return Reflect.has(target, prop)
    },
  })

  Object.defineProperty(process, 'env', {
    value: proxy,
    configurable: true,
    writable: true,
    enumerable: true,
  })
}

export function installFetchGuard(ctx: CheckContext): void {
  const realFetch = globalThis.fetch
  if (typeof realFetch !== 'function') return

  const capwallFetch = (...args: Parameters<typeof fetch>) => {
    if (ctx.policy.active) {
      const input = args[0]
      const url =
        typeof input === 'string'
          ? input
          : input instanceof URL
            ? input.href
            : (input as Request | undefined)?.url
      const pkg = attributeStack(currentStack())
      if (pkg) {
        let host: string | undefined
        try {
          host = url ? new URL(url).host : undefined
        } catch {
          host = undefined
        }
        const action = checkCapability(
          ctx,
          pkg,
          'http.request',
          'runtime',
          `fetch(${host ? `"${host}"` : '…'})`,
          currentStack(),
        )
        if (action === 'block') {
          throw new CapabilityDeniedError(pkg, 'http.request', `fetch(${host ?? '…'})`)
        }
        if (action === 'allow' && host && !ctx.policy.hostPermitted(pkg, host)) {
          ctx.reporter.violation({
            pkg, capability: 'http.request', kind: 'runtime',
            detail: `fetch(${host}) outside scoped grant`, stack: currentStack(), blocked: true,
          })
          throw new CapabilityDeniedError(pkg, 'http.request', `fetch(${host}) — host outside scoped grant`)
        }
      }
    }
    return realFetch.apply(globalThis, args)
  }

  Object.defineProperty(globalThis, 'fetch', {
    value: capwallFetch,
    configurable: true,
    writable: true,
  })
}
