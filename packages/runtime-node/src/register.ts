/**
 * Capwall runtime entry — load with:
 *   node --import @capwall/runtime-node app.js
 * or programmatically:
 *   import '@capwall/runtime-node'
 */
import * as nodeModule from 'node:module'
import { fileURLToPath } from 'node:url'
import { installCjsGuard } from './cjs.js'
import { makeResolveHook } from './esm.js'
import { enforceFirstLoader, verifyFirstLoader } from './first.js'
import { installHardening, readHardening } from './hardening.js'
import { installEnvGuard, installFetchGuard } from './globals.js'
import { Policy } from './policy.js'
import { Reporter } from './report.js'

const INSTALLED = Symbol.for('capwall.runtime-node.installed')
const globalThisWithFlag = globalThis as typeof globalThis & { [INSTALLED]?: boolean }

if (globalThisWithFlag[INSTALLED]) {
  // Already installed in this thread (e.g. double --import) — no-op.
} else if (process.env.CAPWALL_DISABLE === '1') {
  console.error('[capwall] disabled via CAPWALL_DISABLE=1')
  globalThisWithFlag[INSTALLED] = true
} else {
  globalThisWithFlag[INSTALLED] = true

  const policy = Policy.load(process.cwd())
  const reporter = new Reporter(policy, {
    cwd: process.cwd(),
    collectorUrl: process.env.CAPWALL_COLLECTOR_URL,
    collectorToken: process.env.CAPWALL_COLLECTOR_TOKEN,
  })

  const ctx = { policy, reporter, importGraphMode: policy.importGraphMode() }
  // First-loader guarantee: if earlier code exists in this process, the
  // enforcement promise is unprovable — warn, or fail closed when strict.
  const strictFirst =
    process.env.CAPWALL_REQUIRE_FIRST === '1' || process.env.CAPWALL_REQUIRE_FIRST === 'strict'
  enforceFirstLoader(verifyFirstLoader([import.meta.url, fileURLToPath(import.meta.url)]), strictFirst)

  installHardening(readHardening(policy.lockPath))
  installCjsGuard(ctx)
  installEnvGuard(ctx)
  installFetchGuard(ctx)

  // ESM gating: prefer in-thread sync hooks (Node >= 22.15); fall back to the
  // loader-thread register() form on older Node versions.
  const registerHooks = (nodeModule as unknown as {
    registerHooks?: (hooks: { resolve: unknown }) => void
  }).registerHooks
  if (typeof registerHooks === 'function') {
    registerHooks({ resolve: makeResolveHook(ctx) })
  } else {
    nodeModule.register('./loader.mjs', {
      parentURL: import.meta.url,
      data: policy.toData(),
    })
  }

  if (!policy.active) {
    console.error(
      '[capwall] no capabilities.lock found — observing only (nothing is blocked).\n' +
        '         Generate one with:  capwall init',
    )
  } else {
    const packages = Object.keys(policy.lock?.packages ?? {}).length
    console.error(`[capwall] enforcing capabilities.lock (${packages} packages) — ${policy.lockPath}`)
  }

  const flush = () => reporter.flush()
  process.on('exit', flush)
  process.on('beforeExit', flush)
}
