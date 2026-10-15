/**
 * `capwall wrap` preload (agent side). Loaded via NODE_OPTIONS into the
 * wrapped agent/MCP Node process alongside the capability firewall:
 *  - Two-axis DIFC lattice over secret-named env reads (L_C escalation)
 *  - fetch sink guard: SECRET ⇒ only allowlisted hosts
 *  - trajectory + violation JSONL to .capwall/agent-shield.jsonl
 * Host-app semantics: the agent process itself is the principal.
 */
import { appendFileSync, mkdirSync, readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { sourceTaint, joinTaint, type TaintState } from './taint.js'

const CWD = process.cwd()
const LOG = join(CWD, '.capwall', 'agent-shield.jsonl')
const event = (e: Record<string, unknown>) => {
  try {
    mkdirSync(join(CWD, '.capwall'), { recursive: true })
    appendFileSync(LOG, `${JSON.stringify({ ts: new Date().toISOString(), ...e })}\n`)
  } catch { /* best effort */ }
}

let taint: TaintState = { confidentiality: 'PUBLIC', integrity: 'TRUSTED' }

interface WrapConfig {
  sinkAllowlist: string[]
  block: boolean // wrap --mode: block (enforce) or audit (warn only)
}
const config: WrapConfig = { sinkAllowlist: [], block: true }
try {
  if (existsSync(join(CWD, 'capabilities.lock'))) {
    const lock = JSON.parse(readFileSync(join(CWD, 'capabilities.lock'), 'utf8')) as {
      agents_and_mcp?: { sink_allowlist_domains?: string[] }
    }
    config.sinkAllowlist = lock.agents_and_mcp?.sink_allowlist_domains ?? []
  }
} catch { /* unreadable lock */ }
if (process.env.CAPWALL_WRAP_MODE === 'audit') config.block = false

const realEnv = process.env
process.env = new Proxy(realEnv, {
  get(target, prop, receiver) {
    if (typeof prop === 'string') {
      const escalated = sourceTaint({ kind: 'env', name: prop }).confidentiality
      if (escalated === 'SECRET' && taint.confidentiality !== 'SECRET') {
        taint = joinTaint(taint, { confidentiality: 'SECRET', integrity: 'TRUSTED' })
        event({ kind: 'taint', axis: 'C', detail: `process.env.${prop}`, taint })
        console.error(`[capwall:wrap] ⚠ session is now SECRET (read process.env.${prop}) — external sinks gated`)
      }
    }
    return Reflect.get(target, prop, receiver)
  },
})

const realFetch = globalThis.fetch
if (typeof realFetch === 'function') {
  globalThis.fetch = function capwallWrappedFetch(...args: Parameters<typeof fetch>) {
    const input = args[0]
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request | undefined)?.url
    let host = ''
    try { host = url ? new URL(url).host : '' } catch { host = '' }
    const allowed = host && config.sinkAllowlist.some((d) => host.endsWith(d))
    if (taint.confidentiality === 'SECRET' && !allowed) {
      event({ kind: 'violation', capability: 'http.request', action: config.block ? 'blocked' : 'warned', detail: `fetch(${host}) under SECRET taint` })
      if (config.block) {
        return Promise.reject(new Error(`[capwall:wrap] blocked fetch(${host}) — session holds SECRET taint and host is not allowlisted`))
      }
      console.error(`[capwall:wrap] ⚠ would block fetch(${host}) (audit mode)`)
    }
    return realFetch.apply(globalThis, args)
  }
}

event({ kind: 'wrap-start', pid: process.pid, argv: process.argv.slice(1), mode: config.block ? 'enforce' : 'audit', taint })
