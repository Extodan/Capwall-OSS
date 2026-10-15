import picomatch from 'picomatch'
import { joinTaint, sourceTaint, INITIAL_TAINT, EXTERNAL_SINK_TOOLS, HIGH_PRIVILEGE_TOOLS, type TaintState } from './taint.js'
import { TrajectoryChain, type AgentTrajectoryNode, type Decision } from './trajectory.js'
import type { AgentsAndMcp, McpServer } from './policy.js'

/**
 * The Reference Monitor Automaton — dual-faced runtime contract harness
 * (arXiv:2608.11274) with DIFC taint enforcement (VIGIL/AgentSpec).
 *
 * The preventive face is stateful by construction: every decision is a
 * function of the full trajectory T_{0..t-1} (via the taint state it induced
 * and the RWXi grants), never of the action in isolation.
 */

export interface AgentAction {
  tool: string
  args?: unknown
  /** Ingestion sources touched while performing this action (reads, fetches). */
  sources?: Parameters<typeof sourceTaint>[0][]
}

export interface MonitorVerdict {
  decision: Decision
  reason: string
  taint: TaintState
  node: AgentTrajectoryNode
}

export class ReferenceMonitor {
  taint: TaintState = { ...INITIAL_TAINT }
  readonly chain: TrajectoryChain

  constructor(
    public policy: AgentsAndMcp,
    actorId = 'agent',
    skillManifest?: { hash?: string; content?: string },
  ) {
    this.chain = new TrajectoryChain(actorId, skillManifest?.hash)
  }

  /**
   * δ_preventive(T_{0..t-1}, a_t, Policy) → { ALLOW, DENY, STEP_UP_AUTH }
   * Applies MCP-server RWXi grants, then the two taint enforcement rules,
   * then appends the trajectory node (decision included — the log is the law).
   */
  decide(action: AgentAction, result?: unknown): MonitorVerdict {
    const taintBefore = { ...this.taint }
    // 0. Ingestion taint applies first: reads/fetches escalate the lattice.
    for (const source of action.sources ?? []) {
      this.taint = joinTaint(this.taint, sourceTaint(source))
    }

    let decision: Decision = 'ALLOW'
    let reason = 'within policy'

    // 1. MCP server RWXi grants.
    const server = this.serverFor(action.tool)
    if (server) {
      decision = this.checkRwx(server, action)
      if (decision === 'DENY') reason = `mcp rwx: denied for ${action.tool}`
      if (decision === 'ALLOW') {
        // Declared confidentiality level escalates the session lattice.
        this.taint = joinTaint(this.taint, {
          confidentiality: server.taint_policy.confidentiality_level,
          integrity: 'TRUSTED',
        })
      }
    }

    // 2. Rule 1 — No Secret Exfiltration: C == SECRET blocks external sinks.
    if (decision !== 'DENY' && this.taint.confidentiality === 'SECRET' && this.isExternalSink(action)) {
      decision = this.policy.sink_allowlist_domains.some((d) => hostOf(action.args).endsWith(d))
        ? 'ALLOW'
        : 'STEP_UP_AUTH'
      reason = `secret taint: ${action.tool} is an external sink — exfiltration requires human approval`
    }

    // 3. Rule 2 — Confused-Deputy Prevention: I == UNTRUSTED_EXTERNAL downgrades
    //    high-privilege capabilities from ALLOW → STEP_UP_AUTH/DENY.
    if (
      decision !== 'DENY' &&
      this.taint.integrity === 'UNTRUSTED_EXTERNAL' &&
      this.isHighPrivilege(action)
    ) {
      const serverPolicy = server?.taint_policy.block_on_untrusted_integrity
      decision = serverPolicy === false ? 'STEP_UP_AUTH' : 'STEP_UP_AUTH'
      reason = 'untrusted external taint: high-privilege action downgraded (indirect prompt-injection exposure)'
    }

    const node = this.chain.append({
      toolName: action.tool,
      args: action.args,
      taint: this.taint,
      decision,
      result,
    })
    return { decision, reason, taint: this.taint, node }
  }

  private serverFor(tool: string): McpServer | undefined {
    // MCP tool calls are addressed as "<server>.<tool>"; the policy keys servers.
    const serverName = tool.includes('.') ? (tool.split('.')[0] ?? '') : ''
    return serverName ? this.policy.mcp_servers[serverName] : undefined
  }

  private checkRwx(server: McpServer, action: AgentAction): Decision {
    const args = (action.args ?? {}) as Record<string, unknown>
    const path = typeof args.path === 'string' ? args.path : ''
    const url = typeof args.url === 'string' ? args.url : ''

    if (action.tool.endsWith('fs.read') || action.tool.endsWith('read_file')) {
      const allowed = server.rwx.fs_read
      if (allowed === 'none' || (path && !matchAny(allowed, path))) {
        return 'DENY'
      }
    }
    if (action.tool.endsWith('fs.write') || action.tool.endsWith('write_file')) {
      const allowed = server.rwx.fs_write
      if (allowed === 'none' || (path && !matchAny(allowed, path))) {
        return 'DENY'
      }
    }
    if (action.tool.endsWith('exec') || action.tool.endsWith('shell')) {
      if (!server.rwx.shell) return 'DENY'
    }
    if (url) {
      const allowed = server.rwx.network
      const host = hostOf(url)
      if (allowed === 'none') return 'DENY'
      if (allowed !== 'all' && !allowed.some((d) => host.endsWith(d))) return 'DENY'
    }
    if (typeof args.env === 'string' && args.env.startsWith('$')) {
      const allowed = server.rwx.env
      if (allowed === 'none') return 'DENY'
      if (allowed !== 'all' && !allowed.includes(args.env.slice(1))) return 'DENY'
    }
    return 'ALLOW'
  }

  private isExternalSink(action: AgentAction): boolean {
    if (EXTERNAL_SINK_TOOLS.has(action.tool)) return true
    if (this.serverFor(action.tool)) return true // untrusted-server MCP calls are sinks
    return false
  }

  private isHighPrivilege(action: AgentAction): boolean {
    if (HIGH_PRIVILEGE_TOOLS.has(action.tool)) return true
    return /^(fs\.write|shell\.|child_process\.|git\.|ci\.|package\.)/.test(action.tool)
  }
}

function matchAny(patterns: string[], path: string): boolean {
  const normalize = (p: string) => p.replace(/^\.\//, '').replace(/^~\/?/, '')
  const subject = normalize(path)
  return patterns.some((p) => {
    const pattern = normalize(p)
    return picomatch.isMatch(subject, pattern) || picomatch.isMatch(path, p)
  })
}

function hostOf(args: unknown): string {
  const url = (args as { url?: unknown } | undefined)?.url
  if (typeof url === 'string') {
    try {
      return new URL(url).host
    } catch {
      return ''
    }
  }
  return ''
}

function taintOfServer(current: TaintState, server: McpServer): TaintState {
  void current
  return { confidentiality: server.taint_policy.confidentiality_level, integrity: 'TRUSTED' }
}
