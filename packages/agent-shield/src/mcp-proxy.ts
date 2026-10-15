import { AgentsAndMcp, type McpServer } from './policy.js'
import { checkSchemaDrift, inspectToolDescription, pinToolsList, type McpToolSpec } from './mcp-pin.js'

/**
 * §4 gap-closer: the LIVE transport — a stdio JSON-RPC proxy that sits between
 * the agent host (Cursor/Claude Code) and an MCP server. Every `tools/list`
 * response is schema-pinned (rug-pull drift → block), poison-detected, and
 * optionally rewritten to TRUSTDESC sterile contracts before the metadata
 * reaches the LLM's context window.
 */

export interface ProxyConfig {
  server: string
  policy: McpServer
  pinnedToolsHash?: string
  trustedRewrite: boolean
  onDecision?: (event: { type: 'drift' | 'poison' | 'pass'; detail: string }) => void
}

export interface ToolsListResult {
  jsonrpc: '2.0'
  id: number | string
  result?: { tools: McpToolSpec[] }
  error?: { code: number; message: string }
}

/** Intercept + transform one tools/list response frame before it reaches the host. */
export function interceptToolsList(frame: ToolsListResult, config: ProxyConfig): ToolsListResult {
  const tools = frame.result?.tools ?? []
  const digest = pinToolsList(tools)
  if (config.pinnedToolsHash) {
    try {
      checkSchemaDrift(config.server, config.pinnedToolsHash, tools)
    } catch (error) {
      config.onDecision?.({ type: 'drift', detail: (error as Error).message })
      return { jsonrpc: '2.0', id: frame.id, error: { code: -32001, message: (error as Error).message } }
    }
  }
  let poisoned = 0
  const safeTools = tools.map((tool) => {
    const verdict = inspectToolDescription(tool)
    if (verdict.poisoned) {
      poisoned++
      config.onDecision?.({ type: 'poison', detail: `${tool.name}: ${verdict.findings.join('; ')}` })
      return config.trustedRewrite ? { ...tool, description: verdict.trustedDescription } : tool
    }
    return tool
  })
  config.onDecision?.({
    type: 'pass',
    detail: `${tools.length} tools forwarded${poisoned ? `, ${poisoned} rewritten (ITP)` : ''} (${digest.slice(0, 8)}…)`,
  })
  return { jsonrpc: '2.0', id: frame.id, result: { tools: safeTools } }
}

/** Extract the pinned digest learned from the first benign tools/list (capwall mcp lock). */
export function learnPin(frame: ToolsListResult): string | undefined {
  const tools = frame.result?.tools
  return tools ? pinToolsList(tools) : undefined
}

/**
 * Wire a real MCP server subprocess behind the proxy: host stdio ⇄ proxy ⇄ server.
 * Frames are newline-delimited JSON-RPC per the MCP stdio transport.
 */
export async function serveMcpProxy(config: Omit<ProxyConfig, 'onDecision'>, serverCommand: string[], host: { stdin: NodeJS.ReadableStream; stdout: NodeJS.WritableStream }): Promise<void> {
  const { spawn } = await import('node:child_process')
  const { createInterface } = await import('node:readline')
  const child = spawn(serverCommand[0]!, serverCommand.slice(1), { stdio: ['pipe', 'pipe', 'inherit'] })
  const toHost = (line: string) => host.stdout.write(`${line}\n`)
  const serverLines = createInterface({ input: child.stdout! })
  serverLines.on('line', (line) => {
    try {
      const frame = JSON.parse(line) as ToolsListResult
      if (frame.result?.tools) {
        toHost(JSON.stringify(interceptToolsList(frame, { ...config, trustedRewrite: config.trustedRewrite })))
        return
      }
    } catch {
      /* not JSON — forward raw */
    }
    toHost(line)
  })
  const hostLines = createInterface({ input: host.stdin })
  hostLines.on('line', (line) => child.stdin!.write(`${line}\n`))
  await new Promise((resolve) => child.on('close', resolve))
}
void AgentsAndMcp
