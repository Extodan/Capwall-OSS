import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { pinToolsList } from './mcp-pin.js'
import type { McpToolSpec } from './mcp-pin.js'

/**
 * Host-wiring gap-closer: real launch configurations for Cursor and Claude
 * Code. Both hosts get the MCP server wrapped in the capwall shim
 * (`node <dist>/mcp-shim.mjs <name> -- <command…>`), which proxies stdio and
 * enforces pinning + ITP rewriting + drift blocking before metadata reaches
 * the LLM.
 */

export interface McpServerLaunch {
  command: string[]
  /** Pin learned from a first benign tools/list (capwall mcp lock). */
  pinnedTools?: McpToolSpec[]
  trustedRewrite?: boolean
}

export function emitMcpConfigs(cwd: string, servers: Record<string, McpServerLaunch>) {
  const shim = join(__shimDir(), 'mcp-shim.mjs')
  const pins: Record<string, { schema_sha256: string; trustedRewrite: boolean }> = {}
  const mcpServers: Record<string, { command: string; args: string[] }> = {}
  for (const [name, launch] of Object.entries(servers)) {
    mcpServers[name] = { command: 'node', args: [shim, name, '--', ...launch.command] }
    pins[name] = {
      schema_sha256: launch.pinnedTools ? pinToolsList(launch.pinnedTools) : '',
      trustedRewrite: launch.trustedRewrite ?? true,
    }
  }
  const pinsPath = join(cwd, '.capwall', 'mcp-pins.json')
  mkdirSync(join(cwd, '.capwall'), { recursive: true })
  writeFileSync(pinsPath, JSON.stringify(pins, null, 2))
  return {
    pinsPath,
    /** Cursor: ~/.cursor/mcp.json fragment */
    cursor: JSON.stringify({ mcpServers }, null, 2),
    /** Claude Code: project .mcp.json */
    claudeCode: JSON.stringify({ mcpServers }, null, 2),
  }
}

declare const __filename: string | undefined
function __shimDir(): string {
  if (typeof import.meta.url === 'string' && import.meta.url.startsWith('file:')) {
    return dirname(fileURLToPath(import.meta.url))
  }
  return typeof __filename === 'string' ? dirname(__filename) : process.cwd()
}

export function loadPins(cwd: string): Record<string, { schema_sha256: string; trustedRewrite: boolean }> {
  try {
    return JSON.parse(readFileSync(join(cwd, '.capwall', 'mcp-pins.json'), 'utf8'))
  } catch {
    return {}
  }
}
