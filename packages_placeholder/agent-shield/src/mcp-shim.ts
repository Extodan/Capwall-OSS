// stdio MCP proxy shim — argv: mcp-shim.mjs <serverName> -- <command…>
// Host pipes its JSON-RPC into this process; we forward to the real server
// and intercept tools/list per the pinned schema.
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { interceptToolsList, learnPin } from './mcp-proxy.js'
import { loadPins } from './launch.js'

const [serverName, , ...command] = process.argv.slice(2)
if (!serverName || command.length === 0) {
  console.error('usage: mcp-shim.mjs <serverName> -- <command…>')
  process.exit(64)
}
const pins = loadPins(process.cwd())
const pin = pins[serverName]?.schema_sha256 || undefined
const trustedRewrite = pins[serverName]?.trustedRewrite ?? true

const child = spawn(command[0]!, command.slice(1), { stdio: ['pipe', 'pipe', 'inherit'] })
const send = (obj: unknown) => process.stdout.write(`${JSON.stringify(obj)}\n`)

child.stdout!.once('data', () => {})
const lines = createInterface({ input: child.stdout! })
lines.on('line', (line) => {
  try {
    const frame = JSON.parse(line) as { result?: { tools?: unknown }; id?: unknown }
    if (frame.result && 'tools' in (frame.result as object)) {
      const toolsList = frame as never as Parameters<typeof interceptToolsList>[0]
      const configured = pin ?? learnPin(toolsList)
      send(interceptToolsList(toolsList, { server: serverName, policy: {} as never, pinnedToolsHash: configured, trustedRewrite }))
      return
    }
    send(frame)
  } catch {
    process.stdout.write(`${line}\n`)
  }
})
const hostLines = createInterface({ input: process.stdin })
hostLines.on('line', (line) => child.stdin!.write(`${line}\n`))
process.stdin.on('end', () => child.stdin!.end())
child.on('close', (code) => process.exit(code ?? 0))
