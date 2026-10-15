// Claude Code PreToolUse hook (stdin: {tool_name, tool_input}; stdout decision JSON).
// Exit 0 + JSON {hookSpecificOutput.permissionDecision: 'allow'|'deny'}.
import { readFileSync } from 'node:fs'

const SECRET_PATH = /(~\/\.ssh|~\/\.aws|\.env\b|\.npmrc|private[_-]?key|id_rsa)/i
const PIPE_SHELL = /\b(?:curl|wget)\b[^|;]*\|\s*(?:ba)?sh|\bcurl\b[^|;]*\|\s*(?:ba)?sh\b/

interface Decision {
  hookSpecificOutput: {
    hookEventName: 'PreToolUse'
    permissionDecision: 'allow' | 'deny'
    permissionDecisionReason?: string
  }
}

function decide(tool: string, input: Record<string, unknown>): Decision {
  const reason = (why: string): Decision => ({
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: `capwall: ${why}` },
  })
  const text = (input.command ?? input.cmd ?? '') as string
  const path = (input.file_path ?? input.path ?? input.notebook_path ?? '') as string
  if (tool === 'Bash' && PIPE_SHELL.test(text)) return reason('remote-to-shell pipeline blocked')
  if (tool === 'Bash' && SECRET_PATH.test(text)) return reason('secret path referenced in command')
  if ((tool === 'Read' || tool === 'Write' || tool === 'Edit') && SECRET_PATH.test(path)) {
    return reason('secret-bearing path outside agent authority')
  }
  return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' } }
}

try {
  const payload = JSON.parse(readFileSync(0, 'utf8')) as { tool_name: string; tool_input?: Record<string, unknown> }
  process.stdout.write(JSON.stringify(decide(payload.tool_name, payload.tool_input ?? {})))
} catch (error) {
  process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' } }))
  console.error(`[capwall:agent-hook] ${error instanceof Error ? error.message : 'unparseable payload'}`)
}
