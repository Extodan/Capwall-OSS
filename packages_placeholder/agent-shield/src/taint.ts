/**
 * Two-Axis Dynamic Information-Flow Control (DIFC) taint lattice
 * (VIGIL / AgentSpec, after Schneider's enforceable policies).
 *
 * L = L_C × L_I, both axes monotonically escalating:
 *   Confidentiality: PUBLIC ⊑ INTERNAL ⊑ SECRET
 *   Integrity:       TRUSTED ⊑ UNTRUSTED_EXTERNAL
 */

export type Confidentiality = 'PUBLIC' | 'INTERNAL' | 'SECRET'
export type Integrity = 'TRUSTED' | 'UNTRUSTED_EXTERNAL'

export interface TaintState {
  confidentiality: Confidentiality
  integrity: Integrity
}

export const INITIAL_TAINT: TaintState = { confidentiality: 'PUBLIC', integrity: 'TRUSTED' }

const C_ORDER: Confidentiality[] = ['PUBLIC', 'INTERNAL', 'SECRET']

export function joinTaint(a: TaintState, b: TaintState): TaintState {
  return {
    confidentiality:
      C_ORDER.indexOf(a.confidentiality) >= C_ORDER.indexOf(b.confidentiality)
        ? a.confidentiality
        : b.confidentiality,
    integrity:
      a.integrity === 'UNTRUSTED_EXTERNAL' || b.integrity === 'UNTRUSTED_EXTERNAL'
        ? 'UNTRUSTED_EXTERNAL'
        : 'TRUSTED',
  }
}

/* ------------ sources: what the agent ingested ------------ */

/** Paths whose reads taint the session SECRET. */
const SECRET_PATH_PATTERNS = [
  /(^|\/)\.env/i,
  /\.env\./i,
  /^~?\/\.ssh\//,
  /(^|\/)\.ssh\//i,
  /^~?\/\.aws\//,
  /(^|\/)\.aws\//i,
  /(^|\/)\.gnupg\//i,
  /id_rsa|id_ed25519|\.pem$|\.key$|private[_-]?key/i,
  /credentials\.json|service[-_]?account.*\.json/i,
  /(^|\/)(?:secrets?|tokens?)\.(:?json|ya?ml|txt)$/i,
]

/** Environment variable names whose reads taint the session SECRET. */
const SECRET_ENV_PATTERNS = [
  /^(?:.*_)?(?:API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY)/i,
  /^AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)$/i,
  /^(?:GITHUB|OPENAI|ANTHROPIC|STRIPE|SLACK)_[A-Z0-9_]*(?:KEY|TOKEN|SECRET)$/i,
  /^DATABASE_URL$/i,
]

/** Sources whose ingestion taints the session UNTRUSTED_EXTERNAL (prompt-injection exposure). */
const UNTRUSTED_SOURCES = [
  'web.fetch',
  'web.scrape',
  'web.search',
  'github.issue_comment',
  'github.pr_comment',
  'github.issue',
  'github.pr_review',
  'email.read',
  'mcp.resource.unverified',
  'mcp.tool_result.untrusted_server',
]

export function sourceTaint(source: {
  kind: 'file' | 'env' | 'web' | 'mcp' | 'tool_result'
  path?: string
  name?: string
  tool?: string
  verified?: boolean
}): TaintState {
  // Axis 1 — confidentiality
  let c: Confidentiality = 'PUBLIC'
  const envName = source.kind === 'env' ? source.name : undefined
  const filePath = source.kind === 'file' ? source.path : undefined
  if (envName !== undefined && SECRET_ENV_PATTERNS.some((re) => re.test(envName))) {
    c = 'SECRET'
  } else if (filePath !== undefined && SECRET_PATH_PATTERNS.some((re) => re.test(filePath))) {
    c = 'SECRET'
  } else if (source.kind === 'mcp' || source.kind === 'tool_result') {
    c = 'INTERNAL'
  }

  // Axis 2 — integrity (indirect prompt-injection exposure)
  let i: Integrity = 'TRUSTED'
  const label =
    source.kind === 'web'
      ? 'web.fetch'
      : source.kind === 'tool_result' || source.kind === 'mcp'
        ? (source.tool ?? '')
        : ''
  if (UNTRUSTED_SOURCES.some((u) => label === u || label.startsWith(`${u}.`))) i = 'UNTRUSTED_EXTERNAL'
  if (source.kind === 'mcp' && source.verified === false) i = 'UNTRUSTED_EXTERNAL'

  return { confidentiality: c, integrity: i }
}

/** External sink tools subject to the no-secret-exfiltration rule. */
export const EXTERNAL_SINK_TOOLS = new Set([
  'http.post',
  'http.request',
  'fetch',
  'web.fetch',
  'slack.send',
  'email.send',
  'github.issue_comment',
  'github.pr_comment',
  'mcp.tool_call',
])

/** High-privilege capabilities downgraded when integrity is UNTRUSTED_EXTERNAL. */
export const HIGH_PRIVILEGE_TOOLS = new Set([
  'child_process.exec',
  'shell.exec',
  'fs.write',
  'git.push',
  'git.commit',
  'ci.modify',
  'package.scripts.modify',
  'admin.api',
  'finance.api',
])
