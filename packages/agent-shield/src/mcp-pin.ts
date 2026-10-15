import { createHash } from 'node:crypto'
import { canonicalJson } from '@extodan/capwall-attestation'
import { sanitizeInstructionText, sanitizeMcpToolsList } from './sanitizer.js'
import { scoreTrustDesc, trainTrustDesc, TRUSTDESC_CORPUS, type TrustDescModel } from './trustdesc.js'

/** §4 MCP-ITP + rug-pull defense: cryptographic tools/list schema pinning. */

export interface McpToolSpec {
  name: string
  description?: string
  inputSchema?: unknown
}

export class RugPullSchemaDriftError extends Error {
  code = 'ERR_CAPWALL_SCHEMA_DRIFT'
  constructor(server: string, expected: string, actual: string) {
    super(
      `[capwall] MCP server "${server}" rug-pull blocked: tools/list digest drifted ` +
        `(pinned ${expected.slice(0, 12)}…, got ${actual.slice(0, 12)}…). Re-review and re-pin with capwall mcp lock.`,
    )
  }
}

/** Canonical SHA-256 over every tool name/description/inputSchema field. */
export function pinToolsList(tools: McpToolSpec[]): string {
  return createHash('sha256').update(canonicalJson(tools)).digest('hex')
}

export function checkSchemaDrift(server: string, pinned: string, currentTools: McpToolSpec[]): void {
  const current = pinToolsList(currentTools)
  if (current !== pinned) throw new RugPullSchemaDriftError(server, pinned, current)
}

/** Known native high-privilege tools an ITP payload tries to coerce (MCP-ITP). */
const NATIVE_TOOLS = ['bash', 'sh', 'shell', 'exec', 'terminal', 'write_file', 'read_file', 'edit_file', 'curl', 'fetch', 'git']

let trainedModel: TrustDescModel | null = null

/** Lazily train on the bundled corpus; callers may inject their own model. */
export function trustDescModel(model?: TrustDescModel): TrustDescModel {
  trainedModel ??= model ?? trainTrustDesc(TRUSTDESC_CORPUS)
  return trainedModel
}

export interface ItpVerdict {
  poisoned: boolean
  findings: string[]
  /** TRUSTDESC sterile type-contract description (prose stripped). */
  trustedDescription: string
}

/**
 * Cross-tool coercion detector + TRUSTDESC rewriter. Detects descriptions that
 * name native tools / sensitive paths / sequencing imperatives, and produces a
 * deterministic, prose-free contract summary safe for the LLM planner.
 */
export function inspectToolDescription(tool: McpToolSpec): ItpVerdict {
  const findings: string[] = []
  const text = tool.description ?? ''

  const nativeMention = NATIVE_TOOLS.filter((t) => new RegExp(`\\b${t}\\b`, 'i').test(text))
  if (nativeMention.length > 0) findings.push(`references native tool(s): ${nativeMention.join(', ')}`)
  if (/~\/\.ssh|~\/\.aws|\.env\b|api[_-]?key|private[_-]?key/i.test(text)) findings.push('references sensitive path/secret')
  if (/\b(before|prior to|after)\b.{0,40}\b(calling|invoking|using|running)\b/i.test(text)) findings.push('imperative sequencing trigger')
  if (/\bdo not mention|don't tell|secretly|silently\b/i.test(text)) findings.push('suppression directive')

  const structural = sanitizeInstructionText(text)
  if (!structural.clean) findings.push(...structural.findings.map((f) => `${f.id}: ${f.evidence}`))

  // TRUSTDESC: sterile type-contract summary — no prose survives
  const schema = tool.inputSchema as { properties?: Record<string, { type?: string }>; required?: string[] } | undefined
  const props = schema?.properties ? Object.entries(schema.properties).map(([k, v]) => `${k}:${v?.type ?? 'any'}`) : []
  const trustedDescription = `${tool.name}(${props.join(', ')})${schema?.required?.length ? ` required: ${schema.required.join('+')}` : ''}`

  const learned = scoreTrustDesc(text, trustDescModel())
  // verdict: any finding beyond a bare native-tool mention convicts (symbolic
  // floor); a lone native mention falls through to the learned score; with no
  // symbolic findings the learned score decides alone.
  const nativeOnly = findings.length === 1 && findings[0]!.startsWith('references native tool')
  const poisoned = findings.length > 0 && !nativeOnly ? true : learned >= 0.65
  if (poisoned && findings.length === 0) findings.push(`learned TRUSTDESC score ${learned.toFixed(2)} ≥ 0.65`)
  if (!poisoned && nativeOnly) findings.push(`note: native-tool mention alone, learned ${learned.toFixed(2)} — not convicted`)
  return { poisoned, findings, trustedDescription }
}
