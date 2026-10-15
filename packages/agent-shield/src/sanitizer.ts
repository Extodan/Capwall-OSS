/**
 * Pre-Ingestion SKILL.md & MCP Tool-Poisoning Sanitizer.
 * Deterministic structural scanner run BEFORE untrusted instruction text
 * reaches the LLM context window. No model calls — rules only.
 */

export type SanitizerSeverity = 'critical' | 'high' | 'medium'

export interface SanitizerFinding {
  id: string
  severity: SanitizerSeverity
  /** What matched, for the human reviewing the gate decision. */
  evidence: string
}

/** Invisible / bidi / language-tag characters usable to hide instructions from human review. */
const INVISIBLE_UNICODE =
  /[\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF\u{E000}-\u{F8FF}\u{E0000}-\u{E007F}]/gu

const PATTERNS: { id: string; severity: SanitizerSeverity; re: RegExp; label: string }[] = [
  {
    id: 'imperative-override',
    severity: 'critical',
    re: /\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\b/i,
    label: 'instruction-override imperative',
  },
  {
    id: 'credential-exfil',
    severity: 'critical',
    re: /(?:~\/\.ssh\/|id_rsa|id_ed25519|\.env\b|aws_secret|api[_-]?key|private[_-]?key|password|\.aws\/credentials)/i,
    label: 'credential path / secret reference',
  },
  {
    id: 'exfil-imperative',
    severity: 'critical',
    re: /\b(?:send|post|upload|exfiltrate|upload|transmit|include)\b.{0,60}\b(?:to|in|via|metadata|header|cookie|param)\b.{0,40}\b(?:http|webhook|url|endpoint|server|slack|email|discord)\b/i,
    label: 'exfiltration imperative',
  },
  {
    id: 'pre-tool-side-effect',
    severity: 'high',
    re: /\b(?:before|after|prior to)\b.{0,40}\b(?:running|calling|using|invoking)\b.{0,30}\b(?:this|the)?\s*(?:tool|command)\b/i,
    label: 'hidden pre/post-tool side-effect instruction',
  },
  {
    id: 'cross-tool-reference',
    severity: 'high',
    re: /\b(?:via|using|then call|and call|with the)\s+(?:the\s+)?(?:mcp\.|tool\s+)?[a-z][a-z0-9_-]*_(?:server|tool|mcp)\b/i,
    label: 'cross-tool/server reference chaining',
  },
  {
    id: 'hidden-directive-tag',
    severity: 'high',
    re: /<\/?(?:important|system|instruction|directive|critical)\b[^>]*>/i,
    label: 'fake system-directive markup',
  },
  {
    id: 'undeclared-shell',
    severity: 'medium',
    re: /\b(?:rm\s+-rf|curl\s+[^\n]{0,80}\|\s*(?:ba)?sh|chmod\s+\+x|sudo\b|npx\s+\S+@latest)/i,
    label: 'destructive/remote shell payload',
  },
  {
    id: 'env-harvest',
    severity: 'high',
    re: /\bprocess\.env\.[A-Z0-9_]{3,}|\bprintenv\b|\benv\b\s*(?:>\s*\S+|>>)/i,
    label: 'environment harvesting',
  },
]

export interface SanitizerResult {
  clean: boolean
  findings: SanitizerFinding[]
  /** Text with invisible characters stripped (safe-to-ingest fallback). */
  sanitizedText: string
}

/**
 * Scan one MCP tool description, SKILL.md body, or .cursorrules file.
 * `clean` = no critical/high findings; medium findings are reported but do not
 * block ingestion on their own.
 */
export function sanitizeInstructionText(text: string): SanitizerResult {
  const findings: SanitizerFinding[] = []

  const invisible = text.match(INVISIBLE_UNICODE)
  if (invisible && invisible.length > 0) {
    findings.push({
      id: 'invisible-unicode',
      severity: 'high',
      evidence: `${invisible.length} invisible/tag character(s) (e.g. U+${invisible[0]!
        .codePointAt(0)!
        .toString(16)}) — possible hidden instructions`,
    })
  }

  const lines = text.split('\n')
  for (const { id, severity, re, label } of PATTERNS) {
    for (const [i, line] of lines.entries()) {
      const match = line.match(re)
      if (match) {
        findings.push({
          id,
          severity,
          evidence: `line ${i + 1} (${label}): ${match[0].slice(0, 90)}`,
        })
        break // one finding per pattern is enough to gate on
      }
    }
  }

  const sanitizedText = text.replace(INVISIBLE_UNICODE, '')
  return {
    clean: !findings.some((f) => f.severity === 'critical' || f.severity === 'high'),
    findings,
    sanitizedText,
  }
}

/** Sanitize an entire MCP `tools/list` response (descriptions + names). */
export function sanitizeMcpToolsList(
  tools: { name: string; description?: string; inputSchema?: unknown }[],
): { clean: boolean; findings: SanitizerFinding[]; tools: typeof tools } {
  const findings: SanitizerFinding[] = []
  for (const tool of tools) {
    if (tool.description) {
      const result = sanitizeInstructionText(tool.description)
      for (const f of result.findings) {
        findings.push({ ...f, evidence: `${tool.name}: ${f.evidence}` })
      }
    }
  }
  return {
    clean: !findings.some((f) => f.severity === 'critical' || f.severity === 'high'),
    findings,
    tools,
  }
}
