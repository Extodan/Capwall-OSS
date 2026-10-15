import { parse } from 'acorn'
import { full } from 'acorn-walk'
import type { Node } from 'acorn'
import {
  builtinCapabilities,
  normalizeSpecifier,
  type Capability,
} from '@capwall/core'
import { analyzeDataflow } from './dataflow.js'

/** Heuristically-known HTTP client libraries — indirect network usage. */
const NETWORK_LIBRARIES = new Set([
  'axios',
  'node-fetch',
  'got',
  'request',
  'superagent',
  'cross-fetch',
  'isomorphic-fetch',
  'undici',
  'needle',
  'phin',
  'bent',
  'unirest',
  'make-fetch-happen',
])

const MAX_OBFUSCATED_FINDINGS = 5

export interface FileFindings {
  /** Pass-1 outputs for cross-file orchestration. */
  taintedFunctions?: string[]
  exportsTainted?: boolean
  capabilities: Set<Capability>
  /** process.env variable names accessed (statically known ones). */
  envVars: Set<string>
  /** Evidence strings for the report. */
  signals: string[]
  /**
   * Soundness escapes (Xu & Møller, ASE 2026): dynamic/reflective access to
   * capability root objects that static analysis cannot resolve. These force
   * runtime protection instead of a silent all-clear.
   */
  escapes: string[]
  parseErrors: number
}

export function emptyFindings(): FileFindings {
  return { capabilities: new Set(), envVars: new Set(), signals: [], escapes: [], parseErrors: 0 }
}

interface AcornNode extends Node {
  [key: string]: any
}

function isIdentifier(node: AcornNode | undefined, name: string): boolean {
  return node?.type === 'Identifier' && node.name === name
}

/** Match `process.env` MemberExpression (non-computed property irrelevant here). */
function isProcessEnv(node: AcornNode | undefined): boolean {
  return (
    node?.type === 'MemberExpression' &&
    ((node.object?.type === 'Identifier' && node.object.name === 'process' &&
      (isIdentifier(node.property, 'env') ||
        (node.property?.type === 'Literal' && node.property.value === 'env'))) ||
      isProcessEnv(node.object))
  )
}

/** Extract the variable name from process.env.FOO / process.env['FOO'] if statically known. */
function envVarName(node: AcornNode): string | undefined {
  if (node.property?.type === 'Identifier' && !node.computed) return node.property.name
  if (node.property?.type === 'Literal' && typeof node.property.value === 'string')
    return node.property.value
  return undefined
}

const BASE64_RE = /^[A-Za-z0-9+/]{80,}={0,2}$/
const HEX_RE = /^(?:[0-9a-fA-F]{2}){40,}$/

function distinctChars(value: string): number {
  return new Set(value).size
}

/**
 * Heuristic obfuscation detector: long encoded blobs. Charset entropy is
 * required so benchmark data, repeated filler and sequential digits
 * (e.g. left-pad's perf fixtures) don't false-positive.
 */
export function looksObfuscated(value: string): boolean {
  const distinct = distinctChars(value)
  if (BASE64_RE.test(value)) return distinct >= 24 // random base64 mixes the full alphabet
  if (HEX_RE.test(value)) return distinct >= 12 // real hex uses most of [0-9a-f]
  return false
}

const CAPABILITY_ROOTS = new Set(['globalThis', 'process', 'require', 'module', 'exports'])

const BASE64_KEYWORDS = ['process', 'env', 'child_process', 'fs', 'net', 'http', 'eval', 'function']

/** Try to statically resolve base64-encoded capability words (common evasion). */
function decodeBase64Literal(value: string): string | null {
  try {
    const decoded = Buffer.from(value, 'base64').toString('utf8')
    return BASE64_KEYWORDS.some((k) => decoded.includes(k)) ? decoded : null
  } catch {
    return null
  }
}

/**
 * Statically analyze one JS source file for capability usage.
 * Best-effort by design: parse failures are counted, never thrown.
 */
export function analyzeSource(source: string, hints: { taintedFunctions?: Set<string>; taintedSiblings?: Set<string> } = {}): FileFindings {
  const findings = emptyFindings()

  let ast: Node | undefined
  for (const options of [
    { ecmaVersion: 'latest', sourceType: 'module', allowReturnOutsideFunction: true } as const,
    { ecmaVersion: 'latest', sourceType: 'script', allowReturnOutsideFunction: true } as const,
  ]) {
    try {
      ast = parse(source, options)
      break
    } catch {
      /* try next mode */
    }
  }
  if (!ast) {
    findings.parseErrors = 1
    return findings
  }

  // §1 dataflow pass: alias/fold resolution adds capabilities and escapes the
  // pattern pass cannot see (e.g. globalThis["pro"+"cess"] chains).
  const dataflow = analyzeDataflow(source, hints)
  for (const cap of dataflow.capabilities) findings.capabilities.add(cap)
  for (const escape of dataflow.escapes) findings.escapes.push(escape)
  findings.taintedFunctions = dataflow.taintedFunctions
  findings.exportsTainted = dataflow.exportsTainted

  let obfuscatedCount = 0

  full(ast as AcornNode, (node: AcornNode) => {
    switch (node.type) {
      case 'ImportDeclaration': {
        const spec = normalizeSpecifier(String(node.source?.value ?? ''))
        const caps = builtinCapabilities(spec)
        if (caps) for (const c of caps) findings.capabilities.add(c)
        checkNetworkLib(spec, findings)
        break
      }

      case 'CallExpression': {
        const callee = node.callee
        // require('fs') / require.resolve('fs')
        if (
          isIdentifier(callee, 'require') ||
          (callee?.type === 'MemberExpression' && isIdentifier(callee.object, 'require') &&
            isIdentifier(callee.property, 'resolve'))
        ) {
          const arg = node.arguments?.[0]
          if (arg?.type === 'Literal' && typeof arg.value === 'string') {
            const spec = normalizeSpecifier(arg.value)
            const caps = builtinCapabilities(spec)
            if (caps) for (const c of caps) findings.capabilities.add(c)
            checkNetworkLib(spec, findings)
          }
        }
        // require(nonLiteral) — unsound statically ⇒ escape
        if (isIdentifier(callee, 'require')) {
          const arg = node.arguments?.[0]
          if (arg && arg.type !== 'Literal') {
            findings.escapes.push('require(<dynamic>) at offset ' + node.start)
          }
        }
        // Reflect.get/set/apply on capability roots ⇒ escape
        if (
          callee?.type === 'MemberExpression' &&
          isIdentifier(callee.object, 'Reflect') &&
          ['get', 'set', 'apply', 'construct'].includes(callee.property?.name ?? '')
        ) {
          const target = node.arguments?.[0]
          if (target?.type === 'Identifier' && CAPABILITY_ROOTS.has(target.name)) {
            findings.escapes.push(`Reflect.${callee.property.name}(${target.name}, …) at offset ${node.start}`)
          }
        }
        // Buffer.from('<b64>', 'base64') decoding capability words ⇒ treat as
        // direct evidence of concealed access attempts.
        if (callee?.type === 'MemberExpression' && isIdentifier(callee.object, 'Buffer') && isIdentifier(callee.property, 'from')) {
          const [b64, enc] = node.arguments ?? []
          if (b64?.type === 'Literal' && enc?.type === 'Literal' && enc.value === 'base64' && typeof b64.value === 'string') {
            const decoded = decodeBase64Literal(b64.value)
            if (decoded) findings.escapes.push(`decodes base64 capability word "${decoded.slice(0, 24)}" at offset ${node.start}`)
          }
        }
        // eval('...')
        if (isIdentifier(callee, 'eval')) {
          findings.capabilities.add('dynamic-code')
          findings.signals.push('eval() call')
        }
        // global fetch(...)
        if (isIdentifier(callee, 'fetch')) {
          findings.capabilities.add('http.request')
        }
        // Buffer.from(x, 'base64') — decoding signal
        if (
          callee?.type === 'MemberExpression' &&
          isIdentifier(callee.object, 'Buffer') &&
          isIdentifier(callee.property, 'from')
        ) {
          const enc = node.arguments?.[1]
          if (enc?.type === 'Literal' && enc.value === 'base64') {
            pushOnce(findings, 'decodes base64 buffers')
          }
        }
        break
      }

      case 'NewExpression': {
        // new Function('...')()
        if (isIdentifier(node.callee, 'Function')) {
          findings.capabilities.add('dynamic-code')
          findings.signals.push('new Function(...) constructor')
        }
        break
      }

      case 'MemberExpression': {
        if (isProcessEnv(node)) {
          findings.capabilities.add('env.read')
          const name = envVarName(node)
          if (name && !name.startsWith('_')) findings.envVars.add(name)
          break
        }
        // §1 Defensive Capability Analysis: computed access on a capability
        // root object, e.g. globalThis['pro' + 'cess'] or process[dyn] —
        // unsound statically ⇒ report an escape.
        if (
          node.computed &&
          node.object?.type === 'Identifier' &&
          CAPABILITY_ROOTS.has(node.object.name) &&
          node.property?.type !== 'Literal'
        ) {
          findings.escapes.push(`computed access on ${node.object.name}[…] at offset ${node.start}`)
        }
        break
      }

      case 'AssignmentExpression': {
        // process.env.FOO = 'x'
        if (node.left?.type === 'MemberExpression' && isProcessEnv(node.left)) {
          findings.capabilities.add('env.write')
          const name = envVarName(node.left)
          if (name) findings.envVars.add(name)
        }
        break
      }

      case 'Literal': {
        if (
          obfuscatedCount < MAX_OBFUSCATED_FINDINGS &&
          typeof node.value === 'string' &&
          looksObfuscated(node.value)
        ) {
          obfuscatedCount++
          findings.capabilities.add('dynamic-code')
          findings.signals.push(
            `obfuscated string literal (${node.value.length} chars): ${node.value.slice(0, 24)}…`,
          )
        }
        break
      }
    }
  })

  return findings
}

function checkNetworkLib(spec: string, findings: FileFindings): void {
  const bare = normalizeSpecifier(spec)
  if (NETWORK_LIBRARIES.has(bare)) {
    pushOnce(findings, `uses network library "${bare}"`)
  }
}

function pushOnce(findings: FileFindings, signal: string): void {
  if (!findings.signals.includes(signal) && findings.signals.length < 20) findings.signals.push(signal)
}

export interface MergedFindings {
  capabilities: Capability[]
  envVars: string[]
  signals: string[]
  /** Soundness escapes (see FileFindings.escapes). */
  escapes: string[]
  filesScanned: number
  parseErrors: number
}

export function mergeFindings(all: FileFindings[]): MergedFindings {
  const capabilities = new Set<Capability>()
  const envVars = new Set<string>()
  const signals = new Set<string>()
  const escapes = new Set<string>()
  let filesScanned = 0
  let parseErrors = 0
  for (const f of all) {
    for (const c of f.capabilities) capabilities.add(c)
    for (const v of f.envVars) envVars.add(v)
    for (const s of f.signals) signals.add(s)
    for (const e of f.escapes) escapes.add(e)
    filesScanned++
    parseErrors += f.parseErrors
  }
  return {
    capabilities: [...capabilities].sort(),
    envVars: [...envVars].sort(),
    signals: [...signals],
    escapes: [...escapes].slice(0, 10),
    filesScanned,
    parseErrors,
  }
}
