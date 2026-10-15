import { parse } from 'acorn'
import type { Node } from 'acorn'
import { full } from 'acorn-walk'
import type { Capability } from '@extodan/capwall-core'

/**
 * §1 gap-closer (Xu & Møller, ASE 2026): capability-relevant DATAFLOW, not
 * just pattern matching. Intra-file abstract interpretation over the
 * capability root set O_cap = {globalThis, process, require, Function, eval}:
 * alias tracking, constant-folding of string concat/base64, property chains,
 * and computed access on tainted roots (escape or — when foldable — the
 * resolved capability itself).
 */

type Root = 'globalThis' | 'process' | 'require' | 'Function' | 'eval'

interface Abstract {
  /** Capability-root provenance of this value. */
  roots: Set<Root>
  /** Statically folded string value, when known. */
  fold?: string
  /** Property path walked from a root, e.g. process → env. */
  path?: string[]
}

interface AcornNode extends Node {
  [key: string]: any
}

const ROOT_IDS = new Set(['globalThis', 'process', 'require', 'Function', 'eval'])
const CAP_BY_PATH: Record<string, Capability> = {
  'process.env': 'env.read',
  'process.exit': 'dynamic-code',
  'eval:': 'dynamic-code',
  'Function:': 'dynamic-code',
}
const WORDS = { env: 'env', process: 'process', child_process: 'child_process', fs: 'fs', net: 'net', http: 'http' }

function tryDecodeB64(value: string): string | undefined {
  try {
    const decoded = Buffer.from(value, 'base64').toString('utf8')
    return /^[A-Za-z0-9_.-]+$/.test(decoded) ? decoded : undefined
  } catch {
    return undefined
  }
}

export interface DataflowResult {
  capabilities: Capability[]
  escapes: string[]
  /** Function names in this file that return root-derived values (cross-file hints). */
  taintedFunctions: string[]
  /** This file's module exports carry capability-root-derived values. */
  exportsTainted: boolean
}

/** Evaluate a statically-foldable expression; undefined when dynamic. */
function fold(node: AcornNode | undefined, env: Map<string, Abstract>): Abstract {
  if (!node) return { roots: new Set() }
  switch (node.type) {
    case 'Identifier':
      return env.get(node.name) ?? { roots: new Set() }
    case 'Literal':
      return typeof node.value === 'string' ? { roots: new Set(), fold: node.value } : { roots: new Set() }
    case 'BinaryExpression':
      if (node.operator === '+') {
        const left = fold(node.left, env)
        const right = fold(node.right, env)
        if (left.fold !== undefined && right.fold !== undefined) return { roots: new Set(), fold: left.fold + right.fold }
        return { roots: new Set([...left.roots, ...right.roots]) }
      }
      return { roots: new Set() }
    case 'CallExpression': {
      // Buffer.from("<b64>", "base64") → folded decoded word
      const callee = node.callee
      if (
        callee?.type === 'MemberExpression' &&
        callee.object?.name === 'Buffer' &&
        callee.property?.name === 'from' &&
        node.arguments?.[0]?.type === 'Literal' &&
        typeof node.arguments[0].value === 'string'
      ) {
        const enc = node.arguments[1]
        if (!enc || enc.type === 'Literal') {
          const decoded = tryDecodeB64(node.arguments[0].value)
          if (decoded) return { roots: new Set(), fold: decoded }
        }
      }
      // require("x") folds to its specifier and carries the require root
      if (callee?.type === 'Identifier' && callee.name === 'require' && node.arguments?.[0]?.type === 'Literal') {
        return { roots: new Set<Root>(['require']), fold: String(node.arguments[0].value) }
      }
      // call of a tainted function name → taint the result conservatively
      if (callee?.type === 'Identifier') {
        const fn = env.get(callee.name)
        if (fn && fn.roots.size > 0) return { roots: fn.roots }
      }
      // chained .toString() on a folded value keeps the fold (base64 idiom)
      if (callee?.type === 'MemberExpression' && callee.property?.name === 'toString') {
        const target = fold(callee.object, env)
        if (target.fold !== undefined) return target
      }
      return { roots: new Set() }
    }
    default:
      return { roots: new Set() }
  }
}

/** Abstract-interpret the module body; returns capabilities + escapes found. */
export function analyzeDataflow(source: string, hints: { taintedFunctions?: Set<string>; taintedSiblings?: Set<string> } = {}): DataflowResult {
  let ast: Node | undefined
  try {
    ast = parse(source, { ecmaVersion: 'latest', sourceType: 'script', allowReturnOutsideFunction: true })
  } catch {
    try {
      ast = parse(source, { ecmaVersion: 'latest', sourceType: 'module', allowReturnOutsideFunction: true })
    } catch {
      return { capabilities: [], escapes: [], taintedFunctions: [], exportsTainted: false }
    }
  }
  const env = new Map<string, Abstract>()
  const capabilities = new Set<Capability>()
  const escapes: string[] = []
  const taintedFunctions: string[] = []
  let exportsTainted = false

  for (const hinted of hints.taintedFunctions ?? []) {
    if (!env.has(hinted)) env.set(hinted, { roots: new Set<Root>(['process']) })
  }
  const asString = (node: AcornNode | undefined): string | undefined => fold(node, env).fold

  const returnRooted = new Set<string>()
  full(ast as AcornNode, (node: AcornNode) => {
    if (node.type === 'FunctionDeclaration' && node.id?.name) {
      const fnName: string = node.id.name
      let rooted = false
      full(node, (n: AcornNode) => {
        if (n.type === 'ReturnStatement' && fold(n.argument, env).roots.size > 0) rooted = true
      })
      if (rooted) returnRooted.add(fnName)
    }
  })
  for (const name of returnRooted) { taintedFunctions.push(name); env.set(name, { roots: new Set<Root>(['process']) }) }

  full(ast as AcornNode, (node: AcornNode) => {
    if (node.type !== 'VariableDeclarator' || !node.id || node.id.type !== 'Identifier') return
    const name: string = node.id.name
    const init = node.init
    if (!init) return

    if (init.type === 'Identifier') {
      if (ROOT_IDS.has(init.name)) {
        env.set(name, { roots: new Set<Root>([init.name as Root]) })
        return
      }
      const src = env.get(init.name)
      if (src) env.set(name, { ...src, roots: new Set(src.roots) })
      return
    }
    if (init.type === 'MemberExpression') {
      const object = init.object
      // root chains: globalThis.x / process.x / <tainted>.x
      if (object?.type === 'Identifier') {
        const propName = init.computed ? asString(init.property) : init.property?.name
        if (ROOT_IDS.has(object.name)) {
          if (init.computed && propName === undefined) {
            escapes.push(`dataflow: computed access ${object.name}[<dynamic>] assigned to ${name}`)
            env.set(name, { roots: new Set<Root>([object.name as Root]) })
            return
          }
          if (propName === 'env' && object.name === 'process') capabilities.add('env.read')
          if (object.name === 'eval' || object.name === 'Function') capabilities.add('dynamic-code')
          env.set(name, { roots: new Set<Root>([object.name as Root]), path: [String(propName)] })
          return
        }
        const src = env.get(object.name)
        if (src && src.roots.size > 0) {
          if (init.computed && propName === undefined) {
            escapes.push(`dataflow: computed access on alias "${object.name}" (rooted at ${[...src.roots][0]})`)
            env.set(name, src)
            return
          }
          const path = [...(src.path ?? []), String(propName)]
          const joined = `${[...src.roots][0]}:${path.join('.')}`
          if (CAP_BY_PATH[`${[...src.roots][0]}.${path.join('.')}`]) {
            capabilities.add(CAP_BY_PATH[`${[...src.roots][0]}.${path.join('.')}`]!)
          }
          if (propName === 'env') capabilities.add('env.read')
          env.set(name, { roots: src.roots, path })
          void joined
        }
      }
      // base64-decoded member access on a folded object path is handled by
      // the parent chain above when the root is an identifier alias.
      return
    }
    // cross-file alias (§1 gap-closer): require('./sibling') whose file exports
    // root-derived values → treat the binding as root-carrying and flag it.
    if (init.type === 'CallExpression' && init.callee?.type === 'Identifier' && init.callee.name === 'require') {
      const arg = init.arguments?.[0]
      if (arg?.type === 'Literal' && typeof arg.value === 'string' && arg.value.startsWith('.')) {
        const base = arg.value.split('/').pop()!.replace(/\.js$/, '')
        if (hints.taintedSiblings?.has(base)) {
          exportsTainted = true
          capabilities.add('env.read')
          escapes.push(`cross-file alias: ${name} = require('${arg.value}') — sibling module exports capability roots`)
          env.set(name, { roots: new Set<Root>(['process']) })
          return
        }
      }
    }
    // generic folding (concat, Buffer.from b64, require literal)
    const value = fold(init, env)
    if (value.fold !== undefined || value.roots.size > 0) env.set(name, value)

    // the evasion idiom: root[folded-string] where the fold resolves a word
    if (init.type === 'MemberExpression' && init.computed) {
      const folded = asString(init.property)
      const objectName = init.object?.name
      if (objectName) {
        const obj = env.get(objectName)
        const objFold = obj?.fold ?? (objectName === 'globalThis' ? 'globalThis' : undefined)
        const word = WORDS[folded as keyof typeof WORDS]
        if (obj && obj.roots.has('globalThis') && word === 'process') {
          env.set(name, { roots: new Set<Root>(['process']) }) // globalThis["process"] → process root
        } else if (obj && obj.roots.has('process') && word === 'env') {
          capabilities.add('env.read')
        } else if (objFold === 'globalThis' && word === 'process') {
          env.set(name, { roots: new Set<Root>(['process']) })
        }
      }
    }
  })

  full(ast as AcornNode, (node: AcornNode) => {
    if (node.type === 'AssignmentExpression' && node.left?.type === 'MemberExpression') {
      const obj = node.left.object?.name
      if (obj === 'module' || obj === 'exports' || (node.left.object?.type === 'MemberExpression' && node.left.object.object?.name === 'module')) {
        if (fold(node.right, env).roots.size > 0 || capabilities.size > 0) exportsTainted = true
      }
    }
  })
  return { capabilities: [...capabilities], escapes: escapes.slice(0, 10), taintedFunctions, exportsTainted }
}
