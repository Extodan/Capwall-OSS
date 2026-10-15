import type { DigestMap } from './statement.js'

/**
 * in-toto Layout artifact rules (spec v1.0 §"Artifact Rules").
 * Rules are evaluated in order against a queue built from the union of a
 * step's materials and products; unconsumed leftovers fail the step.
 */

export type Rule =
  | { rule: 'ALLOW'; pattern: string }
  | { rule: 'DISALLOW'; pattern: string }
  | { rule: 'CREATE'; pattern: string }
  | { rule: 'MODIFY'; pattern: string }
  | { rule: 'DELETE'; pattern: string }
  | {
      rule: 'MATCH'
      pattern: string
      /** Source path pattern; defaults to matching basenames. */
      in?: string
      /** Match against source step's products (default) or materials. */
      with: 'PRODUCTS' | 'MATERIALS'
      from?: string
    }

/** Parse the string form, e.g. `MATCH capabilities.lock WITH PRODUCTS FROM step_ast_capability_scan`. */
export function parseRule(text: string): Rule {
  const parts = text.trim().split(/\s+/)
  const head = (parts[0] ?? '').toUpperCase()
  const rest = parts.slice(1)

  switch (head) {
    case 'ALLOW':
    case 'DISALLOW':
    case 'CREATE':
    case 'MODIFY':
    case 'DELETE': {
      if (rest.length < 1) throw new Error(`rule "${text}" needs a pattern`)
      return { rule: head, pattern: rest.join(' ') } as Rule
    }
    case 'MATCH': {
      if (rest.length < 1) throw new Error(`MATCH needs a pattern`)
      let pattern = rest[0]!
      let inPattern: string | undefined
      let withWhat: 'PRODUCTS' | 'MATERIALS' = 'PRODUCTS'
      let from: string | undefined
      for (let i = 1; i < rest.length; i++) {
        const token = rest[i]!.toUpperCase()
        if (token === 'IN') {
          inPattern = rest[++i]
        } else if (token === 'WITH') {
          const next = (rest[++i] ?? '').toUpperCase()
          withWhat = next === 'MATERIALS' ? 'MATERIALS' : 'PRODUCTS'
        } else if (token === 'FROM') {
          from = rest[++i]
        }
      }
      return { rule: 'MATCH', pattern, in: inPattern, with: withWhat, from }
    }
    default:
      throw new Error(`unknown rule "${text}"`)
  }
}

export function formatRule(rule: Rule): string {
  if (rule.rule === 'MATCH') {
    return [
      'MATCH',
      rule.pattern,
      rule.in ? `IN ${rule.in}` : '',
      `WITH ${rule.with}`,
      rule.from ? `FROM ${rule.from}` : '',
    ]
      .filter(Boolean)
      .join(' ')
  }
  return `${rule.rule} ${rule.pattern}`
}

/** Glob supporting `*` (within a segment), `**` (across segments) and `?`. */
export function globToRegExp(glob: string): RegExp {
  let re = ''
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!
    if (c === '*') {
      if (glob[i + 1] === '*') {
        re += '.*'
        i++
        if (glob[i + 1] === '/') i++ // '**/' also swallows the slash
      } else {
        re += '[^/]*'
      }
    } else if (c === '?') {
      re += '[^/]'
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&')
    }
  }
  return new RegExp(`^${re}$`)
}

function basename(path: string): string {
  const idx = path.lastIndexOf('/')
  return idx === -1 ? path : path.slice(idx + 1)
}

interface QueuedArtifact {
  path: string
  sha256: string
  inMaterials: boolean
  inProducts: boolean
}

export interface RuleEvaluation {
  ok: boolean
  violations: string[]
}

/**
 * Apply a step's artifact rules. `linksByStep` supplies MATCH sources:
 * artifact maps of other steps' links (products or materials per the rule).
 */
export function applyRules(
  rules: Rule[],
  materials: DigestMap,
  products: DigestMap,
  linksByStep: Record<string, { materials: DigestMap; products: DigestMap }>,
): RuleEvaluation {
  const violations: string[] = []

  // Queue: union of materials + products (a path present in both keeps the product digest,
  // but remembers it appeared in materials so MODIFY/DELETE can reason about it).
  const queue = new Map<string, QueuedArtifact>()
  for (const [path, digest] of Object.entries(materials)) {
    queue.set(path, { path, sha256: digest.sha256, inMaterials: true, inProducts: false })
  }
  for (const [path, digest] of Object.entries(products)) {
    const existing = queue.get(path)
    if (existing) {
      existing.inProducts = true
      existing.sha256 = digest.sha256
    } else {
      queue.set(path, { path, sha256: digest.sha256, inMaterials: false, inProducts: true })
    }
  }

  const consumeMatching = (pattern: string): QueuedArtifact[] => {
    const re = globToRegExp(pattern)
    const matched: QueuedArtifact[] = []
    for (const artifact of queue.values()) {
      const path = pattern.includes('/') ? artifact.path : basename(artifact.path)
      if (re.test(path)) matched.push(artifact)
    }
    for (const artifact of matched) queue.delete(artifact.path)
    return matched
  }

  for (const rule of rules) {
    switch (rule.rule) {
      case 'ALLOW': {
        consumeMatching(rule.pattern)
        break
      }
      case 'DISALLOW': {
        const matched = consumeMatching(rule.pattern)
        if (matched.length > 0) {
          violations.push(`DISALLOW ${rule.pattern}: forbidden artifacts ${matched.map((m) => m.path).join(', ')}`)
        }
        break
      }
      case 'CREATE': {
        const matched = consumeMatching(rule.pattern)
        if (matched.length === 0) violations.push(`CREATE ${rule.pattern}: no artifacts matched`)
        for (const artifact of matched) {
          if (artifact.inMaterials) {
            violations.push(`CREATE ${rule.pattern}: ${artifact.path} already existed in materials`)
          }
        }
        break
      }
      case 'MODIFY': {
        const matched = consumeMatching(rule.pattern)
        if (matched.length === 0) violations.push(`MODIFY ${rule.pattern}: no artifacts matched`)
        for (const artifact of matched) {
          if (!artifact.inMaterials || !artifact.inProducts) {
            violations.push(
              `MODIFY ${rule.pattern}: ${artifact.path} must appear in both materials and products`,
            )
          } else if (materials[artifact.path]?.sha256 === products[artifact.path]?.sha256) {
            violations.push(`MODIFY ${rule.pattern}: ${artifact.path} is unchanged`)
          }
        }
        break
      }
      case 'DELETE': {
        const re = globToRegExp(rule.pattern)
        let deletedAny = false
        for (const artifact of [...queue.values()]) {
          const path = rule.pattern.includes('/') ? artifact.path : basename(artifact.path)
          if (re.test(path) && artifact.inMaterials && !artifact.inProducts) {
            queue.delete(artifact.path)
            deletedAny = true
          }
        }
        if (!deletedAny) violations.push(`DELETE ${rule.pattern}: no deleted artifacts matched`)
        break
      }
      case 'MATCH': {
        const source = rule.from ? linksByStep[rule.from] : undefined
        if (!source) {
          violations.push(`MATCH ${rule.pattern} FROM ${rule.from ?? '(missing step)'}: source step not found`)
          break
        }
        const sourceArtifacts = rule.with === 'PRODUCTS' ? source.products : source.materials
        const matched = consumeMatching(rule.pattern)
        if (matched.length === 0) {
          violations.push(`MATCH ${rule.pattern}: no destination artifacts matched`)
          break
        }
        const sourceRe = rule.in ? globToRegExp(rule.in) : globToRegExp(rule.pattern)
        for (const artifact of matched) {
          // Resolve source path: with IN pattern, substitute dir prefix; else match basename.
          const sourcePath = Object.keys(sourceArtifacts).find((p) =>
            rule.in ? sourceRe.test(p) : sourceRe.test(basename(p)),
          )
          const sourceDigest = sourcePath ? sourceArtifacts[sourcePath]?.sha256 : undefined
          if (!sourceDigest) {
            violations.push(
              `MATCH ${rule.pattern} WITH ${rule.with} FROM ${rule.from}: no source artifact for ${artifact.path}`,
            )
          } else if (sourceDigest !== artifact.sha256) {
            violations.push(
              `MATCH ${rule.pattern} WITH ${rule.with} FROM ${rule.from}: digest mismatch for ${artifact.path} ` +
                `(expected ${sourceDigest.slice(0, 12)}…, got ${artifact.sha256.slice(0, 12)}…)`,
            )
          }
        }
        break
      }
    }
  }

  if (queue.size > 0) {
    violations.push(
      `unconsumed artifacts not covered by any rule: ${[...queue.values()].map((a) => a.path).join(', ')}`,
    )
  }

  return { ok: violations.length === 0, violations }
}
