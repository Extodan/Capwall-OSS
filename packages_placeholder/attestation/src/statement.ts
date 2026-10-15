/**
 * in-toto Statement v1 (attestation framework) carrying Link metadata as
 * the predicate. This is the payload inside every DSSE envelope.
 */

export const STATEMENT_TYPE = 'https://in-toto.io/Statement/v1'
export const LINK_PREDICATE_TYPE = 'https://capwall.dev/attest/link/v0.1'
export const SBOM_PREDICATE_TYPE = 'https://capwall.dev/attest/sbom/v0.1'
export const RBOM_PREDICATE_TYPE = 'https://capwall.dev/attest/rbom/v0.1'

/** artifact path → content digests */
export type DigestMap = Record<string, { sha256: string }>

export interface Subject {
  name: string
  digest: { sha256: string }
}

/**
 * in-toto Link metadata (layout/link spec v1.0) as a Statement predicate.
 * `environment` carries Capwall runtime telemetry for RBOM links.
 */
export interface LinkPredicate {
  /** Step name this link attests (must match a Layout step). */
  name: string
  /** Exact command + flags executed. */
  command?: string[]
  /** Input artifacts + SHA-256 digests captured *before* the step ran. */
  materials: DigestMap
  /** Output artifacts + SHA-256 digests captured *after* the step ran. */
  products: DigestMap
  /** Execution telemetry: loaded packages, RWXi capabilities exercised, blocked violations. */
  byproducts?: Record<string, unknown>
  environment?: Record<string, unknown>
}

export interface Statement {
  _type: typeof STATEMENT_TYPE
  subject: Subject[]
  predicateType: string
  predicate: LinkPredicate | Record<string, unknown>
}

export function linkStatement(
  stepName: string,
  input: {
    command?: string[]
    materials?: DigestMap
    products?: DigestMap
    byproducts?: Record<string, unknown>
    environment?: Record<string, unknown>
  },
): Statement {
  const materials = input.materials ?? {}
  const products = input.products ?? {}
  return {
    _type: STATEMENT_TYPE,
    subject: Object.entries(products).map(([name, digest]) => ({
      name,
      digest: { sha256: digest.sha256 },
    })),
    predicateType: LINK_PREDICATE_TYPE,
    predicate: {
      name: stepName,
      command: input.command,
      materials,
      products,
      byproducts: input.byproducts,
      environment: input.environment,
    },
  }
}

/** Type guard for link-shaped predicates. */
export function isLinkPredicate(predicate: unknown): predicate is LinkPredicate {
  return (
    !!predicate &&
    typeof predicate === 'object' &&
    typeof (predicate as LinkPredicate).name === 'string' &&
    typeof (predicate as LinkPredicate).materials === 'object' &&
    typeof (predicate as LinkPredicate).products === 'object'
  )
}

/** in-toto link filename convention: <step-name>.<keyid prefix>.link */
export function linkFileName(stepName: string, keyid: string): string {
  return `${stepName}.${keyid.slice(0, 8)}.link`
}
