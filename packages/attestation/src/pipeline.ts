import type { Capability, ScanReport, ViolationEvent } from '@capwall/core'
import { signEnvelope, type Envelope } from './dsse.js'
import { createLayout, type Layout, type LayoutStep } from './layout.js'
import { parseRule, type Rule } from './rules.js'
import { linkStatement, RBOM_PREDICATE_TYPE, SBOM_PREDICATE_TYPE, type DigestMap, type Statement } from './statement.js'
import type { KeyPair } from './keys.js'

/**
 * The Capwall supply chain: git checkout ➔ AST capability scan ➔ build ➔ runtime
 * enforcement. The artifact-rule spine guarantees the capabilities.lock produced
 * by the scanner is the *bit-identical* file enforced in production.
 */

export const STEP_GIT_CHECKOUT = 'step_git_checkout'
export const STEP_AST_CAPABILITY_SCAN = 'step_ast_capability_scan'
export const STEP_BUILD_PACKAGE = 'step_build_package'
export const STEP_RUNTIME_ENFORCEMENT = 'step_runtime_enforcement'

export const CAPWALL_STEPS = [
  STEP_GIT_CHECKOUT,
  STEP_AST_CAPABILITY_SCAN,
  STEP_BUILD_PACKAGE,
  STEP_RUNTIME_ENFORCEMENT,
] as const

export const DEFAULT_RULES: Record<(typeof CAPWALL_STEPS)[number], Rule[]> = {
  [STEP_GIT_CHECKOUT]: [parseRule('ALLOW *')],
  [STEP_AST_CAPABILITY_SCAN]: [
    parseRule('MATCH package.json WITH PRODUCTS FROM step_git_checkout'),
    parseRule('CREATE capabilities.lock'),
    parseRule('ALLOW *'),
  ],
  [STEP_BUILD_PACKAGE]: [
    parseRule('MATCH capabilities.lock WITH PRODUCTS FROM step_ast_capability_scan'),
    parseRule('ALLOW *'),
  ],
  [STEP_RUNTIME_ENFORCEMENT]: [
    parseRule('MATCH capabilities.lock WITH PRODUCTS FROM step_ast_capability_scan'),
    parseRule('ALLOW *'),
  ],
}

export interface FunctionaryAssignment {
  /** Developer passkey — signs the git checkout step. */
  developer: KeyPair
  /** CI runner key — signs AST scan + build steps. */
  ci: KeyPair
  /** Production runtime node key — signs runtime enforcement (RBOM). */
  runtime: KeyPair
}

export function capwallLayoutSteps(rules: Record<string, Rule[]> = DEFAULT_RULES): LayoutStep[] {
  return [
    { name: STEP_GIT_CHECKOUT, expectedCommand: ['git', 'checkout'], authorizedKeyids: [], artifactRules: rules[STEP_GIT_CHECKOUT] ?? [] },
    { name: STEP_AST_CAPABILITY_SCAN, expectedCommand: ['capwall', 'scan'], authorizedKeyids: [], artifactRules: rules[STEP_AST_CAPABILITY_SCAN] ?? [] },
    { name: STEP_BUILD_PACKAGE, expectedCommand: ['npm', 'run', 'build'], authorizedKeyids: [], artifactRules: rules[STEP_BUILD_PACKAGE] ?? [] },
    { name: STEP_RUNTIME_ENFORCEMENT, expectedCommand: ['node', '--import', '@capwall/runtime-node'], authorizedKeyids: [], artifactRules: rules[STEP_RUNTIME_ENFORCEMENT] ?? [] },
  ]
}

/** Build the signed root layout binding functionary keys to Capwall steps. */
export function createCapwallLayout(
  functionaries: FunctionaryAssignment,
  rootSigner: KeyPair,
  options: { expires?: Date | string; rules?: Record<string, Rule[]>; readme?: string } = {},
): { layout: Layout; envelope: Envelope } {
  const rules = options.rules ?? DEFAULT_RULES
  const steps = capwallLayoutSteps(rules).map((step) => {
    const key =
      step.name === STEP_GIT_CHECKOUT
        ? functionaries.developer
        : step.name === STEP_RUNTIME_ENFORCEMENT
          ? functionaries.runtime
          : functionaries.ci
    return { ...step, authorizedKeyids: [key.keyid] }
  })
  return createLayout(
    { steps, functionaries: [functionaries.developer, functionaries.ci, functionaries.runtime], expires: options.expires, readme: options.readme },
    rootSigner,
  )
}

/** Sign one step's link (DSSE envelope around an in-toto Statement). */
export function emitLink(
  stepName: string,
  input: {
    command?: string[]
    materials?: DigestMap
    products?: DigestMap
    byproducts?: Record<string, unknown>
    environment?: Record<string, unknown>
  },
  signer: KeyPair,
): Envelope {
  return signEnvelope(linkStatement(stepName, input), signer)
}

/* ---------------- SBOM & RBOM predicates ---------------- */

export interface SbomPackageEntry {
  name: string
  version: string
  capabilities: Capability[]
  score: number
}

/** Build-time SBOM predicate: what the dependency tree *is allowed* to do. */
export function sbomPredicate(report: ScanReport): Record<string, unknown> {
  return {
    _type: SBOM_PREDICATE_TYPE,
    root: report.root,
    packages: report.packages.map<SbomPackageEntry>((p) => ({
      name: p.name,
      version: p.version,
      capabilities: p.capabilities,
      score: p.score,
    })),
    totals: report.totals,
  }
}

/** RWXi taxonomy: R(ead), W(rite), X(ecute), i(nternet). */
export type Rwxi = 'R' | 'W' | 'X' | 'i'

const RWXI_MAP: Record<Capability, Rwxi> = {
  'env.read': 'R',
  'fs.read': 'R',
  'env.write': 'W',
  'fs.write': 'W',
  'net.listen': 'W',
  child_process: 'X',
  'dynamic-code': 'X',
  worker_threads: 'X',
  'http.request': 'i',
  'net.connect': 'i',
  'dns.resolve': 'i',
}

export function toRwxi(capability: Capability): Rwxi {
  return RWXI_MAP[capability] ?? 'R'
}

export interface RuntimeTelemetry {
  /** Every package that actually loaded into memory. */
  loadedPackages: string[]
  /** Capabilities actually exercised at runtime, per package (RWXi buckets). */
  exercised: Record<string, Partial<Record<Rwxi, Capability[]>>>
  /** Blocked + warned violations observed by the hook. */
  violations: ViolationEvent[]
  /** SHA-256 of the capabilities.lock the runtime enforced. */
  lockDigest?: string
}

/** Runtime RBOM predicate: what the dependency tree *actually did* in production. */
export function rbomPredicate(telemetry: RuntimeTelemetry): Record<string, unknown> {
  return {
    _type: RBOM_PREDICATE_TYPE,
    loadedPackages: telemetry.loadedPackages,
    exercised: telemetry.exercised,
    violations: telemetry.violations,
    lockDigest: telemetry.lockDigest,
  }
}

/** Statement for a scan step, carrying the SBOM as byproduct. */
export function scanStepStatement(report: ScanReport, materials: DigestMap, products: DigestMap): Statement {
  return linkStatement(STEP_AST_CAPABILITY_SCAN, {
    command: ['capwall', 'scan'],
    materials,
    products,
    byproducts: { scanReport: sbomPredicate(report) },
  })
}

/** Statement for the runtime step, carrying the RBOM as byproduct/environment. */
export function runtimeStepStatement(telemetry: RuntimeTelemetry, materials: DigestMap): Statement {
  return linkStatement(STEP_RUNTIME_ENFORCEMENT, {
    command: ['node', '--import', '@capwall/runtime-node'],
    materials,
    products: {},
    byproducts: { rbom: rbomPredicate(telemetry) },
    environment: {
      node: process.version,
      exercisedCapabilities: telemetry.exercised,
      violationsBlocked: telemetry.violations.filter((v) => v.action === 'blocked').length,
    },
  })
}
