import type { Capability } from './capabilities.js'
import type { RiskFactor, RiskLevel } from './risk.js'

/** Metadata pulled from the npm registry for a scanned package. */
export interface PackageMeta {
  maintainersCount?: number
  lastPublished?: string
  deprecated?: boolean
  hasRepository?: boolean
  hasInstallScript?: boolean
  weeklyDownloads?: number
  license?: string
  description?: string
}

/** Analysis result for one package inside a scan. */
export interface PackageReport {
  name: string
  version: string
  /** Capabilities detected in the package's own code. */
  capabilities: Capability[]
  riskFactors: RiskFactor[]
  /** 0–100 composite risk score (derived from riskFactors). */
  score: number
  level: RiskLevel
  /** 0 = direct dependency of the scanned project, 1+ = transitive. */
  depth: number
  /** Dependency names, used to draw graph edges. */
  deps: string[]
  meta?: PackageMeta
  filesScanned?: number
  /** Free-form observations: obfuscation evidence, network libraries, ... */
  signals: string[]
}

export type ScanSource =
  | { kind: 'package.json'; ref: string; name?: string }
  | { kind: 'github'; ref: string; name?: string }
  | { kind: 'directory'; ref: string; name?: string }

export interface ScanTotals {
  packages: number
  byCapability: Partial<Record<Capability, number>>
  withInstallScripts: number
  maxScore: number
}

export interface ScanReport {
  id?: string
  createdAt: string
  source: ScanSource
  root: { name: string; version: string }
  packages: PackageReport[]
  totals: ScanTotals
  /** Highest package score — headline risk of this dependency tree. */
  score: number
  error?: string
}

/** A runtime violation reported by @capwall/runtime-node. */
export interface ViolationEvent {
  id: string
  ts: string
  /** Package that attempted the action, e.g. "silly-string" */
  pkg: string
  pkgVersion?: string
  capability: Capability
  /** 'import' = gated builtin import/require; 'runtime' = wrapped global (env/fetch) */
  kind: 'import' | 'runtime'
  action: 'blocked' | 'warned'
  /** What was attempted: specifier, env var name, or URL. */
  detail: string
  stack?: string
  host?: string
  cwd?: string
  node?: string
  /** True for dashboard demo events. */
  simulated?: boolean
}

/** Progress payload streamed while a scan job runs. */
export interface ScanProgress {
  status: 'queued' | 'resolving' | 'analyzing' | 'done' | 'error'
  phase?: string
  done: number
  total: number
}
