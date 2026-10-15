import type { Capability } from './capabilities.js'

/**
 * Transparent, additive risk model.
 * Each triggered factor contributes a fixed weight; the package score is the
 * clamped sum (0–100). Weights are data, not magic — surfaced in the dashboard
 * so users can argue with them.
 */

export const RISK_FACTOR_IDS = [
  'dynamic-evasion',
  'child_process',
  'dynamic-code',
  'env-access',
  'obfuscation',
  'install-scripts',
  'network-capability',
  'network-library',
  'stale',
  'no-repository',
  'deprecated',
] as const

export type RiskFactorId = (typeof RISK_FACTOR_IDS)[number]

export interface RiskFactorInfo {
  label: string
  description: string
  weight: number
}

export const RISK_FACTORS: Record<RiskFactorId, RiskFactorInfo> = {
  'dynamic-evasion': {
    label: 'Dynamic capability evasion',
    description: 'Computed/reflective access to capability root objects (globalThis/process/require) — statically unsound, flagged per Defensive Capability Analysis.',
    weight: 45,
  },
  child_process: {
    label: 'Spawns child processes',
    description: 'Code paths that execute shell commands or binaries.',
    weight: 35,
  },
  'dynamic-code': {
    label: 'Evaluates dynamic code',
    description: 'Uses eval, new Function, or the vm module to run generated code.',
    weight: 30,
  },
  'env-access': {
    label: 'Reads environment variables',
    description: 'Accesses process.env — where secrets, tokens and keys live.',
    weight: 20,
  },
  obfuscation: {
    label: 'Obfuscated payloads',
    description: 'Long base64/hex blobs or string-decoding loops — rare in benign packages.',
    weight: 40,
  },
  'install-scripts': {
    label: 'Runs install scripts',
    description: 'preinstall/install/postinstall hooks execute code on your machine at npm install time.',
    weight: 15,
  },
  'network-capability': {
    label: 'Network capability',
    description: 'Imports net/http/dns builtins directly.',
    weight: 10,
  },
  'network-library': {
    label: 'Uses a network library',
    description: 'Imports axios, node-fetch, got, request or similar HTTP clients.',
    weight: 10,
  },
  stale: {
    label: 'Not published in 2+ years',
    description: 'Last publish is older than two years.',
    weight: 10,
  },
  'no-repository': {
    label: 'No source repository',
    description: 'Package metadata links no repository — nothing to audit.',
    weight: 10,
  },
  deprecated: {
    label: 'Deprecated',
    description: 'Marked deprecated in the npm registry.',
    weight: 50,
  },
}

export interface RiskFactor {
  id: RiskFactorId
  /** Optional evidence detail, e.g. "process.env accessed in lib/pay.js" */
  detail?: string
}

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'

export const RISK_LEVELS: Record<RiskLevel, { label: string; max: number }> = {
  low: { label: 'Low', max: 19 },
  medium: { label: 'Medium', max: 44 },
  high: { label: 'High', max: 69 },
  critical: { label: 'Critical', max: 100 },
}

export function riskScore(factors: RiskFactor[]): number {
  let score = 0
  for (const f of factors) {
    const info = RISK_FACTORS[f.id]
    if (info) score += info.weight
  }
  return Math.max(0, Math.min(100, score))
}

export function riskLevel(score: number): RiskLevel {
  if (score <= RISK_LEVELS.low.max) return 'low'
  if (score <= RISK_LEVELS.medium.max) return 'medium'
  if (score <= RISK_LEVELS.high.max) return 'high'
  return 'critical'
}

/** Map raw detected capabilities to risk factors (used by scanner). */
export function factorsForCapabilities(caps: Capability[]): RiskFactor[] {
  const factors: RiskFactor[] = []
  if (caps.includes('child_process')) factors.push({ id: 'child_process' })
  if (caps.includes('dynamic-code')) factors.push({ id: 'dynamic-code' })
  if (caps.includes('env.read') || caps.includes('env.write')) factors.push({ id: 'env-access' })
  if (
    caps.includes('net.connect') ||
    caps.includes('net.listen') ||
    caps.includes('http.request') ||
    caps.includes('dns.resolve')
  ) {
    factors.push({ id: 'network-capability' })
  }
  return factors
}
