import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import {
  riskLevel,
  riskScore,
  factorsForCapabilities,
  type PackageReport,
  type ScanReport,
} from '@capwall/core'
import { analyzeSource, mergeFindings } from './ast.js'
import { buildReport, type ManifestInput } from './analyze.js'

const MAX_FILES_PER_PACKAGE = 400
const SKIP_DIRS = new Set(['node_modules', '.git', 'test', 'tests', '__tests__', 'coverage', 'docs', 'examples'])

function isScoped(name: string): boolean {
  return name.startsWith('@')
}

function readJsonSafe(path: string): any {
  try {
    return JSON.parse(readFileSync(path, 'utf8'))
  } catch {
    return undefined
  }
}

function collectJsFiles(dir: string, budget: { left: number }, out: string[] = []): string[] {
  if (budget.left <= 0) return out
  let entries: string[]
  try {
    entries = readdirSync(dir)
  } catch {
    return out
  }
  for (const entry of entries) {
    if (budget.left <= 0) break
    const full = join(dir, entry)
    let st
    try {
      st = statSync(full)
    } catch {
      continue
    }
    if (st.isDirectory()) {
      if (!SKIP_DIRS.has(entry)) collectJsFiles(full, budget, out)
    } else if (/\.(js|cjs|mjs)$/i.test(entry)) {
      budget.left--
      out.push(full)
    }
  }
  return out
}

function scanPackageDir(name: string, version: string, depth: number, dir: string): PackageReport {
  const pkgJson = readJsonSafe(join(dir, 'package.json')) ?? {}
  const files = collectJsFiles(dir, { left: MAX_FILES_PER_PACKAGE })
  const findings = mergeFindings(
    files.map((f) => {
      try {
        return analyzeSource(readFileSync(f, 'utf8'))
      } catch {
        return { capabilities: new Set(), envVars: new Set(), signals: [], escapes: [], parseErrors: 0 }
      }
    }),
  )

  const factors = [...factorsForCapabilities(findings.capabilities), ...localFactors(pkgJson, findings.signals)]
  const score = riskScore(factors)
  const deps = Object.keys(pkgJson.dependencies ?? {})
  return {
    name,
    version: version || pkgJson.version || '0.0.0',
    capabilities: findings.capabilities,
    riskFactors: factors,
    score,
    level: riskLevel(score),
    depth,
    deps,
    meta: {
      hasInstallScript: ['preinstall', 'install', 'postinstall'].some((s) => pkgJson.scripts?.[s]),
      hasRepository: pkgJson.repository != null,
      license: typeof pkgJson.license === 'string' ? pkgJson.license : undefined,
      description: pkgJson.description,
    },
    filesScanned: findings.filesScanned,
    signals: [...findings.signals, ...findings.escapes.map((e) => `ESCAPE: ${e}`)],
  }
}

function localFactors(pkgJson: any, signals: string[]): PackageReport['riskFactors'] {
  const factors: PackageReport['riskFactors'] = []
  if (['preinstall', 'install', 'postinstall'].some((s) => pkgJson.scripts?.[s])) {
    factors.push({ id: 'install-scripts' })
  }
  if (pkgJson.repository == null) factors.push({ id: 'no-repository' })
  if (signals.some((s) => s.startsWith('obfuscated'))) factors.push({ id: 'obfuscation' })
  if (signals.some((s) => s.startsWith('uses network library'))) factors.push({ id: 'network-library' })
  return factors
}

/** List installed package dirs inside a node_modules folder (handles @scopes). */
function listPackages(nodeModulesDir: string): { name: string; dir: string }[] {
  const out: { name: string; dir: string }[] = []
  let entries: string[]
  try {
    entries = readdirSync(nodeModulesDir)
  } catch {
    return out
  }
  for (const entry of entries) {
    if (entry.startsWith('.')) continue
    const full = join(nodeModulesDir, entry)
    if (isScoped(entry)) {
      let scoped: string[]
      try {
        scoped = readdirSync(full)
      } catch {
        continue
      }
      for (const sub of scoped) {
        if (!sub.startsWith('.')) out.push({ name: `${entry}/${sub}`, dir: join(full, sub) })
      }
    } else {
      out.push({ name: entry, dir: full })
    }
  }
  return out
}

/**
 * Scan an installed project: reads node_modules on disk (fast, offline),
 * one level of nested node_modules included.
 */
export function scanLocalTree(projectDir: string, maxDepth = 1): ScanReport {
  const rootJson: ManifestInput = readJsonSafe(join(projectDir, 'package.json')) ?? {}
  const reports: PackageReport[] = []

  const walk = (dir: string, depth: number) => {
    if (depth > maxDepth) return
    for (const { name, dir: pkgDir } of listPackages(join(dir, 'node_modules'))) {
      if (reports.some((r) => r.name === name)) continue
      reports.push(scanPackageDir(name, '', depth, pkgDir))
      walk(pkgDir, depth + 1) // nested installs under this package
    }
  }
  walk(projectDir, 0)

  const seen = new Set(reports.map((r) => r.name))
  const declared = Object.keys(rootJson.dependencies ?? {})
  // Direct deps not installed locally still appear (depth 0, unscanned) so the graph is complete.
  for (const name of declared) {
    if (!seen.has(name)) {
      const score = 0
      reports.push({
        name,
        version: 'not-installed',
        capabilities: [],
        riskFactors: [],
        score,
        level: riskLevel(score),
        depth: 0,
        deps: [],
        signals: [],
      })
    }
  }

  return buildReport({
    source: { kind: 'directory', ref: projectDir, name: rootJson.name },
    root: { name: rootJson.name ?? 'your-project', version: rootJson.version ?? '0.0.0' },
    packages: reports.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name)),
  })
}
