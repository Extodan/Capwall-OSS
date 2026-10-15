import {
  factorsForCapabilities,
  riskLevel,
  riskScore,
  type PackageMeta,
  type PackageReport,
  type RiskFactor,
  type ScanProgress,
  type ScanReport,
  type ScanSource,
} from '@capwall/core'
import { NpmRegistry } from './npm.js'
import { scanTarball } from './tarball.js'
import { DEFAULT_FETCH, mapWithPool, type FetchLike } from './util.js'

export interface ManifestInput {
  name?: string
  version?: string
  dependencies?: Record<string, string>
}

export interface AnalyzeOptions {
  fetchImpl?: FetchLike
  maxDepth?: number
  maxPackages?: number
  concurrency?: number
  onProgress?: (progress: ScanProgress & { current?: string }) => void
}

const TWO_YEARS_MS = 2 * 365 * 24 * 3600 * 1000

/** Extra risk factors derived from registry metadata + scan signals. */
function metaFactors(meta: PackageMeta | undefined, signals: string[]): RiskFactor[] {
  const factors: RiskFactor[] = []
  if (meta?.hasInstallScript) factors.push({ id: 'install-scripts' })
  if (meta?.deprecated) factors.push({ id: 'deprecated' })
  if (meta?.hasRepository === false) factors.push({ id: 'no-repository' })
  if (meta?.lastPublished && Date.now() - Date.parse(meta.lastPublished) > TWO_YEARS_MS) {
    factors.push({ id: 'stale', detail: `last publish ${meta.lastPublished.slice(0, 10)}` })
  }
  if (signals.some((s) => s.startsWith('obfuscated'))) factors.push({ id: 'obfuscation' })
  if (signals.some((s) => s.startsWith('uses network library'))) factors.push({ id: 'network-library' })
  if (signals.some((s) => s.startsWith('ESCAPE:'))) factors.push({ id: 'dynamic-evasion' })
  return factors
}

export function buildPackageReport(params: {
  name: string
  version: string
  depth: number
  deps: string[]
  capabilities: PackageReport['capabilities']
  signals: string[]
  filesScanned: number
  meta?: PackageMeta
}): PackageReport {
  const factors = [
    ...factorsForCapabilities(params.capabilities),
    ...metaFactors(params.meta, params.signals),
  ]
  const score = riskScore(factors)
  return {
    name: params.name,
    version: params.version,
    capabilities: params.capabilities,
    riskFactors: factors,
    score,
    level: riskLevel(score),
    depth: params.depth,
    deps: params.deps,
    meta: params.meta,
    filesScanned: params.filesScanned,
    signals: params.signals,
  }
}

export function buildReport(params: {
  source: ScanSource
  root: { name: string; version: string }
  packages: PackageReport[]
}): ScanReport {
  const { packages } = params
  const byCapability: Partial<Record<PackageReport['capabilities'][number], number>> = {}
  let withInstallScripts = 0
  let maxScore = 0
  for (const p of packages) {
    for (const cap of p.capabilities) byCapability[cap] = (byCapability[cap] ?? 0) + 1
    if (p.meta?.hasInstallScript) withInstallScripts++
    if (p.score > maxScore) maxScore = p.score
  }
  return {
    createdAt: new Date().toISOString(),
    source: params.source,
    root: params.root,
    packages,
    totals: { packages: packages.length, byCapability, withInstallScripts, maxScore },
    score: maxScore,
  }
}

/**
 * Analyze a manifest (package.json contents) without installing anything:
 * resolve each dependency from the npm registry, fetch its tarball, AST-scan it.
 */
export async function analyzeManifest(
  pkg: ManifestInput,
  source: ScanSource,
  options: AnalyzeOptions = {},
): Promise<ScanReport> {
  const fetchImpl = options.fetchImpl ?? DEFAULT_FETCH
  const maxDepth = options.maxDepth ?? 2
  const maxPackages = options.maxPackages ?? 60
  const concurrency = options.concurrency ?? 8
  const registry = new NpmRegistry(fetchImpl)

  const root = { name: pkg.name ?? 'your-project', version: pkg.version ?? '0.0.0' }
  const reports = new Map<string, PackageReport>()
  const queue: { name: string; range: string; depth: number }[] = Object.entries(
    pkg.dependencies ?? {},
  ).map(([name, range]) => ({ name, range, depth: 0 }))
  const seen = new Set<string>()

  // Resolve + scan one dependency (recursively enqueues its own deps).
  async function scanDep(name: string, range: string, depth: number): Promise<void> {
    const report = await reportFor(name, range, depth, options, registry, fetchImpl, (child) => {
      if (child.depth <= maxDepth && seen.size < maxPackages) queue.push(child)
    })
    if (report) reports.set(name, report)
  }

  options.onProgress?.({ status: 'resolving', done: 0, total: queue.length })
  let processed = 0

  // BFS with a worker pool; the queue grows as dependencies are discovered.
  for (;;) {
    const batch = queue.splice(0, queue.length).filter((item) => {
      if (seen.has(item.name) || seen.size >= maxPackages) return false
      seen.add(item.name)
      return true
    })
    if (batch.length === 0) break

    await mapWithPool(batch, concurrency, async (item) => {
      await scanDep(item.name, item.range, item.depth)
      processed++
      options.onProgress?.({
        status: 'analyzing',
        phase: item.name,
        done: processed,
        total: processed + queue.length,
      })
    })
  }

  const packages = [...reports.values()].sort(
    (a, b) => b.score - a.score || a.name.localeCompare(b.name),
  )
  const report = buildReport({ source, root, packages })
  options.onProgress?.({ status: 'done', done: packages.length, total: packages.length })
  return report
}

async function reportFor(
  name: string,
  range: string,
  depth: number,
  options: AnalyzeOptions,
  registry: NpmRegistry,
  fetchImpl: FetchLike,
  enqueue: (child: { name: string; range: string; depth: number }) => void,
): Promise<PackageReport | null> {
  let resolved
  try {
    resolved = await registry.resolve(name, range)
  } catch {
    return null // registry hiccup — skip rather than fail the whole scan
  }
  if (!resolved) return null

  let tar
  try {
    const buffer = await registry.tarball(resolved.tarballUrl)
    tar = await scanTarball(buffer)
  } catch {
    tar = null
  }

  const capabilities = tar?.capabilities ?? []
  const escapes = tar?.escapes ?? []
  const signals = [...(tar?.signals ?? []), ...escapes.map((e) => `ESCAPE: ${e}`)]
  const deps = Object.keys(tar?.pkgJson?.dependencies ?? resolved.dependencies)

  const meta: PackageMeta = {
    ...resolved.meta,
    hasInstallScript:
      resolved.meta.hasInstallScript ??
      ['preinstall', 'install', 'postinstall'].some((s) => tar?.pkgJson?.scripts?.[s]),
  }
  // Downloads are nice-to-have; never let them break a scan.
  const downloads = await registry.weeklyDownloads(name)
  if (downloads != null) meta.weeklyDownloads = downloads

  for (const [childName, childRange] of Object.entries(resolved.dependencies)) {
    enqueue({ name: childName, range: childRange, depth: depth + 1 })
  }

  return buildPackageReport({
    name,
    version: resolved.version,
    depth,
    deps,
    capabilities,
    signals,
    filesScanned: tar?.filesScanned ?? 0,
    meta,
  })
}
