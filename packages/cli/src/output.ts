import picocolors from 'picocolors'
import { CAPABILITY_INFO, RISK_FACTORS, type PackageReport, type ScanReport } from '@capwall/core'

const LEVEL_COLOR: Record<PackageReport['level'], (s: string) => string> = {
  low: picocolors.green,
  medium: picocolors.yellow,
  high: picocolors.red,
  critical: picocolors.bgRed,
}

function riskBar(score: number): string {
  const filled = Math.round((score / 100) * 10)
  return `${picocolors.dim('[')}${'█'.repeat(filled)}${picocolors.dim('·'.repeat(10 - filled))}${picocolors.dim(']')}`
}

export function printScanReport(report: ScanReport, verbose = false): void {
  const root = report.root
  console.log(`\n${picocolors.bold(`${root.name}@${root.version}`)}${picocolors.dim(` — ${report.totals.packages} packages scanned`)}`)

  if (report.packages.length === 0) {
    console.log(picocolors.dim('  no dependencies found'))
    return
  }

  for (const pkg of report.packages) {
    const color = LEVEL_COLOR[pkg.level]
    const caps = pkg.capabilities.length
      ? pkg.capabilities.map((c) => picocolors.cyan(c)).join(' ')
      : picocolors.dim('no sensitive capabilities')
    console.log(
      `  ${color(pkg.level.toUpperCase().padEnd(8))} ${String(pkg.score).padStart(3)} ${riskBar(pkg.score)} ${picocolors.bold(pkg.name)}${picocolors.dim(`@${pkg.version}`)}${pkg.depth > 0 ? picocolors.dim(` (depth ${pkg.depth})`) : ''}`,
    )
    console.log(`           ${caps}`)
    if (pkg.riskFactors.length > 0) {
      const factors = pkg.riskFactors
        .map((f) => `${RISK_FACTORS[f.id].label}${f.detail ? picocolors.dim(` (${f.detail})`) : ''}`)
        .join(' · ')
      console.log(`           ${picocolors.yellow('⚠')}  ${factors}`)
    }
    if (verbose) {
      if (pkg.signals.length) {
        console.log(`           ${picocolors.dim(pkg.signals.join(' · '))}`)
      }
      if (pkg.meta) {
        const bits = [
          pkg.meta.weeklyDownloads != null ? `${pkg.meta.weeklyDownloads.toLocaleString()}/wk` : null,
          pkg.meta.maintainersCount != null ? `${pkg.meta.maintainersCount} maintainers` : null,
          pkg.meta.lastPublished ? `published ${pkg.meta.lastPublished.slice(0, 10)}` : null,
          pkg.meta.hasInstallScript ? picocolors.red('install scripts') : null,
        ].filter(Boolean)
        if (bits.length) console.log(`           ${picocolors.dim(bits.join(' · '))}`)
      }
    }
  }

  const worst = report.packages[0]
  console.log(
    `\n  ${picocolors.bold('Headline risk:')} ${LEVEL_COLOR[worst.level](worst.name)} ${riskBar(worst.score)} ${worst.score}/100\n`,
  )
}

export function printCapabilityLegend(): void {
  console.log(`\n  ${picocolors.bold('Capabilities')}`)
  for (const [cap, info] of Object.entries(CAPABILITY_INFO)) {
    console.log(`    ${picocolors.cyan(cap.padEnd(16))} ${info.label}${picocolors.dim(` — ${info.description}`)}`)
  }
  console.log()
}
