import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { scanLocalTree } from '../src/local.js'

const projectDir = join(import.meta.dirname, 'fixtures', 'project')

describe('scanLocalTree', () => {
  const report = scanLocalTree(projectDir)

  it('finds direct, scoped, and nested packages', () => {
    const names = report.packages.map((p) => p.name)
    expect(names).toContain('leftpad')
    expect(names).toContain('@scope/util')
    expect(names).toContain('dep-inner')
  })

  it('attributes capabilities per package', () => {
    const byName = Object.fromEntries(report.packages.map((p) => [p.name, p]))
    expect(byName.leftpad?.capabilities).toEqual(['child_process', 'env.read'])
    expect(byName.leftpad?.depth).toBe(0)
    expect(byName['@scope/util']?.capabilities).toContain('fs.read')
    expect(byName['@scope/util']?.capabilities).toContain('http.request')
    expect(byName['dep-inner']?.capabilities).toEqual(['dynamic-code'])
    expect(byName['dep-inner']?.depth).toBe(1)
  })

  it('collects risk factors from metadata', () => {
    const leftpad = report.packages.find((p) => p.name === 'leftpad')
    expect(leftpad?.riskFactors.map((f) => f.id)).toContain('install-scripts')
    expect(leftpad?.score).toBeGreaterThan(0)
  })

  it('tracks dependency edges', () => {
    const leftpad = report.packages.find((p) => p.name === 'leftpad')
    expect(leftpad?.deps).toEqual(['dep-inner'])
  })

  it('builds totals', () => {
    expect(report.totals.packages).toBe(3)
    expect(report.totals.byCapability.child_process).toBe(1)
    expect(report.root.name).toBe('fixture-app')
    expect(report.source.kind).toBe('directory')
  })

  it('marks declared-but-missing deps as not-installed', () => {
    const report2 = scanLocalTree(join(projectDir, 'missing-deps-tmp'))
    // directory without node_modules at all
    expect(report2.packages).toEqual([])
  })
})
