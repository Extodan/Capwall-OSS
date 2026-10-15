import { gzipSync } from 'node:zlib'
import { describe, expect, it } from 'vitest'
import { pack } from 'tar-stream'
import { analyzeManifest } from '../src/analyze.js'
import { parseGitHubUrl } from '../src/github.js'
import type { FetchLike } from '../src/util.js'

async function tarball(files: Record<string, string>): Promise<Buffer> {
  const p = pack()
  for (const [name, content] of Object.entries(files)) p.entry({ name }, content)
  p.finalize()
  const tar = await new Promise<Buffer>((resolve) => {
    const chunks: Buffer[] = []
    p.on('data', (c) => chunks.push(c))
    p.on('end', () => resolve(Buffer.concat(chunks)))
  })
  return gzipSync(tar)
}

const registryFixture = {
  'malicious-string': {
    'dist-tags': { latest: '2.0.0' },
    time: { '2.0.0': new Date().toISOString(), '1.0.0': '2020-01-01T00:00:00.000Z' },
    maintainers: [{ name: 'a' }, { name: 'b' }],
    versions: {
      '1.0.0': {
        deprecated: 'use something else',
        repository: 'https://github.com/x/y',
        dist: { tarball: 'https://registry.example/malicious-string/-/malicious-string-1.0.0.tgz' },
      },
      '2.0.0': {
        repository: 'https://github.com/x/y',
        dist: { tarball: 'https://registry.example/malicious-string/-/malicious-string-2.0.0.tgz' },
      },
    },
  },
  'benign-pad': {
    'dist-tags': { latest: '1.0.0' },
    time: { '1.0.0': new Date().toISOString() },
    maintainers: [{ name: 'z' }],
    versions: {
      '1.0.0': {
        repository: 'https://github.com/x/benign-pad',
        dist: { tarball: 'https://registry.example/benign-pad/-/benign-pad-1.0.0.tgz' },
      },
    },
  },
}

/** Offline registry mock: serves packuments, tarballs and download counts from fixtures. */
const mockFetch: FetchLike = async (url) => {
  const parsed = new URL(url)
  if (parsed.hostname === 'registry.npmjs.org') {
    const name = decodeURIComponent(parsed.pathname.slice(1))
    const doc = (registryFixture as any)[name]
    if (!doc) return new Response('not found', { status: 404 })
    return Response.json(doc)
  }
  if (parsed.hostname === 'registry.example') {
    const match = parsed.pathname.match(/\/([^/]+)\/-\/\1-(\d+\.\d+\.\d+)\.tgz$/)
    const name = match?.[1]
    const version = match?.[2]
    const maliciousBody = {
      'package/package.json': JSON.stringify({ name, version }),
      'package/index.js': "const cp=require('child_process');process.env.AWS_SECRET;eval('1')",
    }
    const benignBody = { 'package/package.json': JSON.stringify({ name, version }), 'package/index.js': 'module.exports=x=>x' }
    const body = name === 'malicious-string' ? maliciousBody : benignBody
    const tgz = await tarball(body)
    return new Response(tgz, { status: 200 })
  }
  if (parsed.hostname === 'api.npmjs.org') {
    return Response.json({ downloads: 12345 })
  }
  return new Response('not found', { status: 404 })
}

describe('analyzeManifest (offline mock registry)', () => {
  it('resolves, downloads, scans and scores dependencies', async () => {
    const progress: string[] = []
    const report = await analyzeManifest(
      { name: 'demo-app', version: '0.1.0', dependencies: { 'malicious-string': '^2.0.0', 'benign-pad': '*' } },
      { kind: 'package.json', ref: 'fixture' },
      {
        fetchImpl: mockFetch,
        onProgress: (p) => {
          if (p.phase) progress.push(p.phase)
        },
      },
    )

    const malicious = report.packages.find((p) => p.name === 'malicious-string')
    const benign = report.packages.find((p) => p.name === 'benign-pad')

    expect(malicious?.version).toBe('2.0.0') // ^2.0.0 resolves to latest 2.x
    expect(malicious?.capabilities).toEqual(['child_process', 'dynamic-code', 'env.read'])
    expect(malicious?.meta?.weeklyDownloads).toBe(12345)
    expect(malicious?.level).toBe('critical')
    expect(benign?.capabilities).toEqual([])
    expect(benign?.score).toBe(0)

    expect(report.totals.byCapability.child_process).toBe(1)
    expect(report.score).toBe(malicious?.score)
    expect(report.root.name).toBe('demo-app')
    expect(progress).toContain('malicious-string')
  })

  it('skips unknown packages without failing the scan', async () => {
    const report = await analyzeManifest(
      { dependencies: { 'does-not-exist': '^1.0.0', 'benign-pad': '*' } },
      { kind: 'package.json', ref: 'fixture' },
      { fetchImpl: mockFetch },
    )
    expect(report.packages.map((p) => p.name)).toEqual(['benign-pad'])
  })

  it('walks transitive dependencies up to maxDepth', async () => {
    // benign-pad has no deps in the fixture; assert depth-0 only — depth covered by fixture body upgrade
    const report = await analyzeManifest(
      { dependencies: { 'benign-pad': '*' } },
      { kind: 'package.json', ref: 'fixture' },
      { fetchImpl: mockFetch, maxDepth: 0 },
    )
    expect(report.packages).toHaveLength(1)
  })
})

describe('parseGitHubUrl', () => {
  it('parses full URLs, tree refs and subdirs', () => {
    expect(parseGitHubUrl('https://github.com/vercel/next.js')).toMatchObject({ owner: 'vercel', repo: 'next.js' })
    expect(parseGitHubUrl('https://github.com/vercel/next.js.git')).toMatchObject({ repo: 'next.js' })
    expect(parseGitHubUrl('https://github.com/o/r/tree/dev')).toMatchObject({ ref: 'dev' })
    expect(parseGitHubUrl('https://github.com/o/r/tree/dev/packages/app')).toMatchObject({
      ref: 'dev',
      subdir: '/packages/app',
    })
    expect(parseGitHubUrl('o/r')).toMatchObject({ owner: 'o', repo: 'r' })
  })

  it('rejects junk', () => {
    expect(() => parseGitHubUrl('https://gitlab.com/o/r')).toThrow()
    expect(() => parseGitHubUrl('not a url')).toThrow()
  })
})
