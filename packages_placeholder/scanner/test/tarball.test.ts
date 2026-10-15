import { gzipSync } from 'node:zlib'
import { describe, expect, it } from 'vitest'
import { pack } from 'tar-stream'
import { scanTarball } from '../src/tarball.js'

async function makeTarball(files: Record<string, string>): Promise<Buffer> {
  const p = pack()
  for (const [name, content] of Object.entries(files)) {
    p.entry({ name }, content)
  }
  p.finalize()
  const chunks: Buffer[] = []
  const tar: Buffer = await new Promise((resolve) => {
    p.on('data', (c) => chunks.push(c))
    p.on('end', () => resolve(Buffer.concat(chunks)))
  })
  return gzipSync(tar)
}

describe('scanTarball', () => {
  it('extracts, parses manifest and scans JS files', async () => {
    const tgz = await makeTarball({
      'package/package.json': JSON.stringify({
        name: 'demo-pkg',
        version: '1.2.3',
        scripts: { postinstall: 'node setup.js' },
      }),
      'package/index.js': "const cp = require('child_process'); process.env.HOME",
      'package/lib/other.mjs': "import fs from 'node:fs/promises'",
      'package/README.md': '# not scanned',
    })

    const result = await scanTarball(tgz)
    expect(result.pkgJson?.name).toBe('demo-pkg')
    expect(result.filesScanned).toBe(2)
    expect(result.capabilities).toEqual(['child_process', 'env.read', 'fs.read', 'fs.write'])
  })

  it('handles gzip payloads with obfuscation signals', async () => {
    const blob = Buffer.from(Uint8Array.from({ length: 120 }, (_, i) => (i * 73 + 41) % 256)).toString('base64')
    const tgz = await makeTarball({
      'package/index.js': `const x = "${blob}"; eval(x)`,
    })
    const result = await scanTarball(tgz)
    expect(result.signals.some((s) => s.startsWith('obfuscated string literal'))).toBe(true)
    expect(result.capabilities).toContain('dynamic-code')
  })

  it('skips non-runtime directories like perf and tests', async () => {
    const digits = '0012345678901234567890'.repeat(6)
    const tgz = await makeTarball({
      'package/index.js': 'module.exports = 1',
      'package/perf/perf.js': `const x = "${digits}"; eval(x)`,
      'package/test/a.test.js': "require('child_process')",
    })
    const result = await scanTarball(tgz)
    expect(result.capabilities).toEqual([])
    expect(result.signals).toEqual([])
  })

  it('does not throw on garbage buffers', async () => {
    const result = await scanTarball(Buffer.from('not a tarball at all'))
    expect(result.pkgJson).toBeNull()
    expect(result.filesScanned).toBe(0)
  })
})
