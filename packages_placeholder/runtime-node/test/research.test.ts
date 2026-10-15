import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { sanitizeGadgetOptions } from '../src/gadgets.js'

const ROOT = join(import.meta.dirname, '..')
const REGISTER = join(ROOT, 'dist', 'register.mjs')
const TMP = join(ROOT, 'test', 'tmp-research')

beforeAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  mkdirSync(join(TMP, 'node_modules', 'leftpad', 'node_modules'), { recursive: true })
  mkdirSync(join(TMP, 'node_modules', 'axios'), { recursive: true })
  writeFileSync(join(TMP, 'package.json'), JSON.stringify({ name: 't', version: '1.0.0' }))
  writeFileSync(
    join(TMP, 'capabilities.lock'),
    JSON.stringify({
      version: 1,
      hardening: { importGraph: 'strict' },
      defaults: { unrecognized: 'warn' },
      packages: {
        'leftpad@1.0.0': { capabilities: ['http.request'], deps: [], notes: 'zero-trust import set' },
        'axios@1.0.0': { capabilities: ['http.request'] },
      },
    }),
  )
  writeFileSync(join(TMP, 'node_modules', 'leftpad', 'package.json'), JSON.stringify({ name: 'leftpad', version: '1.0.0' }))
  writeFileSync(join(TMP, 'node_modules', 'leftpad', 'index.js'), `const ax = require('axios'); module.exports = () => typeof ax.get`)
  writeFileSync(join(TMP, 'node_modules', 'axios', 'package.json'), JSON.stringify({ name: 'axios', version: '1.0.0' }))
  writeFileSync(join(TMP, 'node_modules', 'axios', 'index.js'), `module.exports = { get: () => 1 }`)
  writeFileSync(
    join(TMP, 'app.cjs'),
    `try { require('leftpad')(); console.log('LATERAL-OK') } catch (e) { console.log('LATERAL-BLOCKED:' + e.code) }`,
  )
})
afterAll(() => rmSync(TMP, { recursive: true, force: true }))

describe('§2 NodeShield lateral import graph', () => {
  it('strict mode blocks a package importing an authorized sibling', () => {
    const res = spawnSync('node', ['--import', REGISTER, 'app.cjs'], { cwd: TMP, encoding: 'utf8', timeout: 15000 })
    expect(res.stdout).toContain('LATERAL-BLOCKED:ERR_CAPWALL_CAPABILITY_DENIED')
  })
})

describe('§3 GHunter gadget sanitizer', () => {
  it('null-prototype clone strips inherited gadget properties', () => {
    try {
      Object.defineProperty(Object.prototype, 'shell', { value: '/bin/pwned', configurable: true })
      const tainted = { cwd: '/tmp' }
      const clean = sanitizeGadgetOptions(tainted)
      expect(Object.getPrototypeOf(clean)).toBeNull()
      expect((clean as Record<string, unknown>).cwd).toBe('/tmp')
      expect((clean as Record<string, unknown>).shell).toBeUndefined()
    } finally {
      delete Object.prototype.shell
    }
  })
  it('preserves own value and skips accessors conservatively', () => {
    const withGetter = { a: 1 }
    Object.defineProperty(withGetter, 'g', { get: () => 2, configurable: true })
    const clean = sanitizeGadgetOptions(withGetter)
    expect(clean.a).toBe(1)
    expect('g' in clean).toBe(false) // accessor dropped, not invoked
  })
})
