import { spawnSync } from 'node:child_process'
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const ROOT = join(import.meta.dirname, '..')
const REGISTER = join(ROOT, 'dist', 'register.mjs')
const TMP = join(ROOT, 'test', 'tmp-hardening')

function makeApp(lock: unknown, pkgCode: string, appCode: string): string {
  const dir = join(TMP, `app-${Math.random().toString(36).slice(2, 8)}`)
  mkdirSync(join(dir, 'node_modules', 'proto-thief'), { recursive: true })
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 't', version: '1.0.0' }))
  writeFileSync(join(dir, 'capabilities.lock'), JSON.stringify(lock))
  writeFileSync(
    join(dir, 'node_modules', 'proto-thief', 'package.json'),
    JSON.stringify({ name: 'proto-thief', version: '1.0.0' }),
  )
  writeFileSync(join(dir, 'node_modules', 'proto-thief', 'index.js'), pkgCode)
  writeFileSync(join(dir, 'app.cjs'), appCode)
  return dir
}

function run(dir: string) {
  return spawnSync('node', ['--import', REGISTER, 'app.cjs'], {
    cwd: dir,
    encoding: 'utf8',
    timeout: 15_000,
  })
}

beforeAll(() => mkdirSync(TMP, { recursive: true }))
afterAll(() => rmSync(TMP, { recursive: true, force: true }))

describe('bootstrap hardening', () => {
  it('freezePrototypes blocks prototype pollution', () => {
    const dir = makeApp(
      {
        version: 1,
        hardening: { freezePrototypes: true },
        defaults: { unrecognized: 'allow' },
        packages: {},
      },
      `module.exports = () => { try { Object.defineProperty(Object.prototype, 'pwned', { value: 1, configurable: true }) } catch { return 'failed (threw)' } return ({}).pwned === 1 ? 'succeeded' : 'failed (frozen)' }`,
      `const r = require('proto-thief')(); console.log('TAMPER:' + r)`,
    )
    const res = run(dir)
    expect(res.stdout).toMatch(/TAMPER:failed/)
  })

  it('without the flag, pollution succeeds (compat default)', () => {
    const dir = makeApp(
      { version: 1, defaults: { unrecognized: 'allow' }, packages: {} },
      `module.exports = () => { try { Object.defineProperty(Object.prototype, 'pwned', { value: 1, configurable: true }) } catch { return 'failed (threw)' } const ok = ({}).pwned === 1; delete Object.prototype.pwned; return ok ? 'succeeded' : 'failed (frozen)' }`,
      `const r = require('proto-thief')(); console.log('TAMPER:' + r)`,
    )
    const res = run(dir)
    expect(res.stdout).toContain('TAMPER:succeeded')
  })

  it('CAPWALL_FREEZE_PROTOTYPES=1 env override works', () => {
    const dir = makeApp(
      { version: 1, defaults: { unrecognized: 'allow' }, packages: {} },
      `module.exports = () => { try { Object.defineProperty(Object.prototype, 'pwned', { value: 1, configurable: true }) } catch { return 'failed (threw)' } return ({}).pwned === 1 ? 'succeeded' : 'failed (frozen)' }`,
      `const r = require('proto-thief')(); console.log('TAMPER:' + r)`,
    )
    const res = spawnSync('node', ['--import', REGISTER, 'app.cjs'], {
      cwd: dir,
      encoding: 'utf8',
      timeout: 15_000,
      env: { PATH: process.env.PATH ?? '', CAPWALL_FREEZE_PROTOTYPES: '1' },
    })
    expect(res.stdout).toMatch(/TAMPER:failed/)
  })
})

describe('stack attribution survives prepareStackTrace poisoning', () => {
  it('env read still attributed + blocked after a package replaces Error.prepareStackTrace', () => {
    const dir = makeApp(
      {
        version: 1,
        defaults: { unrecognized: 'allow' },
        packages: { 'proto-thief@1.0.0': { capabilities: [] } },
      },
      `// poison stack formatting, then read env — attribution must still catch us
Error.prepareStackTrace = () => 'at NothingToSeeHere (/nowhere/x.js:1:1)'
module.exports = () => process.env.SECRET`,
      `try { require('proto-thief')(); console.log('NOT-BLOCKED') } catch (e) { console.log('THROWN:' + e.code) }`,
    )
    const res = run(dir)
    expect(res.stdout).toContain('THROWN:ERR_CAPWALL_CAPABILITY_DENIED')
  })
})

describe('deep primordials freeze (SES-style)', () => {
  const deepPayload = `module.exports = () => {
    const results = []
    try { Array.prototype.evil = 1 } catch { /* strict */ }
    try { String.prototype.evil = 1 } catch { /* strict */ }
    try { Object.defineProperty(Function.prototype, 'evil', { value: 1 }) } catch { /* throws */ }
    results.push('array:' + ([].evil === undefined ? 'frozen' : 'polluted'))
    results.push('string:' + (''.evil === undefined ? 'frozen' : 'polluted'))
    results.push('function:' + (typeof (() => {}).evil === 'undefined' ? 'frozen' : 'polluted'))
    try { delete Array.prototype.evil; delete String.prototype.evil } catch { /* noop */ }
    return results.join('|')
  }`
  const appCode = `console.log('DEEP:' + require('proto-thief')())`

  it('freezePrimordials locks Array/String/Function prototypes', () => {
    const dir = makeApp(
      { version: 1, hardening: { freezePrimordials: true }, defaults: { unrecognized: 'allow' }, packages: {} },
      deepPayload, appCode,
    )
    const res = run(dir)
    expect(res.stdout).toContain('DEEP:array:frozen|string:frozen|function:frozen')
  })

  it('without the flag, prototypes remain mutable (compat default)', () => {
    const dir = makeApp(
      { version: 1, defaults: { unrecognized: 'allow' }, packages: {} },
      deepPayload, appCode,
    )
    const res = run(dir)
    expect(res.stdout).toContain('DEEP:array:polluted|string:polluted|function:polluted')
  })

  it('apps still run normally under the deep freeze', () => {
    const dir = makeApp(
      { version: 1, hardening: { freezePrimordials: true }, defaults: { unrecognized: 'allow' }, packages: {} },
      `module.exports = () => [1,2,3].map(String).join('-') + JSON.stringify({ok:true})`,
      `console.log('WORKS:' + require('proto-thief')())`,
    )
    const res = run(dir)
    expect(res.status).toBe(0)
    expect(res.stdout).toContain('WORKS:1-2-3{"ok":true}')
  })
})


describe('§3 gap-closer: ESM child_process namespace shim', () => {
  it('granted ESM import gets the gadget-sanitized namespace', () => {
    const dir = makeApp(
      { version: 1, defaults: { unrecognized: 'warn' }, packages: { 'proto-thief@1.0.0': { capabilities: ['child_process', 'fs.read', 'fs.write', 'env.read'] } } }, // env.read: Node's spawn internals read COMMAND_MODE on darwin
      `module.exports.probe = async (out) => { const cp = await import('node:child_process'); const fs = require('node:fs'); fs.writeFileSync(out, JSON.stringify({ spawn: typeof cp.default.spawn, ok: cp.default.spawnSync(process.execPath, ['-e', 'process.exit(0)'], { cwd: require('node:os').tmpdir() }).status })) }`,
      `require('proto-thief').probe(process.env.OUT_FILE).catch((e) => { console.log('PROBE-ERR:' + e.message.slice(0, 60)) })`,
    )
    const out = join(TMP, 'esm-cp.json')
    const res = spawnSync('node', ['--import', REGISTER, 'app.cjs'], {
      cwd: dir,
      encoding: 'utf8',
      timeout: 15000,
      env: { PATH: process.env.PATH ?? '', OUT_FILE: out },
    })
    expect(res.status).toBe(0)
    const parsed = JSON.parse(readFileSync(out, 'utf8'))
    expect(parsed.spawn).toBe('function')
    expect(parsed.ok).toBe(0)
  })
})
