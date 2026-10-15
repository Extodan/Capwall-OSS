import { spawnSync } from 'node:child_process'
import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const ROOT = join(import.meta.dirname, '..')
const REGISTER = join(ROOT, 'dist', 'register.mjs')
const TMP = join(ROOT, 'test', 'tmp-first')

// a foreign preload that grabs pristine references BEFORE capwall installs
const EVIL_PRELOAD = `
const rawEnv = process.env            // pristine reference, pre-proxy
globalThis.__evil = { rawEnv }
`

beforeAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  mkdirSync(TMP, { recursive: true })
  writeFileSync(join(TMP, 'package.json'), JSON.stringify({ name: 't', version: '1.0.0' }))
  writeFileSync(
    join(TMP, 'capabilities.lock'),
    JSON.stringify({ version: 1, defaults: { unrecognized: 'warn' }, packages: {} }),
  )
  writeFileSync(join(TMP, 'preload.js'), EVIL_PRELOAD)
  writeFileSync(join(TMP, 'app.cjs'), "console.log('app-ok', !!globalThis.__evil)")
})

afterAll(() => rmSync(TMP, { recursive: true, force: true }))

function run(extraArgs: string[], env: Record<string, string> = {}) {
  return spawnSync('node', [...extraArgs, '--import', REGISTER, 'app.cjs'], {
    cwd: TMP,
    encoding: 'utf8',
    timeout: 15_000,
    env: { PATH: process.env.PATH ?? '', ...env },
  })
}

describe('first-loader guarantee', () => {
  it('clean run: capwall is first, no warning', () => {
    const res = run([])
    expect(res.status).toBe(0)
    expect(res.stdout).toContain('app-ok')
    expect(res.stderr).not.toContain('not the first loader')
  })

  it('foreign --require preload: warns that enforcement may be bypassable', () => {
    const res = run(['--require', './preload.js'])
    expect(res.status).toBe(0)
    expect(res.stdout).toContain('app-ok true') // the capture happened
    expect(res.stderr).toContain('not the first loader')
    expect(res.stderr).toContain('foreign preload flag')
  })

  it('CAPWALL_REQUIRE_FIRST=1 fails closed (exit 78) when not first', () => {
    const res = run(['--require', './preload.js'], { CAPWALL_REQUIRE_FIRST: '1' })
    expect(res.status).toBe(78)
    expect(res.stderr).toContain('refusing to run')
  })

  it('strict mode still allows a clean first run', () => {
    const res = run([], { CAPWALL_REQUIRE_FIRST: '1' })
    expect(res.status).toBe(0)
    expect(res.stdout).toContain('app-ok')
  })
})
