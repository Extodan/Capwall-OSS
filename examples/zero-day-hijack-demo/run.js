// 5-attack demo: unprotected run vs capwall-walled run, ANSI verdict table.
const { spawnSync } = require('node:child_process')
const fs = require('node:fs')
const GREEN = (s) => `\x1b[32m${s}\x1b[0m`, RED = (s) => `\x1b[31m${s}\x1b[0m`, BOLD = (s) => `\x1b[1m${s}\x1b[0m`, DIM = (s) => `\x1b[2m${s}\x1b[0m`
const CLI = ['npx', '--yes', '@extodan/capwall']

fs.writeFileSync('app.tmp.js', `const evil = require('evil-color-logger')
console.log('app output:', evil.colorize('still works'))
setTimeout(() => process.exit(0), 800)`)

const npx = (args, env = {}) => spawnSync('npx', ['--yes', '@extodan/capwall', ...args], { encoding: 'utf8', env: { ...process.env, ...env }, timeout: 60000 })

// --- run the app twice: naked, then walled
console.log(BOLD('\n── run 1: standard node (no protection)'))
const raw = npx(['run', '--', 'node', 'app.tmp.js'], { STRIPE_SECRET_KEY: 'sk_live-demo-not-a-real-key-999' })
console.log((raw.stdout || '').trim(), DIM((raw.stderr || '').trim().split('\n').slice(0, 1).join('')))

console.log(BOLD('\n── run 2: under capwall (zero-trust lock + frozen prototypes)'))
fs.writeFileSync('capabilities.lock', JSON.stringify({
  version: 1, defaults: { unrecognized: 'warn' },
  hardening: { freezePrototypes: true, importGraph: 'strict' },
  packages: { 'evil-color-logger@3.1.4': { capabilities: [], notes: 'explicitly revoked' } },
}, null, 2))
const walled = npx(['run', '--', 'node', 'app.tmp.js'], { STRIPE_SECRET_KEY: 'sk_live-demo-not-a-real-key-999' })
const out = `${walled.stdout || ''}\n${walled.stderr || ''}`

// --- attack 5: MCP-ITP scan of the poisoned tools document
const mcp = spawnSync('node', [`${__dirname}/../../packages/cli/dist/cli.mjs`, 'mcp', 'scan', 'poisoned-mcp-tools.json'], { encoding: 'utf8' })

const vectors = /VECTORS (\{.*\})/.exec(out)?.[1]
const v = vectors ? JSON.parse(vectors) : {}
const blocked = (s) => /BLOCKED|THREW|FROZEN-OUT/.test(s)
const rows = [
  ['1  direct secret theft (process.env.STRIPE_SECRET_KEY)', v.v1 ? blocked(v.v1) || v.v1.startsWith('LEAKED') === false : /env\.read/.test(out), v.v1, 'env.read'],
  ['2  async-context evasion (setTimeout → fetch exfil)', v.v2 ? blocked(v.v2) : false, v.v2, 'http.request'],
  ['3  GHunter prototype gadget (Object.prototype.shell)', v.v3 ? blocked(v.v3) : false, v.v3, 'hardening'],
  ['4  NodeShield lateral import (undeclared child_process)', v.v4 ? blocked(v.v4) : /child_process/.test(out), v.v4, 'import edge'],
  ['5  MCP-ITP poisoned tools/list (~/.ssh coercion)', /native tool|sensitive path|sequencing/.test(mcp.stdout + (mcp.stderr || '')), '', 'ITP scan'],
]
const verdict = (ok) => (ok ? ['BLOCKED', GREEN] : ['MISSED', RED])

console.log(BOLD('\n┌─ 5 attacks vs capwall ' + '─'.repeat(34) + '┐'))
for (const [label, ok, evidence, gate] of rows) {
  const [v, color] = verdict(ok)
  console.log(`│ ${label.padEnd(56)} │ ${color(v.padEnd(8))} │ ${DIM(gate)} ${DIM(evidence ? '· ' + evidence.slice(0, 12) : '')}`)
}
console.log(BOLD('└' + '─'.repeat(60) + '┘'))
console.log(DIM('\nraw walled output (abridged):'))
console.log(DIM(out.trim().split('\n').filter((l) => /BLOCK|blocked|frozen|grant|output/.test(l)).slice(0, 8).join('\n')))
console.log(DIM('\nmcp scan: ' + (mcp.stdout || mcp.stderr).trim().split('\n').slice(0, 3).join(' | ')))
