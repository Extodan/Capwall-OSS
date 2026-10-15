// Runs the app twice: unprotected, then under capwall — same code, different fate.
const { spawnSync } = require('node:child_process')
const mode = process.argv[2] ?? 'both'
const app = `const evil = require('evil-color-logger')
console.log('output:', evil.colorize('pwned'))
setTimeout(() => process.exit(0), 400)`
require('node:fs').writeFileSync('app.tmp.js', app)

const run = (label, args) => {
  console.log(`\n──────── ${label} ────────`)
  const r = spawnSync('npx', ['--yes', '@extodan/capwall', ...args], { stdio: 'inherit', env: process.env })
  return r.status
}
if (mode === 'attack' || mode === 'both') run('UNPROTECTED node', ['run', '--', 'node', 'app.tmp.js'])
if (mode === 'capwall' || mode === 'both') {
  console.log('\n── generating zero-trust capabilities.lock ──')
  run('capwall init', ['init'])
  require('node:fs').writeFileSync('capabilities.lock', JSON.stringify({
    version: 1, defaults: { unrecognized: 'warn' },
    hardening: { freezePrototypes: true },
    packages: { 'evil-color-logger@3.1.4': { capabilities: [], notes: 'explicitly revoked' } },
  }, null, 2))
  run('UNDER CAPWALL', ['run', '--', 'node', 'app.tmp.js'])
}
