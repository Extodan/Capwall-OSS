import { createRequire } from 'node:module'

/**
 * First-loader guarantee. A preload hook can only enforce what loads after it:
 * a package that ran EARLIER (another --import/--require, a wrapper) may hold
 * pristine references (raw process.env, unpatched Module._load) that bypass
 * every gate. True compartments (SES) eliminate that class; until then, the
 * honest move is detection: if Capwall is not provably first in the process,
 * say so — and in strict mode, refuse to run at all.
 *
 * Signals checked:
 *  1. execArgv / NODE_OPTIONS for other --import / --require preloads
 *  2. require.cache for any node_modules module already loaded
 */

export interface FirstLoaderVerdict {
  first: boolean
  reasons: string[]
}

const OUR_MARKERS = ['capwall', '@capwall/runtime-node']

function isOurs(value: string): boolean {
  return OUR_MARKERS.some((marker) => value.includes(marker))
}

export function verifyFirstLoader(own: string[] = []): FirstLoaderVerdict {
  const reasons: string[] = []
  const isOursOrSelf = (value: string) => isOurs(value) || own.some((self) => value.includes(self))

  // 1. other preloads on the command line / NODE_OPTIONS (flag + value pairs)
  const tokens = [
    ...process.execArgv,
    ...(process.env.NODE_OPTIONS ?? '').split(/\s+/).filter(Boolean),
  ]
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i]!
    let flag = token
    let value = ''
    if (token.startsWith('--import=') || token.startsWith('--require=')) {
      flag = token.split('=')[0]!
      value = token.slice(token.indexOf('=') + 1)
    } else if (token === '--import' || token === '--require' || token === '-r') {
      value = tokens[i + 1] ?? ''
      i++
    } else {
      continue
    }
    const entry = value ? `${flag} ${value}` : flag
    if (!(isOursOrSelf(entry) || (value && isOursOrSelf(value)))) {
      reasons.push(`foreign preload flag: ${entry}`)
    }
  }

  // 2. node_modules modules already resident before us
  try {
    const require = createRequire(import.meta.url)
    for (const filename of Object.keys(require.cache)) {
      if (filename.includes(`${'node_modules'}${'/'}`) && !isOursOrSelf(filename)) {
        reasons.push(`already loaded before capwall: ${filename}`)
        break // one example is enough to report
      }
    }
  } catch {
    /* cache inaccessible — skip this signal */
  }

  return { first: reasons.length === 0, reasons }
}

/** Applies the verdict: warn (default) or fail closed (strict). */
export function enforceFirstLoader(verdict: FirstLoaderVerdict, strict: boolean): void {
  if (verdict.first) return
  const detail = verdict.reasons.join('; ')
  if (strict) {
    console.error(
      `[capwall] ✖ refusing to run: capwall is not the first loader in this process (${detail}).\n` +
        '  Earlier code may hold pristine references that bypass enforcement; the\n' +
        '  capability guarantee cannot be proven. Remove earlier preloads, or unset\n' +
        '  CAPWALL_REQUIRE_FIRST to downgrade to a warning.',
    )
    process.exit(78 // EX_CONFIG: configuration error
    )
  }
  console.error(
    `[capwall] ⚠ enforcement may be bypassable — capwall is not the first loader (${detail}).\n` +
      '  Set CAPWALL_REQUIRE_FIRST=1 to fail closed instead of warning.',
  )
}
