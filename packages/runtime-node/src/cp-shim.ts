// ESM namespace shim for granted node:child_process imports (§3 GHunter).
// The resolve hook rewrites managed+granted imports to this module; it
// re-exports the core module with every options-taking function wrapped by
// the null-prototype gadget sanitizer.
import * as cp from 'node:child_process'
import { wrapChildProcess } from './gadgets.js'

const wrapped = wrapChildProcess(cp as unknown as Record<string, unknown>) as typeof cp
export const spawn = wrapped.spawn
export const spawnSync = wrapped.spawnSync
export const exec = wrapped.exec
export const execFile = wrapped.execFile
export const execSync = wrapped.execSync
export const execFileSync = wrapped.execFileSync
export const fork = wrapped.fork
export default wrapped
