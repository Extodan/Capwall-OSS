import { describe, expect, it } from 'vitest'
import {
  allowCapabilities,
  createLock,
  denyCapabilities,
  grantedCapabilities,
  isRecognized,
  LockfileFormatError,
  LOCKFILE_NAME,
  parseLock,
  serializeLock,
} from '../src/index.js'

const validLock = {
  version: 1,
  defaults: { unrecognized: 'warn' },
  packages: {
    'lodash@4.17.21': { capabilities: ['env.read'], source: 'scan' },
    react: { capabilities: ['fs.read'] },
  },
}

describe('lockfile parse/serialize', () => {
  it('round-trips a valid lock', () => {
    const lock = parseLock(JSON.stringify(validLock))
    expect(lock.packages['lodash@4.17.21']?.capabilities).toEqual(['env.read'])
    const again = parseLock(serializeLock(lock))
    expect(again).toEqual(lock)
  })

  it('fills defaults', () => {
    const lock = parseLock('{"version":1,"packages":{}}')
    expect(lock.defaults.unrecognized).toBe('warn')
  })

  it('rejects invalid JSON with a readable error', () => {
    expect(() => parseLock('{nope')).toThrow(LockfileFormatError)
  })

  it('rejects wrong version', () => {
    expect(() => parseLock('{"version":99,"packages":{}}')).toThrow(/version/)
  })

  it('rejects unknown capabilities', () => {
    expect(() =>
      parseLock('{"version":1,"packages":{"a":{"capabilities":["telepathy"]}}}'),
    ).toThrow(/telepathy/)
  })

  it('lockfile name constant', () => {
    expect(LOCKFILE_NAME).toBe('capabilities.lock')
  })
})

describe('lockfile lookups', () => {
  const lock = parseLock(JSON.stringify(validLock))

  it('prefers name@version over bare name', () => {
    expect(grantedCapabilities(lock, 'lodash', '4.17.21')).toEqual(['env.read'])
    expect(grantedCapabilities(lock, 'react', '19.0.0')).toEqual(['fs.read'])
    expect(grantedCapabilities(lock, 'unknown-pkg')).toEqual([])
    expect(isRecognized(lock, 'react')).toBe(true)
    expect(isRecognized(lock, 'nope')).toBe(false)
  })
})

describe('allow/deny mutations', () => {
  it('allow merges capabilities and keeps existing ones', () => {
    const lock = createLock()
    const next = allowCapabilities(lock, 'axios@1.7.0', ['http.request', 'env.read'])
    const next2 = allowCapabilities(next, 'axios@1.7.0', ['http.request'], { source: 'scan' })
    expect(grantedCapabilities(next2, 'axios', '1.7.0')).toEqual(['env.read', 'http.request'])
    expect(next2.packages['axios@1.7.0']?.source).toBe('scan')
  })

  it('deny removes capabilities and drops empty entries', () => {
    let lock = createLock()
    lock = allowCapabilities(lock, 'pkg', ['env.read', 'fs.read'])
    lock = denyCapabilities(lock, 'pkg', ['env.read'])
    expect(grantedCapabilities(lock, 'pkg')).toEqual(['fs.read'])
    lock = denyCapabilities(lock, 'pkg', ['fs.read'])
    expect(isRecognized(lock, 'pkg')).toBe(false)
  })
})
