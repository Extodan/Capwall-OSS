import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs'
import { join } from 'node:path'
import { generateKeyPair, type KeyPair } from '@capwall/attestation'

/** Local keystore: .capwall/keys.json — root + functionary Ed25519 keys (0600). */

export interface KeyStore {
  root: KeyPair
  developer: KeyPair
  ci: KeyPair
  runtime: KeyPair
}

export function keystorePath(cwd: string): string {
  return join(cwd, '.capwall', 'keys.json')
}

export function generateKeyStore(): KeyStore {
  return {
    root: generateKeyPair('org-root'),
    developer: generateKeyPair('developer-passkey'),
    ci: generateKeyPair('ci-runner'),
    runtime: generateKeyPair('prod-runtime'),
  }
}

export function saveKeyStore(cwd: string, store: KeyStore): string {
  const path = keystorePath(cwd)
  mkdirSync(join(cwd, '.capwall'), { recursive: true })
  writeFileSync(path, JSON.stringify(store, null, 2))
  try {
    chmodSync(path, 0o600)
  } catch {
    /* Windows / unusual fs — best effort */
  }
  return path
}

export function loadKeyStore(cwd: string): KeyStore | null {
  const path = keystorePath(cwd)
  if (!existsSync(path)) return null
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as KeyStore
  } catch {
    return null
  }
}

export function keyForStep(store: KeyStore, step: string): KeyPair {
  if (step.includes('git_checkout')) return store.developer
  if (step.includes('runtime')) return store.runtime
  return store.ci
}
