/**
 * The Capwall capability model.
 *
 * A capability is a class of sensitive action a package can perform
 * (read env vars, spawn processes, open sockets, ...). The scanner infers
 * which capabilities a package's code actually exercises; the runtime hook
 * enforces the allowlist found in `capabilities.lock`.
 */

export const CAPABILITIES = [
  'env.read',
  'env.write',
  'child_process',
  'net.connect',
  'net.listen',
  'http.request',
  'dns.resolve',
  'fs.read',
  'fs.write',
  'dynamic-code',
  'worker_threads',
] as const

export type Capability = (typeof CAPABILITIES)[number]

export type Severity = 'low' | 'medium' | 'high' | 'critical'

export interface CapabilityInfo {
  /** Human label, e.g. "Read environment variables" */
  label: string
  /** One-line explanation of what granting this allows. */
  description: string
  /** How dangerous an *unjustified* use of this capability is. */
  severity: Severity
}

export const CAPABILITY_INFO: Record<Capability, CapabilityInfo> = {
  'env.read': {
    label: 'Read environment variables',
    description: 'Package can read every environment variable, including API keys and connection strings.',
    severity: 'high',
  },
  'env.write': {
    label: 'Write environment variables',
    description: 'Package can mutate process.env, hijacking configuration for later readers.',
    severity: 'high',
  },
  child_process: {
    label: 'Spawn child processes',
    description: 'Package can execute arbitrary shell commands and binaries on your machine.',
    severity: 'critical',
  },
  'net.connect': {
    label: 'Outbound TCP connections',
    description: 'Package can open raw TCP/TLS sockets to any host — a data-exfiltration channel.',
    severity: 'medium',
  },
  'net.listen': {
    label: 'Listen for network connections',
    description: 'Package can bind a port and accept inbound connections.',
    severity: 'medium',
  },
  'http.request': {
    label: 'Outbound HTTP requests',
    description: 'Package can send HTTP/HTTPS requests to any URL — the classic exfiltration vector.',
    severity: 'medium',
  },
  'dns.resolve': {
    label: 'DNS resolution',
    description: 'Package can resolve hostnames, useful for DNS-tunneling exfiltration.',
    severity: 'low',
  },
  'fs.read': {
    label: 'Read filesystem',
    description: 'Package can read any file your process can, including .env and SSH keys.',
    severity: 'medium',
  },
  'fs.write': {
    label: 'Write filesystem',
    description: 'Package can overwrite files anywhere your process has permission.',
    severity: 'high',
  },
  'dynamic-code': {
    label: 'Dynamic code evaluation',
    description: 'Package uses eval / new Function / vm to execute code built at runtime — invisible to static review.',
    severity: 'critical',
  },
  worker_threads: {
    label: 'Worker threads',
    description: 'Package can spawn worker threads, which get their own module registry.',
    severity: 'low',
  },
}

export function isCapability(value: string): value is Capability {
  return (CAPABILITIES as readonly string[]).includes(value)
}

/**
 * Node builtin modules gated by Capwall, mapped to the capabilities they grant.
 * Specifiers may appear bare ("fs") or prefixed ("node:fs").
 */
export const GATED_BUILTINS: Record<string, Capability[]> = {
  fs: ['fs.read', 'fs.write'],
  'fs/promises': ['fs.read', 'fs.write'],
  'node:fs': ['fs.read', 'fs.write'],
  'node:fs/promises': ['fs.read', 'fs.write'],
  child_process: ['child_process'],
  'node:child_process': ['child_process'],
  net: ['net.connect', 'net.listen'],
  'node:net': ['net.connect', 'net.listen'],
  http: ['http.request'],
  'node:http': ['http.request'],
  https: ['http.request'],
  'node:https': ['http.request'],
  http2: ['http.request'],
  'node:http2': ['http.request'],
  dns: ['dns.resolve'],
  'node:dns': ['dns.resolve'],
  tls: ['net.connect'],
  'node:tls': ['net.connect'],
  dgram: ['net.connect', 'net.listen'],
  'node:dgram': ['net.connect', 'net.listen'],
  vm: ['dynamic-code'],
  'node:vm': ['dynamic-code'],
  worker_threads: ['worker_threads'],
  'node:worker_threads': ['worker_threads'],
}

/** Returns the capabilities a builtin specifier grants, or undefined if not gated. */
export function builtinCapabilities(specifier: string): Capability[] | undefined {
  return GATED_BUILTINS[specifier]
}

/**
 * Normalize a require/import specifier for capability lookup.
 * Handles "node:fs", "fs", "fs/promises" (also "node:fs/promises?query" edge cases).
 */
export function normalizeSpecifier(specifier: string): string {
  return specifier.split('?')[0]?.trim() ?? specifier
}
