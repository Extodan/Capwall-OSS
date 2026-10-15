import { spawn, spawnSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join } from 'node:path'
import {
  allowCapabilities as allowCaps,
  createLock,
  denyCapabilities as denyCaps,
  grantedCapabilities,
  isCapability,
  LOCKFILE_NAME,
  parseLock,
  serializeLock,
  type Capability,
  type LockFile,
  type ScanReport,
} from '@extodan/capwall-core'
import { scanLocalTree } from '@extodan/capwall-scanner'
import { inspectToolDescription, pinToolsList } from '@extodan/capwall-agent-shield'
import {
  createCapwallLayout,
  emitLink,
  linkFileName,
  rbomPredicate,
  sbomPredicate,
  toRwxi,
  CAPWALL_STEPS,
  STEP_GIT_CHECKOUT,
  STEP_AST_CAPABILITY_SCAN,
  STEP_BUILD_PACKAGE,
  STEP_RUNTIME_ENFORCEMENT,
  verifySupplyChain,
  buildAttestationRecord,
  attestationRecordHash,
  type Envelope,
  signEnvelope,
  type DigestMap,
  type Rwxi,
} from '@extodan/capwall-attestation'
import { generateKeyStore, loadKeyStore, saveKeyStore } from './keystore.js'

export { CAPWALL_STEPS }

/* ------------------------------------------------------------------ */
/* lockfile workflows                                                  */
/* ------------------------------------------------------------------ */

export function lockFromScan(dir: string): { lock: LockFile; report: ScanReport } {
  const report = scanLocalTree(dir)
  const packages: LockFile['packages'] = {}
  for (const pkg of report.packages) {
    if (pkg.version === 'not-installed') continue
    packages[`${pkg.name}@${pkg.version}`] = {
      capabilities: [...pkg.capabilities],
      deps: pkg.deps,
      source: 'scan',
    }
  }
  return { lock: createLock(packages), report }
}

export function initLock(dir: string): { path: string; lock: LockFile; report: ScanReport } {
  const { lock, report } = lockFromScan(dir)
  const path = join(dir, LOCKFILE_NAME)
  writeFileSync(path, serializeLock(lock))
  return { path, lock, report }
}

export function loadLock(dir: string): LockFile | null {
  const path = join(dir, LOCKFILE_NAME)
  if (!existsSync(path)) return null
  return parseLock(readFileSync(path, 'utf8'))
}

export interface DriftRow {
  pkg: string
  kind: 'missing-in-lock' | 'new-capability' | 'not-installed'
  detail: string
}

export function verifyLock(dir: string): { drift: DriftRow[]; report: ScanReport } {
  const report = scanLocalTree(dir)
  const lock = loadLock(dir)
  const drift: DriftRow[] = []
  if (!lock) {
    for (const pkg of report.packages) {
      drift.push({ pkg: pkg.name, kind: 'missing-in-lock', detail: 'no capabilities.lock found' })
    }
    return { drift, report }
  }
  for (const pkg of report.packages) {
    if (pkg.version === 'not-installed') {
      drift.push({ pkg: pkg.name, kind: 'not-installed', detail: 'declared but not installed' })
      continue
    }
    const granted = grantedCapabilities(lock, pkg.name, pkg.version)
    const missing = pkg.capabilities.filter((c) => !granted.includes(c))
    if (!lock.packages[`${pkg.name}@${pkg.version}`] && !lock.packages[pkg.name]) {
      drift.push({ pkg: pkg.name, kind: 'missing-in-lock', detail: `${pkg.capabilities.join(', ') || 'no capabilities'}` })
    } else if (missing.length > 0) {
      drift.push({
        pkg: pkg.name,
        kind: 'new-capability',
        detail: `uses ${missing.join(', ')} but lock grants only ${granted.join(', ') || 'nothing'}`,
      })
    }
  }
  return { drift, report }
}

export function allowCapabilities(dir: string, pkg: string, caps: string[]): LockFile {
  validateCaps(caps)
  const lock = loadLock(dir) ?? createLock()
  let next = lock
  for (const key of resolveKeys(lock, pkg)) {
    next = allowCaps(next, key, caps as Capability[], { source: 'manual' })
  }
  writeFileSync(join(dir, LOCKFILE_NAME), serializeLock(next))
  return next
}

export function denyCapabilitiesInLock(dir: string, pkg: string, caps: string[]): LockFile {
  validateCaps(caps)
  const lock = loadLock(dir)
  if (!lock) throw new Error(`no ${LOCKFILE_NAME} in ${dir} — run capwall init first`)
  const keys = resolveKeys(lock, pkg)
  let next = lock
  for (const key of keys) {
    next = denyCaps(next, key, caps)
  }
  // Revoking every capability must not make the package "unrecognized"
  // (which only warns by default) — keep an explicit zero-trust entry.
  const packages = { ...next.packages }
  for (const key of keys) {
    if (packages[key] === undefined && lock.packages[key] !== undefined) {
      packages[key] = { capabilities: [], source: 'manual', notes: 'explicitly revoked' }
    }
  }
  next = { ...next, packages }
  writeFileSync(join(dir, LOCKFILE_NAME), serializeLock(next))
  return next
}

/**
 * `capwall allow leftpad …` should work whether the lock keys the package as
 * `leftpad` or `leftpad@1.3.0`. Exact key wins; otherwise every versioned
 * entry for that name is addressed.
 */
function resolveKeys(lock: LockFile, pkg: string): string[] {
  if (lock.packages[pkg]) return [pkg]
  const versioned = Object.keys(lock.packages).filter((k) => k.startsWith(`${pkg}@`))
  return versioned.length > 0 ? versioned : [pkg]
}

function validateCaps(caps: string[]): void {
  for (const cap of caps) {
    if (!isCapability(cap)) {
      throw new Error(`unknown capability "${cap}" — see: capwall capabilities`)
    }
  }
}

/* ------------------------------------------------------------------ */
/* run                                                                 */
/* ------------------------------------------------------------------ */

export function resolveRegisterPath(): string {
  const require = createRequire(import.meta.url)
  return require.resolve('@extodan/capwall-runtime-node')
}

export function runWithHook(cmd: string[], options: { mode?: 'enforce' | 'audit' } = {}): Promise<number> {
  const register = resolveRegisterPath()
  const [head, ...rest] = cmd
  if (!head) throw new Error('no command given — try: capwall run -- node app.js')

  const isNode = head === 'node' || head === process.execPath || head.endsWith('/node')
  const isScript = /\.(js|cjs|mjs)$/.test(head)
  const modeEnv = options.mode === 'audit' ? { ...process.env, CAPWALL_MODE: 'audit' } : process.env
  const child = isNode || isScript
    ? spawn(process.execPath, [
        '--import',
        register,
        ...(isNode ? rest : cmd),
      ], { stdio: 'inherit', env: modeEnv })
    : // npm/npx/other launchers get the hook via NODE_OPTIONS so every
      // nested node process is covered too.
      spawn(head, rest, {
        stdio: 'inherit',
        env: { ...process.env, NODE_OPTIONS: `--import=${register}` },
      })
  return new Promise((resolve) => {
    child.on('close', (code) => resolve(code ?? 0))
    child.on('error', (err) => {
      console.error(err.message)
      resolve(1)
    })
  })
}

/* ------------------------------------------------------------------ */
/* attestation                                                         */
/* ------------------------------------------------------------------ */

export function sha256File(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

export function digestFiles(cwd: string, names: string[]): DigestMap {
  const map: DigestMap = {}
  for (const name of names) {
    const path = join(cwd, name)
    if (existsSync(path)) map[name] = { sha256: sha256File(path) }
  }
  return map
}

export function attestKeysGenerate(cwd: string): string {
  const store = generateKeyStore()
  return saveKeyStore(cwd, store)
}

/** step_git_checkout: manifests as products, signed by the developer passkey. */
export function attestCheckoutLink(cwd: string, linksDir = '.capwall/links'): string {
  const store = loadKeyStore(cwd)
  if (!store) throw new Error('no keystore found — run: capwall keys generate')
  const envelope = emitLink(
    STEP_GIT_CHECKOUT,
    {
      command: ['git', 'checkout'],
      materials: {},
      products: digestFiles(cwd, ['package.json', 'package-lock.json']),
    },
    store.developer,
  )
  return writeLink(cwd, linksDir, envelope, store.developer.keyid)
}

/** step_build_package: manifests + lock in, dist artifacts out. */
export function attestBuildLink(cwd: string, linksDir = '.capwall/links'): string {
  const store = loadKeyStore(cwd)
  if (!store) throw new Error('no keystore found — run: capwall keys generate')
  const distDir = join(cwd, 'dist')
  const distFiles = listFiles(distDir).map((p) => `dist/${p}`)
  const envelope = emitLink(
    STEP_BUILD_PACKAGE,
    {
      command: ['npm', 'run', 'build'],
      materials: digestFiles(cwd, ['package.json', 'package-lock.json', LOCKFILE_NAME]),
      products: digestFiles(cwd, distFiles.slice(0, 200)),
    },
    store.ci,
  )
  return writeLink(cwd, linksDir, envelope, store.ci.keyid)
}

function listFiles(dir: string): string[] {
  if (!existsSync(dir)) return []
  const out: string[] = []
  const walk = (d: string, prefix: string) => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name
      if (entry.isDirectory()) walk(join(d, entry.name), rel)
      else out.push(rel)
    }
  }
  walk(dir, '')
  return out
}

/** Emit the full four-step chain from local state. */
export function attestEmitAll(cwd: string): string[] {
  return [
    attestCheckoutLink(cwd),
    attestScanLink(cwd),
    attestBuildLink(cwd),
    attestRuntimeLink(cwd),
  ]
}

export function attestLayout(cwd: string, outPath = 'root.layout'): string {
  const store = loadKeyStore(cwd)
  if (!store) throw new Error('no keystore found — run: capwall keys generate')
  const { envelope } = createCapwallLayout(
    { developer: store.developer, ci: store.ci, runtime: store.runtime },
    store.root,
  )
  const path = join(cwd, outPath)
  writeFileSync(path, JSON.stringify(envelope, null, 2))
  return path
}

export function attestScanLink(cwd: string, linksDir = '.capwall/links'): string {
  const store = loadKeyStore(cwd)
  if (!store) throw new Error('no keystore found — run: capwall keys generate')
  const lockPath = join(cwd, LOCKFILE_NAME)
  if (!existsSync(lockPath)) throw new Error(`no ${LOCKFILE_NAME} — run: capwall init first`)

  const report = scanLocalTree(cwd)
  const materials = digestFiles(cwd, ['package.json', 'package-lock.json'])
  const products = digestFiles(cwd, [LOCKFILE_NAME])

  const envelope = emitLink(
    STEP_AST_CAPABILITY_SCAN,
    {
      command: ['capwall', 'scan'],
      materials,
      products,
      byproducts: { scanReport: sbomPredicate(report) },
    },
    store.ci,
  )
  return writeLink(cwd, linksDir, envelope, store.ci.keyid)
}

export function attestRuntimeLink(
  cwd: string,
  options: { telemetryFile?: string; linksDir?: string } = {},
): string {
  const store = loadKeyStore(cwd)
  if (!store) throw new Error('no keystore found — run: capwall keys generate')
  const linksDir = options.linksDir ?? '.capwall/links'

  const telemetryPath =
    options.telemetryFile ?? join(cwd, '.capwall', 'telemetry', 'latest.json')
  let telemetry: { loadedPackages?: string[]; exercised?: Record<string, string[]>; violations?: unknown[]; lockDigest?: string } = {}
  if (existsSync(telemetryPath)) {
    telemetry = JSON.parse(readFileSync(telemetryPath, 'utf8'))
  }

  const materials = digestFiles(cwd, [LOCKFILE_NAME])
  const envelope = emitLink(
    STEP_RUNTIME_ENFORCEMENT,
    {
      command: ['node', '--import', '@extodan/capwall-runtime-node'],
      materials,
      products: {},
      byproducts: { rbom: rbomPredicate({
        loadedPackages: telemetry.loadedPackages ?? [],
        exercised: toRwxiBuckets(telemetry.exercised ?? {}),
        violations: (telemetry.violations ?? []) as never[],
        lockDigest: telemetry.lockDigest,
      }) },
      environment: {
        node: process.version,
        violationsBlocked: (telemetry.violations ?? []).filter((v) => (v as { action?: string }).action === 'blocked').length,
      },
    },
    store.runtime,
  )
  return writeLink(cwd, linksDir, envelope, store.runtime.keyid)
}

function toRwxiBuckets(
  exercised: Record<string, string[]>,
): Record<string, Partial<Record<Rwxi, Capability[]>>> {
  const out: Record<string, Partial<Record<Rwxi, Capability[]>>> = {}
  for (const [pkg, caps] of Object.entries(exercised)) {
    const buckets: Partial<Record<Rwxi, Capability[]>> = {}
    for (const cap of caps) {
      const bucket = toRwxi(cap as Capability)
      ;(buckets[bucket] ??= []).push(cap as Capability)
    }
    out[pkg] = buckets
  }
  return out
}

function writeLink(cwd: string, linksDir: string, envelope: Envelope, keyid: string): string {
  const predicate = JSON.parse(Buffer.from(envelope.payload, 'base64').toString('utf8')) as {
    predicate: { name: string }
  }
  const dir = join(cwd, linksDir)
  mkdirSync(dir, { recursive: true })
  const name = linkFileName(predicate.predicate.name, keyid)
  const path = join(dir, name)
  writeFileSync(path, JSON.stringify(envelope, null, 2))
  return path
}

export interface AttestVerifyResult {
  ok: boolean
  recordHash: string
  summary: string
  steps: { name: string; ok: boolean; errors: string[] }[]
  errors: string[]
}

export function attestVerify(
  cwd: string,
  options: { layoutPath?: string; linksDir?: string } = {},
): AttestVerifyResult {
  const store = loadKeyStore(cwd)
  if (!store) throw new Error('no keystore found — run: capwall keys generate')

  const layoutPath = join(cwd, options.layoutPath ?? 'root.layout')
  if (!existsSync(layoutPath)) throw new Error(`no layout at ${layoutPath} — run: capwall attest layout`)
  const layoutEnvelope = JSON.parse(readFileSync(layoutPath, 'utf8')) as Envelope

  const linksDir = join(cwd, options.linksDir ?? join('.capwall', 'links'))
  const links: Envelope[] = []
  if (existsSync(linksDir)) {
    for (const file of readdirSync(linksDir)) {
      if (file.endsWith('.link')) {
        links.push(JSON.parse(readFileSync(join(linksDir, file), 'utf8')) as Envelope)
      }
    }
  }

  const verification = verifySupplyChain({
    layoutEnvelope,
    links,
    trustedRootKeys: [store.root.publicHex],
  })

  const runtimeLink = links.find((l) => {
    const payload = JSON.parse(Buffer.from(l.payload, 'base64').toString('utf8')) as { predicate?: { name?: string } }
    return payload.predicate?.name === STEP_RUNTIME_ENFORCEMENT
  })

  let recordHash = ''
  if (runtimeLink) {
    const record = buildAttestationRecord({
      layoutEnvelope,
      stepName: STEP_RUNTIME_ENFORCEMENT,
      stepEnvelope: runtimeLink,
      verification,
    })
    recordHash = attestationRecordHash(record)
  }

  return {
    ok: verification.ok,
    recordHash,
    summary: verification.ok
      ? 'supply chain verified — capabilities.lock chained end-to-end'
      : 'verification FAILED',
    steps: verification.steps.map((s) => ({ name: s.name, ok: s.ok, errors: s.errors })),
    errors: verification.errors,
  }
}

/** §2 NodeShield: CycloneDX v1.6 security-enhanced SBOM, DSSE-signed. */
export function exportCycloneDxSbom(cwd: string, outPath = 'capwall-sbom.json'): string {
  const store = loadKeyStore(cwd)
  if (!store) throw new Error('no keystore found — run: capwall keys generate')
  const report = scanLocalTree(cwd)
  const components = report.packages.map((p) => ({
    type: 'library',
    'bom-ref': `pkg:npm/${p.name}@${p.version}`,
    name: p.name,
    version: p.version,
    properties: [
      { name: 'capwall:rwx:capabilities', value: p.capabilities.join(',') || 'none' },
      { name: 'capwall:rwx:imports', value: p.deps.join(',') || 'none' },
      { name: 'nodeshield:capabilities:risk', value: String(p.score) },
    ],
  }))
  const document = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: { timestamp: new Date().toISOString(), tools: [{ vendor: 'capwall', name: 'capwall-cli', version: '0.1.0' }] },
    components,
  }
  const envelope = signEnvelope(document, store.root)
  const path = join(cwd, outPath)
  writeFileSync(path, JSON.stringify(envelope, null, 2))
  return path
}


const NODE_BIN = process.env.CAPWALL_NODE_BIN ?? 'node'

/* ------------------------------------------------------------------ */
/* agent & MCP shield surface (capwall wrap / mcp / taint)             */
/* ------------------------------------------------------------------ */

/** Probe a stdio MCP server: send tools/list, capture one response frame. */
export function probeMcpToolsList(command: string[], timeoutMs = 8000): { tools: { name: string; description?: string; inputSchema?: unknown }[]; raw: string } {
  // accept both `-- node server.js` and `-- server.js` forms
  const args = /^(node|node.exe)$/i.test(command[0] ?? '') ? command.slice(1) : command
  const res = spawnSync(NODE_BIN, args, {
    input: `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })}\n`,
    encoding: 'utf8',
    timeout: timeoutMs,
    env: { PATH: process.env.PATH ?? '' },
  })
  const frame = (res.stdout ?? '').split('\n').map((l) => l.trim()).filter(Boolean)
    .map((l) => { try { return JSON.parse(l) } catch { return null } })
    .find((o) => o && o.result && 'tools' in (o.result as object)) as
    { result: { tools: { name: string; description?: string; inputSchema?: unknown }[] } } | undefined
  if (!frame) throw new Error(`no tools/list response from: ${command.join(' ')}\nstderr: ${(res.stderr ?? '').slice(-300)}`)
  return { tools: frame.result.tools, raw: (res.stdout ?? '') }
}

export interface McpScanReport {
  server: string
  toolCount: number
  findings: { tool: string; findings: string[] }[]
  clean: boolean
  pin: string
}

/** capwall mcp scan — MCP-ITP audit of a live tools/list response. */
export function mcpScan(server: string, command: string[]): McpScanReport {
  const { tools } = probeMcpToolsList(command)
  const pin = pinToolsList(tools)
  const findings = tools.map((tool) => {
    const verdict = inspectToolDescription(tool)
    return { tool: tool.name, findings: verdict.findings }
  }).filter((r) => r.findings.length > 0 && !r.findings[0]!.startsWith('note:'))
  return { server, toolCount: tools.length, findings, clean: findings.length === 0, pin }
}

/** capwall mcp lock — pin the tools/list digest into .capwall/mcp-pins.json. */
export function mcpLock(server: string, command: string[], cwd = process.cwd()): { pin: string; path: string } {
  const { tools } = probeMcpToolsList(command)
  const pin = pinToolsList(tools)
  const dir = join(cwd, '.capwall')
  mkdirSync(dir, { recursive: true })
  const pinsPath = join(dir, 'mcp-pins.json')
  let pins: Record<string, { schema_sha256: string; trustedRewrite?: boolean }> = {}
  try { pins = JSON.parse(readFileSync(pinsPath, 'utf8')) } catch { /* new */ }
  pins[server] = { schema_sha256: pin, trustedRewrite: true }
  writeFileSync(pinsPath, JSON.stringify(pins, null, 2))
  return { pin, path: pinsPath }
}

/** capwall taint status — persisted SPA ledger view. */
export function taintStatus(cwd = process.cwd()): { entries: { path: string; label: string; sha256: string }[]; ledgerPath: string } {
  const ledgerPath = join(cwd, '.capwall', 'taint-ledger.json')
  let entries: { path: string; sha256: string; label: { confidentiality: string; integrity: string } }[] = []
  try {
    entries = JSON.parse(readFileSync(ledgerPath, 'utf8'))
  } catch { /* empty */ }
  return {
    entries: entries.map((e) => ({ path: e.path, label: `C:${e.label.confidentiality} I:${e.label.integrity}`, sha256: e.sha256.slice(0, 12) })),
    ledgerPath,
  }
}

export function taintClear(cwd = process.cwd()): boolean {
  const ledgerPath = join(cwd, '.capwall', 'taint-ledger.json')
  if (!existsSync(ledgerPath)) return false
  rmSync(ledgerPath)
  return true
}

/** capwall wrap — wrap an agent / MCP / lifecycle command in the shield. */
export async function wrapCommand(
  command: string[],
  options: { agent?: 'claude' | 'cursor' | 'codex' | 'mcp'; mode?: 'enforce' | 'audit'; cwd?: string } = {},
): Promise<number> {
  const cwd = options.cwd ?? process.cwd()
  const isMcp = options.agent === 'mcp'
  const runtimeRegister = resolveRegisterPath()
  const agentPreload = createRequire(import.meta.url).resolve('@extodan/capwall-agent-shield/wrap-preload')

  if (isMcp) {
    // stdio MCP servers go through the intercepting proxy shim
    const preload = createRequire(import.meta.url).resolve('@extodan/capwall-agent-shield/wrap-preload')
    const shim = preload.replace('wrap-preload.mjs', 'mcp-shim.mjs')
    const pins = existsSync(join(cwd, '.capwall', 'mcp-pins.json'))
    const child = spawn(NODE_BIN, [shim, 'wrapped', '--', ...command], {
      stdio: 'inherit',
      env: { ...process.env, PATH: process.env.PATH ?? '', CAPWALL_WRAP_MODE: options.mode ?? 'enforce' },
    })
    void pins
    return await new Promise((resolve) => { child.on('close', (c) => resolve(c ?? 0)); child.on('error', () => resolve(1)) })
  }

  // agent / lifecycle node processes: preload BOTH the capability firewall
  // and the DIFC wrap monitor; non-node commands still get the env vars.
  const child = spawn(command[0]!, command.slice(1), {
    stdio: 'inherit',
    env: {
      ...process.env,
      CAPWALL_WRAP_MODE: options.mode ?? 'enforce',
      NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} --import=${runtimeRegister} --import=${agentPreload}`.trim(),
    },
  })
  return await new Promise((resolve) => { child.on('close', (c) => resolve(c ?? 0)); child.on('error', () => resolve(1)) })
}

export const STEPS = {
  gitCheckout: STEP_GIT_CHECKOUT,
  scan: STEP_AST_CAPABILITY_SCAN,
  build: STEP_BUILD_PACKAGE,
  runtime: STEP_RUNTIME_ENFORCEMENT,
}
