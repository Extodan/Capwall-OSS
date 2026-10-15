import { describe, expect, it } from 'vitest'
import {
  applyRules,
  attestationRecordHash,
  buildAttestationRecord,
  canonicalJson,
  createCapwallLayout,
  emitLink,
  generateKeyPair,
  keyidForPublicHex,
  pae,
  parseRule,
  runtimeStepStatement,
  scanStepStatement,
  sha256Hex,
  signEnvelope,
  verifyEnvelope,
  verifySupplyChain,
  type DigestMap,
} from '../src/index.js'
import type { ScanReport } from '@capwall/core'

const sha = (content: string) => sha256Hex(content)

function digestMap(files: Record<string, string>): DigestMap {
  return Object.fromEntries(Object.entries(files).map(([name, content]) => [name, { sha256: sha(content) }]))
}

describe('keys', () => {
  it('keyid is deterministic and derived from the public key record', () => {
    const key = generateKeyPair('test')
    expect(key.keyid).toBe(keyidForPublicHex(key.publicHex))
    expect(key.keyid).toHaveLength(64)
    expect(key.publicHex).toHaveLength(64)
  })
})

describe('DSSE', () => {
  const signer = generateKeyPair('dsse')
  const payload = { hello: 'world', n: 42 }

  it('PAE follows the DSSEv1 framing', () => {
    const body = Buffer.from('{"a":1}')
    expect(pae('application/vnd.in-toto+json', body).toString()).toBe(
      'DSSEv1 28 application/vnd.in-toto+json 7 {"a":1}',
    )
  })

  it('sign → verify round-trip', () => {
    const env = signEnvelope(payload, signer)
    const check = verifyEnvelope(env, { [signer.keyid]: signer.publicHex })
    expect(check.valid).toBe(true)
    expect(check.payload).toEqual(payload)
    expect(check.verifiedKeyids).toEqual([signer.keyid])
  })

  it('rejects tampered payloads', () => {
    const env = signEnvelope(payload, signer)
    const tampered = { ...env, payload: Buffer.from('{"hello":"attacker"}').toString('base64') }
    const check = verifyEnvelope(tampered, { [signer.keyid]: signer.publicHex })
    expect(check.valid).toBe(false)
  })

  it('rejects unknown keys and bad signatures', () => {
    const env = signEnvelope(payload, signer)
    expect(verifyEnvelope(env, { someoneelse: generateKeyPair().publicHex }).valid).toBe(false)
    const forged = { ...env, signatures: [{ keyid: signer.keyid, sig: Buffer.alloc(64).toString('base64') }] }
    expect(verifyEnvelope(forged, { [signer.keyid]: signer.publicHex }).valid).toBe(false)
  })
})

describe('artifact rules', () => {
  const scanLink = { materials: digestMap({ 'package.json': 'src' }), products: digestMap({ 'capabilities.lock': 'LOCK-V1' }) }

  it('MATCH passes when digests chain', () => {
    const result = applyRules(
      [parseRule('MATCH capabilities.lock WITH PRODUCTS FROM step_ast_capability_scan'), parseRule('ALLOW *')],
      digestMap({ 'capabilities.lock': 'LOCK-V1', 'dist/app.js': 'built' }),
      digestMap({}),
      { step_ast_capability_scan: scanLink },
    )
    expect(result.ok).toBe(true)
  })

  it('MATCH fails on digest mismatch (the bit-identical guarantee)', () => {
    const result = applyRules(
      [parseRule('MATCH capabilities.lock WITH PRODUCTS FROM step_ast_capability_scan')],
      digestMap({ 'capabilities.lock': 'TAMPERED-LOCK' }),
      {},
      { step_ast_capability_scan: scanLink },
    )
    expect(result.ok).toBe(false)
    expect(result.violations[0]).toMatch(/digest mismatch/)
  })

  it('DISALLOW catches forbidden artifacts', () => {
    const result = applyRules(
      [parseRule('ALLOW src/**'), parseRule('DISALLOW *')],
      digestMap({ 'src/a.js': 'a', '.env': 'secrets' }),
      {},
      {},
    )
    expect(result.ok).toBe(false)
    expect(result.violations[0]).toMatch(/DISALLOW/)
  })

  it('CREATE requires the artifact to be new', () => {
    const ok = applyRules([parseRule('CREATE capabilities.lock')], {}, digestMap({ 'capabilities.lock': 'x' }), {})
    expect(ok.ok).toBe(true)
    const bad = applyRules(
      [parseRule('CREATE capabilities.lock')],
      digestMap({ 'capabilities.lock': 'x' }),
      digestMap({ 'capabilities.lock': 'x' }),
      {},
    )
    expect(bad.ok).toBe(false)
    expect(bad.violations[0]).toMatch(/already existed in materials/)
  })

  it('leftover artifacts fail the chain', () => {
    const result = applyRules([parseRule('ALLOW a')], digestMap({ a: '1', b: '2' }), {}, {})
    expect(result.ok).toBe(false)
    expect(result.violations[0]).toMatch(/unconsumed/)
  })
})

describe('end-to-end supply chain verification', () => {
  // Keys: root (org security owner) + 3 functionaries.
  const root = generateKeyPair('org-root')
  const developer = generateKeyPair('developer-passkey')
  const ci = generateKeyPair('ci-runner')
  const runtimeNode = generateKeyPair('prod-runtime')

  const buildChain = (lockContent: string) => {
    const { layout, envelope } = createCapwallLayout({ developer, ci, runtime: runtimeNode }, root)

    const checkout = emitLink(
      'step_git_checkout',
      {
        command: ['git', 'checkout', 'main'],
        materials: {},
        products: digestMap({ 'package.json': 'MANIFEST', 'package-lock.json': 'LOCKFILE' }),
      },
      developer,
    )
    const scan = signEnvelope(
      scanStepStatement(dummyReport(), digestMap({ 'package.json': 'MANIFEST', 'package-lock.json': 'LOCKFILE' }), digestMap({ 'capabilities.lock': lockContent })),
      ci,
    )
    const build = emitLink(
      'step_build_package',
      {
        command: ['npm', 'run', 'build'],
        materials: digestMap({ 'capabilities.lock': lockContent, 'package.json': 'MANIFEST' }),
        products: digestMap({ 'dist/app.js': 'BUNDLE' }),
      },
      ci,
    )
    const runtime = signEnvelope(
      runtimeStepStatement(
        {
          loadedPackages: ['leftpad', 'evil-string'],
          exercised: { 'evil-string': { R: ['env.read'], i: ['http.request'] } },
          violations: [],
          lockDigest: sha(lockContent),
        },
        digestMap({ 'capabilities.lock': lockContent, 'dist/app.js': 'BUNDLE' }),
      ),
      runtimeNode,
    )
    return { layout, layoutEnvelope: envelope, links: [checkout, scan, build, runtime] }
  }

  it('verifies a legitimate chain', () => {
    const chain = buildChain('LOCK-CONTENT-V1')
    const result = verifySupplyChain({
      layoutEnvelope: chain.layoutEnvelope,
      links: chain.links,
      trustedRootKeys: [root.publicHex],
    })
    expect(result.ok).toBe(true)
    expect(result.steps.map((s) => s.name)).toEqual([
      'step_git_checkout',
      'step_ast_capability_scan',
      'step_build_package',
      'step_runtime_enforcement',
    ])
    expect(result.steps.every((s) => s.ok)).toBe(true)
  })

  it('rejects a tampered capabilities.lock at the runtime node', () => {
    const chain = buildChain('LOCK-CONTENT-V1')
    const swapped = emitLink(
      'step_runtime_enforcement',
      {
        command: ['node', '--import', '@capwall/runtime-node'],
        materials: digestMap({ 'capabilities.lock': 'SWAPPED-LOCK', 'dist/app.js': 'BUNDLE' }),
      },
      runtimeNode,
    )
    const result = verifySupplyChain({
      layoutEnvelope: chain.layoutEnvelope,
      links: [chain.links[0]!, chain.links[1]!, chain.links[2]!, swapped],
      trustedRootKeys: [root.publicHex],
    })
    expect(result.ok).toBe(false)
    const step = result.steps.find((s) => s.name === 'step_runtime_enforcement')
    expect(step?.errors.join(' ')).toMatch(/digest mismatch/)
  })

  it('rejects a link signed by an unauthorized functionary', () => {
    const chain = buildChain('LOCK-CONTENT-V1')
    const impostor = emitLink(
      'step_runtime_enforcement',
      { materials: digestMap({ 'capabilities.lock': 'LOCK-CONTENT-V1' }) },
      developer, // developer is not authorized for the runtime step
    )
    const result = verifySupplyChain({
      layoutEnvelope: chain.layoutEnvelope,
      links: [chain.links[0]!, chain.links[1]!, chain.links[2]!, impostor],
      trustedRootKeys: [root.publicHex],
    })
    expect(result.ok).toBe(false)
    expect(result.steps.find((s) => s.name === 'step_runtime_enforcement')?.errors.join(' ')).toMatch(
      /not authorized/,
    )
  })

  it('rejects links signed by keys unknown to the layout entirely', () => {
    const chain = buildChain('LOCK-CONTENT-V1')
    const stranger = generateKeyPair('stranger')
    const forged = emitLink(
      'step_runtime_enforcement',
      { materials: digestMap({ 'capabilities.lock': 'LOCK-CONTENT-V1' }) },
      stranger,
    )
    const result = verifySupplyChain({
      layoutEnvelope: chain.layoutEnvelope,
      links: [chain.links[0]!, chain.links[1]!, chain.links[2]!, forged],
      trustedRootKeys: [root.publicHex],
    })
    expect(result.ok).toBe(false)
    expect(result.errors.join(' ')).toMatch(/no valid signature/)
  })

  it('rejects expired layouts', () => {
    const expired = new Date(Date.now() - 864e5)
    const { envelope } = createCapwallLayout({ developer, ci, runtime: runtimeNode }, root, { expires: expired })
    const chain = buildChain('LOCK-CONTENT-V1')
    const result = verifySupplyChain({
      layoutEnvelope: envelope,
      links: chain.links,
      trustedRootKeys: [root.publicHex],
    })
    expect(result.ok).toBe(false)
    expect(result.errors.join(' ')).toMatch(/expired/)
  })

  it('rejects a layout not signed by the trusted root', () => {
    const fakeRoot = generateKeyPair('fake-root')
    const { envelope } = createCapwallLayout({ developer, ci, runtime: runtimeNode }, fakeRoot)
    const chain = buildChain('LOCK-CONTENT-V1')
    const result = verifySupplyChain({
      layoutEnvelope: envelope,
      links: chain.links,
      trustedRootKeys: [root.publicHex],
    })
    expect(result.ok).toBe(false)
    expect(result.errors.join(' ')).toMatch(/root layout signature invalid/)
  })

  it('rejects missing steps', () => {
    const chain = buildChain('LOCK-CONTENT-V1')
    const result = verifySupplyChain({
      layoutEnvelope: chain.layoutEnvelope,
      links: chain.links.slice(0, 3), // runtime step missing
      trustedRootKeys: [root.publicHex],
    })
    expect(result.ok).toBe(false)
    expect(result.steps.find((s) => s.name === 'step_runtime_enforcement')?.errors.join(' ')).toMatch(
      /no valid link/,
    )
  })
})

describe('registry seam (Base)', () => {
  it('record hash is deterministic and content-sensitive', () => {
    const root = generateKeyPair()
    const { envelope } = createCapwallLayout(
      { developer: generateKeyPair(), ci: generateKeyPair(), runtime: generateKeyPair() },
      root,
    )
    const link = emitLink('step_runtime_enforcement', { materials: digestMap({ 'capabilities.lock': 'v1' }) }, generateKeyPair())
    const verification = verifySupplyChain({ layoutEnvelope: envelope, links: [link], trustedRootKeys: [root.publicHex] })

    const record = buildAttestationRecord({
      layoutEnvelope: envelope,
      stepName: 'step_runtime_enforcement',
      stepEnvelope: link,
      verification,
      subjectDigests: { 'capabilities.lock': sha('v1') },
      verifiedAt: '2026-10-14T00:00:00.000Z',
    })
    const hash1 = attestationRecordHash(record)
    const hash2 = attestationRecordHash(JSON.parse(JSON.stringify(record)))
    expect(hash1).toBe(hash2)
    expect(hash1).toMatch(/^0x[0-9a-f]{64}$/)

    const changed = attestationRecordHash({ ...record, result: 'verified' as const })
    expect(changed).not.toBe(hash1) // rejected vs verified differs
  })

  it('canonicalJson sorts keys deterministically', () => {
    expect(canonicalJson({ b: 1, a: { d: 2, c: 3 } })).toBe('{"a":{"c":3,"d":2},"b":1}')
  })
})

function dummyReport(): ScanReport {
  return {
    createdAt: new Date().toISOString(),
    source: { kind: 'package.json', ref: 'test' },
    root: { name: 'app', version: '1.0.0' },
    packages: [],
    totals: { packages: 0, byCapability: {}, withInstallScripts: 0, maxScore: 0 },
    score: 0,
  }
}

describe('§6 zkSBOM commitment layer', () => {
  it('commits an RBOM to a merkle root and verifies inclusion proofs', async () => {
    const { commitRbom, proveInclusion, verifyInclusion } = await import('../src/index.js')
    const pkgs = [
      { name: 'a', version: '1.0.0', capabilities: ['env.read'] },
      { name: 'b', version: '2.0.0', capabilities: [] },
      { name: 'c', version: '0.1.0', capabilities: ['child_process'] },
    ]
    const { root } = commitRbom(pkgs)
    expect(root).toMatch(/^[0-9a-f]{64}$/)
    const proof = proveInclusion(pkgs, { name: 'b', version: '2.0.0' })
    expect(verifyInclusion(root, proof)).toBe(true)
    // a proof against a different root must fail
    const { root: otherRoot } = commitRbom([...pkgs, { name: 'd', version: '1.0.0', capabilities: [] }])
    expect(verifyInclusion(otherRoot, proof)).toBe(false)
  })
})

describe('§6 zkSBOM exclusion proofs', () => {
  it('proves a package absent from the committed set via bracketing neighbors', async () => {
    const { commitRbom, proveExclusion, verifyExclusion } = await import('../src/index.js')
    const pkgs = [
      { name: 'aa', version: '1.0.0', capabilities: [] },
      { name: 'cc', version: '1.0.0', capabilities: [] },
      { name: 'ee', version: '1.0.0', capabilities: [] },
    ]
    const { root } = commitRbom(pkgs)
    const proof = proveExclusion(pkgs, 'dd@1.0.0:')
    expect(verifyExclusion(root, proof, 'dd@1.0.0:')).toBe(true)
    // a present package must NOT be excludable via this bracket
    const proof2 = proveExclusion(pkgs, 'cc@1.0.0:')
    expect(verifyExclusion(root, proof2, 'cc@1.0.0:')).toBe(false)
  })
})

describe('§6 zkSBOM hiding set (salted sparse Merkle)', () => {
  it('proves inclusion AND exclusion revealing only sibling hashes', async () => {
    const { zkCommit, zkProve, zkVerify } = await import('../src/index.js')
    const set = zkCommit([
      { name: 'aa', version: '1.0.0', capabilities: [] },
      { name: 'cc', version: '1.0.0', capabilities: ['env.read'] },
      { name: 'ee', version: '1.0.0', capabilities: [] },
    ])
    const member = zkProve(set, 'cc@1.0.0:env.read')
    expect(zkVerify(set.root, 'cc@1.0.0:env.read', member)).toEqual({ included: true, valid: true })
    const absent = zkProve(set, 'dd@1.0.0:')
    expect(zkVerify(set.root, 'dd@1.0.0:', absent)).toEqual({ included: false, valid: true })
    // proofs never reveal another member's ref: only hex hashes transit
    const transit = JSON.stringify(absent) + JSON.stringify(member)
    expect(transit).not.toContain('aa@')
    expect(transit).not.toContain('ee@')
    // a forged inclusion (claim absent package as member) fails
    const forged = { ...absent, leafHex: member.leafHex }
    expect(zkVerify(set.root, 'dd@1.0.0:', forged).valid).toBe(false)
  })
})
