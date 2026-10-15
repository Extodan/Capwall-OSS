#!/usr/bin/env node
import { Command } from 'commander'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import picocolors from 'picocolors'
import { CAPABILITY_INFO, CAPABILITIES } from '@extodan/capwall-core'
import { scanLocalTree } from '@extodan/capwall-scanner'
import {
  allowCapabilities,
  attestBuildLink,
  attestCheckoutLink,
  attestEmitAll,
  attestKeysGenerate,
  exportCycloneDxSbom,
  mcpLock,
  mcpScan,
  taintClear,
  taintStatus,
  wrapCommand,
  attestLayout,
  attestRuntimeLink,
  attestScanLink,
  attestVerify,
  denyCapabilitiesInLock,
  initLock,
  loadLock,
  runWithHook,
  verifyLock,
} from './lib.js'
import { printCapabilityLegend, printScanReport } from './output.js'

const program = new Command()

program
  .name('capwall')
  .description('Capability firewall for npm dependencies — scan, lock, enforce, attest.')
  .version('0.1.0')

program
  .command('scan')
  .description('analyze node_modules and print a capability + risk report')
  .argument('[dir]', 'project directory', '.')
  .option('-v, --verbose', 'show npm metadata and signals', false)
  .action((dir: string, opts: { verbose: boolean }) => {
    const report = scanLocalTree(dir)
    printScanReport(report, opts.verbose)
  })

program
  .command('init')
  .description('scan node_modules and write capabilities.lock (review before committing!)')
  .argument('[dir]', 'project directory', '.')
  .action((dir: string) => {
    const { path, report } = initLock(dir)
    printScanReport(report)
    console.log(picocolors.green(`  ✔ wrote ${path}`))
    console.log(
      picocolors.dim(`  next: review the grants, then run your app with:\n     capwall run -- node app.js`),
    )
  })

program
  .command('verify')
  .description('check capabilities.lock against the current node_modules (CI-friendly exit code)')
  .argument('[dir]', 'project directory', '.')
  .action((dir: string) => {
    const { drift } = verifyLock(dir)
    if (drift.length === 0) {
      console.log(picocolors.green('  ✔ capabilities.lock matches the installed tree'))
      return
    }
    console.log(picocolors.red(`  ✖ ${drift.length} drift finding(s):`))
    for (const row of drift) {
      console.log(`    ${picocolors.bold(row.pkg)} [${row.kind}] ${picocolors.dim(row.detail)}`)
    }
    console.log(picocolors.dim('\n  re-baseline with: capwall init'))
    process.exitCode = 1
  })

program
  .command('run')
  .description('run a Node/npm process under the @extodan/capwall-runtime-node V8 hook')
  .argument('<cmd...>', 'command to run, e.g. -- node app.js')
  .option('--mode <mode>', 'enforce | audit (observe-only, nothing blocks)', 'enforce')
  .allowExcessArguments(true)
  .enablePositionalOptions()
  .action(async (cmd: string[], opts: { mode: string }) => {
    const code = await runWithHook(cmd, { mode: opts.mode as 'enforce' | 'audit' })
    process.exitCode = code
  })

program
  .command('capabilities')
  .description('list all capabilities Capwall gates')
  .action(() => printCapabilityLegend())

program
  .command('allow')
  .description('grant capabilities to a package in capabilities.lock')
  .argument('<pkg>', 'package name (or name@version)')
  .argument('<capabilities...>', `one of: ${CAPABILITIES.join(', ')}`)
  .action((pkg: string, caps: string[]) => {
    const lock = allowCapabilities(process.cwd(), pkg, caps)
    const granted = lock.packages[pkg]?.capabilities ?? []
    console.log(picocolors.green(`  ✔ ${pkg} → ${granted.join(', ') || '(none)'}`))
  })

program
  .command('deny')
  .description('revoke capabilities from a package in capabilities.lock')
  .argument('<pkg>', 'package name (or name@version)')
  .argument('<capabilities...>', 'capabilities to revoke')
  .action((pkg: string, caps: string[]) => {
    const lock = denyCapabilitiesInLock(process.cwd(), pkg, caps)
    const granted = lock.packages[pkg]?.capabilities ?? []
    console.log(picocolors.green(`  ✔ ${pkg} → ${granted.join(', ') || '(no grants)'}`))
  })

program
  .command('show')
  .description('print the current capabilities.lock')
  .action(() => {
    const lock = loadLock(process.cwd())
    if (!lock) {
      console.log(picocolors.yellow('  no capabilities.lock — run: capwall init'))
      return
    }
    for (const [key, entry] of Object.entries(lock.packages)) {
      console.log(`  ${picocolors.bold(key)}`)
      console.log(`    ${entry.capabilities.map((c) => picocolors.cyan(c)).join(' ') || picocolors.dim('(no capabilities)')}`)
      for (const cap of entry.capabilities) {
        console.log(picocolors.dim(`      ${CAPABILITY_INFO[cap]?.label ?? cap}`))
      }
    }
  })

program
  .command('sbom')
  .description('security-enhanced SBOM operations (NodeShield)')
  .command('export')
  .description('emit a DSSE-signed CycloneDX v1.6 SBOM with capwall:rwx properties')
  .option('--format <fmt>', 'output format', 'cyclonedx')
  .option('--out <file>', 'output path', 'capwall-sbom.json')
  .action((opts: { format: string; out: string }) => {
    if (opts.format !== 'cyclonedx') throw new Error(`unsupported format: ${opts.format}`)
    const path = exportCycloneDxSbom(process.cwd(), opts.out)
    console.log(picocolors.green(`  ✔ wrote ${path} (CycloneDX 1.6, DSSE-signed)`))
  })

program
  .command('keys')
  .description('manage the local Ed25519 attestation keystore (.capwall/keys.json)')
  .command('generate')
  .description('generate root + developer/ci/runtime functionary keypairs')
  .action(() => {
    const path = attestKeysGenerate(process.cwd())
    console.log(picocolors.green(`  ✔ wrote ${path} (root, developer-passkey, ci-runner, prod-runtime)`))
    console.log(picocolors.yellow('  ⚠ keep this file secret — it contains private keys'))
  })

const attest = program.command('attest').description('in-toto + DSSE supply-chain attestations')

attest
  .command('layout')
  .description('create and sign root.layout binding functionary keys to Capwall steps')
  .option('--out <file>', 'layout output path', 'root.layout')
  .action((opts: { out: string }) => {
    const path = attestLayout(process.cwd(), opts.out)
    console.log(picocolors.green(`  ✔ wrote ${path} (steps: git_checkout → ast_capability_scan → build → runtime_enforcement)`))
  })

attest
  .command('checkout-link')
  .description('emit the signed git-checkout link (products: package manifests)')
  .action(() => {
    const path = attestCheckoutLink(process.cwd())
    console.log(picocolors.green(`  ✔ wrote ${path}`))
  })

attest
  .command('build-link')
  .description('emit the signed build link (materials: manifests + lock, products: dist/**)')
  .action(() => {
    const path = attestBuildLink(process.cwd())
    console.log(picocolors.green(`  ✔ wrote ${path}`))
  })

attest
  .command('scan-link')
  .description('emit the signed AST-scan link (materials: manifests, products: capabilities.lock)')
  .action(() => {
    const path = attestScanLink(process.cwd())
    console.log(picocolors.green(`  ✔ wrote ${path}`))
  })

attest
  .command('runtime-link')
  .description('emit the signed runtime-enforcement link with RBOM telemetry')
  .option('--telemetry <file>', 'telemetry JSON (default: .capwall/telemetry/latest.json)')
  .action((opts: { telemetry?: string }) => {
    const path = attestRuntimeLink(process.cwd(), { telemetryFile: opts.telemetry })
    console.log(picocolors.green(`  ✔ wrote ${path}`))
  })

attest
  .command('emit-all')
  .description('emit the complete four-step chain (checkout → scan → build → runtime)')
  .action(() => {
    for (const path of attestEmitAll(process.cwd())) {
      console.log(picocolors.green(`  ✔ wrote ${path}`))
    }
  })

attest
  .command('verify')
  .description('verify the full supply chain: layout signature, functionaries, artifact rules')
  .option('--layout <file>', 'layout path', 'root.layout')
  .option('--links <dir>', 'links directory', '.capwall/links')
  .action((opts: { layout: string; links: string }) => {
    const result = attestVerify(process.cwd(), { layoutPath: opts.layout, linksDir: opts.links })
    for (const step of result.steps) {
      const mark = step.ok ? picocolors.green('✔') : picocolors.red('✖')
      console.log(`  ${mark} ${step.name}`)
      for (const err of step.errors) console.log(picocolors.red(`      ${err}`))
    }
    for (const err of result.errors) console.log(picocolors.red(`  ${err}`))
    if (result.ok) {
      console.log(picocolors.green(`\n  ✔ ${result.summary}`))
      if (result.recordHash) {
        console.log(picocolors.dim(`  attestation record: ${result.recordHash.slice(0, 34)}…`))
      }
    } else {
      console.log(picocolors.red(`\n  ✖ ${result.summary}`))
      process.exitCode = 1
    }
  })


program
  .command('wrap')
  .description('wrap an AI agent, MCP server (stdio) or lifecycle script in the DIFC shield')
  .argument('<cmd...>', 'command to wrap, e.g. -- claude')
  .option('--agent <agent>', 'claude | cursor | codex | mcp', 'claude')
  .option('--mode <mode>', 'enforce | audit', 'enforce')
  .allowExcessArguments(true)
  .enablePositionalOptions()
  .action(async (cmd: string[], opts: { agent: 'claude' | 'cursor' | 'codex' | 'mcp'; mode: 'enforce' | 'audit' }) => {
    const code = await wrapCommand(cmd, { agent: opts.agent, mode: opts.mode })
    process.exitCode = code
  })

const mcpCmd = program.command('mcp').description('MCP server security (MCP-ITP / rug-pull)')
mcpCmd
  .command('scan')
  .description("audit a live MCP server's tools/list (or a saved tools.json file) for implicit tool poisoning")
  .argument('<server>')
  .argument('[cmd...]', 'server command (or a single tools/list .json file path)')
  .allowExcessArguments(true)
  .enablePositionalOptions()
  .action((server: string, cmd: string[]) => {
    const report = mcpScan(server, cmd.length ? cmd : [server])
    console.log(`\n  ${picocolors.bold(report.server)} — ${report.toolCount} tool(s) · pin ${report.pin.slice(0, 16)}…`)
    if (report.clean) {
      console.log(picocolors.green('  ✔ no implicit-tool-poisoning findings'))
      return
    }
    for (const finding of report.findings) {
      console.log(picocolors.red(`  ✖ ${finding.tool}`))
      for (const f of finding.findings) console.log(picocolors.dim(`      ${f}`))
    }
    process.exitCode = 1
  })
mcpCmd
  .command('lock')
  .description('pin the tools/list schema digest (blocks rug-pull drift)')
  .argument('<server>')
  .argument('[cmd...]', 'server command (or a single tools/list .json file path)')
  .allowExcessArguments(true)
  .enablePositionalOptions()
  .action((server: string, cmd: string[]) => {
    const { pin, path } = mcpLock(server, cmd.length ? cmd : [server])
    console.log(picocolors.green(`  ✔ pinned ${server} → ${pin.slice(0, 24)}… (${path})`))
  })

const taintCmd = program.command('taint').description('inspect or clear the persisted SPA taint ledger')
taintCmd.command('status').description('list persisted taint labels').action(() => {
  const { entries, ledgerPath } = taintStatus()
  if (entries.length === 0) {
    console.log(picocolors.dim(`  no persisted taint (${ledgerPath})`))
    return
  }
  for (const entry of entries) {
    console.log(`  ${picocolors.bold(entry.label)}  ${entry.path} ${picocolors.dim(entry.sha256 + '…')}`)
  }
})
taintCmd.command('clear').description('delete the taint ledger').action(() => {
  console.log(taintClear() ? picocolors.green('  ✔ taint ledger cleared') : picocolors.dim('  no ledger to clear'))
})

const agentCmd = program.command('agent').description('agent-host deep integration')
agentCmd
  .command('install')
  .argument('[host]', 'claude', 'claude')
  .description('install the PreToolUse hook into .claude/settings.json')
  .action((host: string) => {
    if (host !== 'claude') throw new Error(`unsupported host: ${host} (wrap --agent=${host} covers stdio/MCP)`)
    const hookBin = join(dirname(fileURLToPath(import.meta.url)), 'agent-hook.mjs')
    const settingsPath = join(process.cwd(), '.claude', 'settings.json')
    let settings: Record<string, unknown> = {}
    try { settings = JSON.parse(readFileSync(settingsPath, 'utf8')) } catch { /* new */ }
    const hooks = (settings.hooks ?? {}) as Record<string, unknown[]>
    hooks.PreToolUse = [{ matcher: '*', hooks: [{ type: 'command', command: `node ${hookBin}` }] }]
    settings.hooks = hooks
    mkdirSync(dirname(settingsPath), { recursive: true })
    writeFileSync(settingsPath, JSON.stringify(settings, null, 2))
    console.log(picocolors.green(`  ✔ PreToolUse hook installed → ${settingsPath}`))
  })

program.parseAsync().catch((err: Error) => {
  console.error(picocolors.red(`  ✖ ${err.message}`))
  process.exitCode = 1
})
