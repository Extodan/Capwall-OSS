# @extodan/capwall-runtime-node

The enforcement hook. Load with:

```bash
node --import @extodan/capwall-runtime-node app.js
# or
capwall run -- node app.js
```

**Coverage** (ESM and CJS both):
- **ESM imports** — `module.registerHooks()` resolve hook (in-thread, Node ≥ 22.15; falls back to loader-thread `register()` on older Node). Attribution from `parentURL` — deterministic.
- **CJS require** — `Module._load` patch; attribution from `parent.filename`.
- **`process.env`** — Proxy-wrapped; stack-trace attribution to the first `node_modules` frame (the runtime's own frames are skipped).
- **global `fetch`** — wrapped, same stack attribution.

**Semantics** — host app code is never restricted. Managed packages:
- granted capability → allowed, recorded as *exercised* (RBOM telemetry)
- recognized package, missing grant → **blocked** (throws `ERR_CAPWALL_CAPABILITY_DENIED`), per-entry `onViolation: warn` override supported
- unrecognized package → `defaults.unrecognized` (`warn` | `block` | `allow`)

**Outputs** — red console banner with the exact `capwall allow …` fix, `.capwall/audit.jsonl`
(every violation), `.capwall/telemetry/latest.json` (RBOM: loaded packages, exercised RWXi
capabilities, violations, enforced-lock SHA-256 — feeds `capwall attest runtime-link`),
optional streaming to the dashboard via `CAPWALL_COLLECTOR_URL` (+ `CAPWALL_COLLECTOR_TOKEN`).

**Bootstrap hardening** (spec: primordials frozen before userland): add
`"hardening": { "freezePrototypes": true }` to capabilities.lock (or
`CAPWALL_FREEZE_PROTOTYPES=1`) → `Object.prototype` frozen. Deep tier —
`"hardening": { "freezePrimordials": true }` or `CAPWALL_FREEZE_PRIMORDIALS=1` —
freezes constructors + prototypes of the full intrinsic set (Object, Function,
Array, String, Number, Symbol, Math, JSON, Date, RegExp, Error family, Promise,
collections, typed arrays…; `globalThis` deliberately excluded since Node and
userland legitimately add globals). Both tiers run before userland loads;
normal apps are unaffected (verified in tests). Independently,
stack attribution snapshots/restores `Error.prepareStackTrace`, so a poisoned
formatter can't hide attacker frames from attribution. Default remains
compat-off; the exploit lab ships it enabled.

**First-loader guarantee** — a preload hook can only enforce what loads after
it; earlier code may hold pristine references that bypass every gate (SES
compartments are the full answer). Until then Capwall detects the condition:
other `--import`/`--require` preloads (execArgv + NODE_OPTIONS) or resident
node_modules modules at install time → loud warning, or fail-closed
(`CAPWALL_REQUIRE_FIRST=1`, exit 78) — an unprovable guarantee is never
silently claimed.

Kill switch: `CAPWALL_DISABLE=1`. Lock path override: `CAPWALL_LOCK`.

**Honest boundary** — a capability gate, not a sandbox: it stops the standard, mundane
attack paths (builtin imports, env reads, fetch exfil). A package that obtains references
before the hook installs, or abuses unhooked APIs, is out of scope by design.
