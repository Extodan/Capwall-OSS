# @extodan/capwall-scanner

Static capability analysis for npm packages. Nothing executes — ever.

Three inputs:
- **local tree** (`scanLocalTree(dir)`) — walks `node_modules` (incl. one nested level), offline
- **raw manifest** (`analyzeManifest(pkgJson, source)`) — resolves deps from the npm registry, downloads tarballs, AST-scans them (the "viral scanner" path: full scan, zero install)
- **GitHub URL** (`fetchGitHubPackageJson`) — grabs the manifest from any public repo

The AST pass (acorn + acorn-walk, source-type agnostic) detects: builtin `require`/`import`
(`node:fs`, `child_process`, `net`, …), `require.resolve` intent, `process.env` reads/writes
(with variable names), `eval` / `new Function` / `vm`, global `fetch`, network libraries
(axios, node-fetch, got, …) as signals, and high-entropy base64/hex blobs as obfuscation
(charset-entropy filtered so benchmark data doesn't false-positive). Non-runtime dirs
(`test/`, `perf/`, `bench/`, `examples/`, `docs/`) are skipped in tarballs.

Registry access is capped and polite: depth ≤ 2, ≤ 60 packages, concurrency 8, per-process
caching, injectable `fetch` (see the offline test suite).
