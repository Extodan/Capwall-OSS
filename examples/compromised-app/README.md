# compromised-app — scan target with REAL malicious versions

Every dependency here is a genuine, historic supply-chain incident, pinned to
the exact compromised release. The app itself does nothing and runs nothing.

| package | incident |
|---|---|
| `ua-parser-js@0.7.29` | Oct 2021 — published cryptominer + credential stealer (child_process dropper, obfuscated payload) |
| `event-stream@4.0.1` | Nov 2018 — the flatmap-stream incident, targeted Copay wallet theft |
| `node-ipc@9.2.6` | Mar 2022 — protestware that wiped filesystems of RU/BY users |
| `left-pad@1.3.0` | 2016 — the break-the-internet incident (deprecated, trust cautionary tale) |

Scan it:

- free scanner: paste `github.com/Extodan/Capwall-OSS/tree/main/examples/compromised-app`
- or: `curl -X POST <api>/api/scans -d '{"packageJson": "<this package.json>"}'`

Nothing here executes; the scanner only reads tarballs statically.

## What you'll see when you scan (and why)

- `ua-parser-js@0.7.29` and `node-ipc@9.2.6` are **absent from the report**:
  npm *removed those tarballs from the registry* after the incidents — the
  scanner reports only what it can fetch, and says so honestly rather than
  inventing results.
- `event-stream@4.0.1` resolves, but the attack lived in its transitive
  `flatmap-stream@0.1.1`, which npm also purged — so the chain shows clean.
- `left-pad@1.3.0` flags **high (60)**: deprecated + stale — the real,
  still-detectable signal.
- For a *live* malicious-code demo (env theft, exec, TCP exfil — benignly
  reproduced), see `examples/vulnerable-app` and `pnpm sim:demo`.
