# zero-day-hijack-demo — one command, four attacks, one wall

A "color logger" dependency that got hijacked — plus a poisoned MCP tools
document. Five real-world vectors, nothing destructive, everything realistic:
direct `.env` theft, async-context evasion (`setTimeout` → fetch exfil), a
GHunter prototype-pollution gadget, a NodeShield lateral `child_process`
import, and an MCP-ITP `~/.ssh` coercion payload.

```bash
cd examples/zero-day-hijack-demo
npm run demo:attack      # both runs + the 5-vector verdict table
                         # (uses the published CLI via npx — no clone needed)
```

Under capwall every vector dies at the module boundary with
`ERR_CAPWALL_CAPABILITY_DENIED` — env read, gadget, exfil fetch and
`child_process` — while `colorize()` still returns your string. The demo uses
the published CLI (`npx @extodan/capwall`), no clone required.

Scoped grants (predicates) are the follow-up: grant the logger
`env: ["LOG_LEVEL"]` and `hosts: ["logs.internal"]` in its `scopes` and it can
touch exactly those, nothing else.

`demo.tape` renders this exact command to `docs/demo.gif` with Charmbracelet
[vhs](https://github.com/charmbracelet/vhs): `vhs demo.tape`.
