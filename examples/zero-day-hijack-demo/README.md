# zero-day-hijack-demo — one command, four attacks, one wall

A "color logger" dependency that got hijacked. It steals your `.env`, plants a
prototype-pollution gadget, exfiltrates over HTTP behind a `setTimeout`, and
shells out laterally. Nothing destructive; everything realistic.

```bash
cd examples/zero-day-hijack-demo
npm run test:capwall     # generates a zero-trust lock, then runs UNDER capwall
npm run test:attack      # the same app with no protection, for contrast
```

Under capwall every vector dies at the module boundary with
`ERR_CAPWALL_CAPABILITY_DENIED` — env read, gadget, exfil fetch and
`child_process` — while `colorize()` still returns your string. The demo uses
the published CLI (`npx @extodan/capwall`), no clone required.

Scoped grants (predicates) are the follow-up: grant the logger
`env: ["LOG_LEVEL"]` and `hosts: ["logs.internal"]` in its `scopes` and it can
touch exactly those, nothing else.
