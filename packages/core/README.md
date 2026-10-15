# @extodan/capwall-core

The shared brain: capability model, `capabilities.lock` schema, and the risk model.
Consumed by scanner, runtime, CLI, API and web — zero runtime deps except zod.

- `capabilities.ts` — the 11 capabilities, severity metadata, builtin→capability map
- `lockfile.ts` — `capabilities.lock` v1 (zod-validated; JSON schema in `schema/`), allow/deny mutations, `name@version` / bare-name lookup
- `risk.ts` — transparent additive scoring (weights are data, surfaced in the dashboard)
- `types.ts` — `ScanReport`, `PackageReport`, `ViolationEvent`, `ScanProgress`

```ts
import { parseLock, grantedCapabilities } from '@extodan/capwall-core'
const lock = parseLock(readFileSync('capabilities.lock', 'utf8'))
grantedCapabilities(lock, 'leftpad', '1.3.0') // → ['env.read']
```
