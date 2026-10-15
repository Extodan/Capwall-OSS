import { chmodSync } from 'node:fs'
import { defineConfig } from 'tsup'

export default defineConfig([
  // CLI binary — plain ESM, dependencies resolved from node_modules at runtime.
  // The shebang comes from src/cli.ts line 1; esbuild keeps it on line 1.
  {
    entry: { cli: 'src/cli.ts', 'agent-hook': 'src/agent-hook.ts' },
    format: ['esm'],
    outDir: 'dist',
    outExtension: () => ({ js: '.mjs' }),
    dts: false,
    clean: false,
    target: 'node20',
    onSuccess: async () => {
      chmodSync('dist/cli.mjs', 0o755)
    },
  },
  // Programmatic API.
  {
    entry: { index: 'src/lib.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    outDir: 'dist',
    clean: false,
    target: 'node20',
  },
])
