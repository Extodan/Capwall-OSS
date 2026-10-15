import { defineConfig } from 'tsup'

export default defineConfig([
  {
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'node20',
  },
  {
    entry: { 'mcp-shim': 'src/mcp-shim.ts', 'wrap-preload': 'src/wrap-preload.ts' },
    format: ['esm'],
    outDir: 'dist',
    outExtension: () => ({ js: '.mjs' }),
    dts: false,
    clean: false,
    target: 'node20',
  },
])
