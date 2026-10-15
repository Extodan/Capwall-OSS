import { defineConfig } from 'tsup'

// The loader hook must be plain ESM (runs in Node's loader thread);
// register must be ESM for `node --import`. Core is bundled in — the
// hook cannot depend on a resolvable workspace layout at runtime.
export default defineConfig({
  entry: {
    register: 'src/register.ts',
    loader: 'src/loader.ts',
    'cp-shim': 'src/cp-shim.ts',
  },
  format: ['esm'],
  outDir: 'dist',
  outExtension: () => ({ js: '.mjs' }),
  dts: false,
  splitting: false,
  clean: true,
  target: 'node20',
  noExternal: ['@capwall/core'],
  banner: {
    js: '/* Capwall runtime — capability enforcement for node_modules. Apache-2.0. */',
  },
})
