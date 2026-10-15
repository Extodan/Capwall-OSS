import { analyzeSource, mergeFindings, type MergedFindings } from './ast.js'

const MAX_FILE_BYTES = 2 * 1024 * 1024 // skip files > 2MB (minified monsters)
const MAX_FILES = 400

/** Directories that never ship as runtime code — benchmarks, tests, docs, examples. */
const NON_RUNTIME_DIRS = /(?:^|\/)(?:test|tests|__tests__|benchmark|bench|perf|examples?|fixtures|docs?|coverage|\.github)(?:\/|$)/i

export function isRuntimeCode(path: string): boolean {
  return !NON_RUNTIME_DIRS.test(path)
}

export interface TarballPackageJson {
  name?: string
  version?: string
  dependencies?: Record<string, string>
  scripts?: Record<string, string>
}

export interface TarballScanResult extends MergedFindings {
  pkgJson: TarballPackageJson | null
}

/**
 * Scan an npm tarball buffer: extract package/package.json plus JS sources,
 * run the AST pass over each. Never throws on malformed archives.
 */
export async function scanTarball(tgz: Buffer): Promise<TarballScanResult> {
  const { extract } = await import('tar-stream')
  const zlib = await import('node:zlib')

  const files: { path: string; content: string }[] = []
  let pkgJson: TarballPackageJson | null = null

  await new Promise<void>((resolve, reject) => {
    const parser = extract()
    // Malformed archives resolve with whatever was collected so far — never throw.
    const settle = (err: Error | null | undefined) => (err ? reject(err) : resolve())

    parser.on('entry', (header, stream, next) => {
      const path = String(header.name ?? '')
      const isJs = /\.(js|cjs|mjs)$/i.test(path) && isRuntimeCode(path)
      const isManifest = /(?:^|\/)package\.json$/.test(path) && !path.includes('node_modules')

      if ((!isJs && !isManifest) || (isJs && files.length >= MAX_FILES)) {
        stream.resume()
        next()
        return
      }

      const chunks: Buffer[] = []
      let size = 0
      let skipped = false
      stream.on('data', (chunk: unknown) => {
        const buf = chunk as Buffer
        size += buf.length
        if (size > MAX_FILE_BYTES) {
          skipped = true
          stream.resume()
        } else if (!skipped) {
          chunks.push(buf)
        }
      })
      stream.on('end', () => {
        if (!skipped) {
          if (isManifest) {
            try {
              pkgJson = JSON.parse(Buffer.concat(chunks).toString('utf8'))
            } catch {
              /* malformed manifest — ignore */
            }
          } else {
            files.push({ path, content: Buffer.concat(chunks).toString('utf8') })
          }
        }
        next()
      })
      stream.on('error', () => next())
    })
    parser.on('finish', () => resolve())
    parser.on('error', (err) => settle(err))

    const isGzip = tgz[0] === 0x1f && tgz[1] === 0x8b
    let input: { end: (data?: Buffer) => void } = parser
    if (isGzip) {
      const gunzip = zlib.createGunzip()
      gunzip.on('error', (err) => settle(err))
      gunzip.pipe(parser)
      input = gunzip
    }
    input.end(tgz)
  }).catch(() => {
    /* malformed archive — keep whatever was extracted */
  })

  // §1 two-pass: pass 1 collects cross-file hints (tainted exports/functions),
  // pass 2 re-analyzes with them — closes the intra-file-only gap.
  const first = files.map((f) => ({ path: f.path, findings: analyzeSource(f.content) }))
  const taintedSiblings = new Set<string>()
  const taintedFunctions = new Set<string>()
  for (const f of first) {
    if (f.findings.exportsTainted || f.findings.capabilities.size > 0) {
      const base = f.path.split('/').pop()!.replace(/\.js$/, '')
      taintedSiblings.add(base)
    }
    for (const fn of f.findings.taintedFunctions ?? []) taintedFunctions.add(fn)
  }
  const pass = (taintedSiblings.size > 0 || taintedFunctions.size > 0)
    ? files.map((f) => analyzeSource(f.content, { taintedSiblings, taintedFunctions }))
    : first.map((f) => f.findings)
  const merged = mergeFindings(pass)
  return { ...merged, pkgJson }
}
