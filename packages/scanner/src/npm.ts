import type { PackageMeta } from '@capwall/core'
import semver from 'semver'
import { fetchBuffer, fetchJson, HttpError, type FetchLike } from './util.js'

const REGISTRY = 'https://registry.npmjs.org'
const DOWNLOADS_API = 'https://api.npmjs.org/downloads/point/last-week'

export interface RegistryVersionMeta {
  version: string
  tarballUrl: string
  dependencies: Record<string, string>
  meta: PackageMeta
}

export interface Packument {
  'dist-tags'?: Record<string, string>
  versions: Record<
    string,
    {
      deprecated?: string
      scripts?: Record<string, string>
      repository?: unknown
      dependencies?: Record<string, string>
      dist?: { tarball?: string; shasum?: string }
      maintainers?: unknown[]
      license?: string
      description?: string
    }
  >
  time?: Record<string, string>
  maintainers?: unknown[]
}

/** npm registry client with per-process caching and an injectable fetch for tests. */
export class NpmRegistry {
  private packuments = new Map<string, Promise<Packument | null>>()
  private tarballs = new Map<string, Promise<Buffer>>()
  private downloads = new Map<string, Promise<number | null>>()

  constructor(private fetchImpl: FetchLike) {}

  async packument(name: string): Promise<Packument | null> {
    let promise = this.packuments.get(name)
    if (!promise) {
      promise = fetchJson<Packument>(this.fetchImpl, `${REGISTRY}/${encodeURIComponent(name)}`)
        .catch((err) => {
          if (err instanceof HttpError && err.status === 404) return null
          throw err
        })
        // Cache failures briefly so one bad package does not retry-loop.
        .then((p) => {
          if (p === null) setTimeout(() => this.packuments.delete(name), 30_000).unref?.()
          return p
        })
      this.packuments.set(name, promise)
    }
    return promise
  }

  /** Resolve a semver range (or tag) to concrete version metadata. */
  async resolve(name: string, range: string): Promise<RegistryVersionMeta | null> {
    const packument = await this.packument(name)
    if (!packument) return null

    let version = packument['dist-tags']?.[range] // tag like "latest"
    if (!version) {
      const candidates = Object.keys(packument.versions ?? {}).filter((v) => semver.valid(v))
      version =
        (range === '*' || range === 'latest'
          ? candidates.at(-1)
          : semver.maxSatisfying(candidates, range, { includePrerelease: false }) ?? undefined)
    }
    const v = packument.versions?.[version ?? '']
    if (!version || !v) return null

    const time = packument.time?.[version]
    const maintainers = v.maintainers ?? packument.maintainers
    return {
      version,
      tarballUrl: v.dist?.tarball ?? `${REGISTRY}/${name}/-/${name}-${version}.tgz`,
      dependencies: v.dependencies ?? {},
      meta: {
        lastPublished: time,
        maintainersCount: Array.isArray(maintainers) ? maintainers.length : undefined,
        deprecated: typeof v.deprecated === 'string',
        hasRepository: v.repository != null,
        hasInstallScript: ['preinstall', 'install', 'postinstall'].some((s) => v.scripts?.[s]),
        license: typeof v.license === 'string' ? v.license : undefined,
        description: v.description,
      },
    }
  }

  async tarball(url: string): Promise<Buffer> {
    let promise = this.tarballs.get(url)
    if (!promise) {
      promise = fetchBuffer(this.fetchImpl, url)
      this.tarballs.set(url, promise)
      promise.catch(() => this.tarballs.delete(url))
    }
    return promise
  }

  async weeklyDownloads(name: string): Promise<number | null> {
    let promise = this.downloads.get(name)
    if (!promise) {
      promise = fetchJson<{ downloads?: number }>(this.fetchImpl, `${DOWNLOADS_API}/${encodeURIComponent(name)}`)
        .then((d) => d.downloads ?? null)
        .catch(() => null)
      this.downloads.set(name, promise)
    }
    return promise
  }
}
