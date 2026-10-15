export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>

export const DEFAULT_FETCH: FetchLike = (url, init) => fetch(url, init)

/** Tiny concurrency pool; keeps registry traffic polite. */
export async function mapWithPool<T, R>(
  items: T[],
  limit: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length)
  let cursor = 0
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor++
      results[index] = await worker(items[index]!, index)
    }
  })
  await Promise.all(runners)
  return results
}

export class HttpError extends Error {
  constructor(
    public status: number,
    url: string,
  ) {
    super(`HTTP ${status} for ${url}`)
  }
}

export async function fetchJson<T>(fetchImpl: FetchLike, url: string): Promise<T> {
  const res = await fetchImpl(url, {
    headers: { accept: 'application/json', 'user-agent': 'capwall-scanner (https://capwall.dev)' },
  })
  if (!res.ok) throw new HttpError(res.status, url)
  return (await res.json()) as T
}

export async function fetchBuffer(fetchImpl: FetchLike, url: string): Promise<Buffer> {
  const res = await fetchImpl(url, {
    headers: { 'user-agent': 'capwall-scanner (https://capwall.dev)' },
  })
  if (!res.ok) throw new HttpError(res.status, url)
  return Buffer.from(await res.arrayBuffer())
}
