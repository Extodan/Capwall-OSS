import { fetchJson, HttpError, type FetchLike } from './util.js'

export interface GitHubTarget {
  owner: string
  repo: string
  branch: string
  subdir: string
}

export class GitHubError extends Error {}

/**
 * Accepts: https://github.com/o/r, https://github.com/o/r.git,
 *          https://github.com/o/r/tree/main, https://github.com/o/r/tree/main/packages/app,
 *          or shorthand "o/r".
 */
export function parseGitHubUrl(input: string): { owner: string; repo: string; ref?: string; subdir?: string } {
  const trimmed = input.trim().replace(/\.git$/, '')
  const url = /^https?:\/\//.test(trimmed) ? new URL(trimmed) : null
  if (url && (url.hostname === 'github.com' || url.hostname === 'www.github.com')) {
    const parts = url.pathname.split('/').filter(Boolean)
    if (parts.length >= 2) {
      const [owner, repo, kind, ref, ...rest] = parts
      if (kind && kind !== 'tree') {
        throw new GitHubError(`Unsupported GitHub URL — expected /owner/repo or /owner/repo/tree/<branch>`)
      }
      return { owner: owner!, repo: repo!, ref: kind === 'tree' ? ref : undefined, subdir: kind === 'tree' ? `/${(rest ?? []).join('/')}` : '' }
    }
    throw new GitHubError('GitHub URL must include owner and repository')
  }
  const short = trimmed.match(/^([\w.-]+)\/([\w.-]+)$/)
  if (short) return { owner: short[1]!, repo: short[2]!, subdir: '' }
  throw new GitHubError(`Not a recognizable GitHub repository: ${input}`)
}

async function defaultBranch(fetchImpl: FetchLike, owner: string, repo: string): Promise<string> {
  try {
    const meta = await fetchJson<{ default_branch?: string }>(
      fetchImpl,
      `https://api.github.com/repos/${owner}/${repo}`,
    )
    return meta.default_branch ?? 'main'
  } catch (err) {
    if (err instanceof HttpError && err.status === 403) {
      throw new GitHubError(
        'GitHub API rate limit reached (60 req/hr unauthenticated). Try again later or paste the package.json directly.',
      )
    }
    if (err instanceof HttpError && err.status === 404) {
      throw new GitHubError(`Repository ${owner}/${repo} not found (or private).`)
    }
    throw err
  }
}

/** Fetch a repository's package.json content. */
export async function fetchGitHubPackageJson(
  fetchImpl: FetchLike,
  input: string,
): Promise<{ pkgJson: unknown; target: GitHubTarget }> {
  const { owner, repo, ref, subdir } = parseGitHubUrl(input)
  const branch = ref ?? (await defaultBranch(fetchImpl, owner, repo))
  const path = `${subdir ? `${subdir.replace(/^\//, '')}/` : ''}package.json`
  const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`

  let res: Response
  try {
    res = await fetchImpl(rawUrl, { headers: { 'user-agent': 'capwall-scanner' } })
  } catch (err) {
    throw new GitHubError(`Could not reach GitHub: ${(err as Error).message}`)
  }
  if (res.status === 404) {
    throw new GitHubError(`No package.json found at ${owner}/${repo}${subdir} (${branch})`)
  }
  if (!res.ok) throw new GitHubError(`GitHub returned HTTP ${res.status} for ${rawUrl}`)

  let pkgJson: unknown
  try {
    pkgJson = await res.json()
  } catch {
    throw new GitHubError(`package.json at ${rawUrl} is not valid JSON`)
  }
  return { pkgJson, target: { owner, repo, branch, subdir: subdir ?? '' } }
}
