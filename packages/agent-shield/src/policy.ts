import { z } from 'zod'

/**
 * The optional `agents_and_mcp:` section of capabilities.lock.
 * Core's v1 lockfile parser strips unknown keys, so this section is parsed
 * separately by the Agent Shield — the core schema stays frozen.
 */

const RwxRule = z.object({
  fs_read: z.union([z.array(z.string()), z.literal('none')]).default([]),
  fs_write: z.union([z.array(z.string()), z.literal('none')]).default('none'),
  env: z.union([z.array(z.string()), z.literal('none'), z.literal('all')]).default('none'),
  network: z.union([z.array(z.string()), z.literal('none'), z.literal('all')]).default('none'),
  shell: z.boolean().default(false),
})

const TaintPolicy = z.object({
  confidentiality_level: z.enum(['PUBLIC', 'INTERNAL', 'SECRET']).default('INTERNAL'),
  block_on_untrusted_integrity: z.boolean().default(true),
})

const McpServer = z.object({
  transport: z.enum(['stdio', 'http', 'sse']).default('stdio'),
  rwx: RwxRule.default({}),
  taint_policy: TaintPolicy.default({}),
})

const EvidentialContract = z.object({
  require_fresh_test_pass: z.boolean().default(true),
  require_clean_capability_diff: z.boolean().default(true),
  /** Receipts older than this (ms) are stale regardless of writes. */
  max_receipt_age_ms: z.number().int().positive().default(30 * 60_000),
})

export const AgentsAndMcp = z.object({
  mcp_servers: z.record(z.string(), McpServer).default({}),
  evidential_contracts: z
    .object({
      on_git_commit_or_push: EvidentialContract.default({}),
      on_pr_merge: EvidentialContract.default({}),
      on_task_complete: EvidentialContract.default({}),
    })
    .default({}),
  /** Domains exempt from the SECRET→sink block (telemetry allowlist). */
  sink_allowlist_domains: z.array(z.string()).default([]),
})

export type RwxRule = z.infer<typeof RwxRule>
export type AgentsAndMcp = z.infer<typeof AgentsAndMcp>
export type McpServer = z.infer<typeof McpServer>
export type EvidentialContract = z.infer<typeof EvidentialContract>

export function parseAgentsAndMcp(lockRaw: unknown): AgentsAndMcp {
  const section = (lockRaw as { agents_and_mcp?: unknown })?.agents_and_mcp
  if (section === undefined) return AgentsAndMcp.parse({})
  return AgentsAndMcp.parse(section)
}
