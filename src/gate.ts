/**
 * The pre-execution gate. A `tools/pre-execute` waterfall listener: it
 * classifies the file argument of gated tools against the policy engine and
 * returns `{ kind: 'deny' }` (short-circuiting the waterfall) for blocked
 * operations, so the tool body never runs. Denials carry guidance toward the
 * safe inspection tools and are recorded in the audit journal.
 */

import type { PreToolDecision, ToolExecution } from '@deepseek-ai/dsh-tools'
import type { Classification, PolicyEngine } from './policy.ts'
import { normalizePath } from './policy.ts'
import type { Journal } from './journal.ts'
import type { ResolvedConfig } from './config.ts'

export type PreExecuteHandler = (
  exec: ToolExecution,
  next: () => Promise<PreToolDecision>,
) => Promise<PreToolDecision>

/** Which argument key holds the target path for each gated tool. */
export const PATH_ARG_KEY: Record<string, 'file_path' | 'path'> = {
  read: 'file_path',
  read_image: 'file_path',
  write: 'file_path',
  edit: 'file_path',
  glob: 'path',
  grep: 'path',
}

/** Tools that surface file content (read-like) vs. tools that mutate (write-like). */
export const READ_LIKE = new Set(['read', 'read_image', 'glob', 'grep'])
export const WRITE_LIKE = new Set(['write', 'edit'])

export function extractGatedPath(tool: string, args: unknown): string | undefined {
  if (typeof args !== 'object' || args === null) return undefined
  const key = PATH_ARG_KEY[tool]
  if (key === undefined) return undefined
  const value = (args as Record<string, unknown>)[key]
  return typeof value === 'string' ? value : undefined
}

/**
 * Search patterns that could select secret material. A `grep` for `password`
 * across a workspace would otherwise surface `.env` lines; the scrubber is the
 * final safety net for the rest. The pattern is a REGEX, so before the keyword
 * test we strip common regex metacharacters (`pass.?word` -> `password`) —
 * the guard stays a heuristic, never a boundary.
 */
const SEARCH_KEYWORD = /(?:\.env|credential|secret|passw|api[_-]?key|access[_-]?key|private[_-]?key|BEGIN(?: |\r?\n)?[A-Z0-9 ]*PRIVATE)/i

/**
 * Coarse de-regexing: keep what the pattern can literally contain, drop what
 * it may omit. `x*`/`x?` can match zero `x`, so we test BOTH interpretations —
 * keeping one copy catches `p*assword`, dropping the quantified character
 * catches insertions like `aP\Is*KeY`; character classes contribute their
 * contents. The guard stays a heuristic, never a boundary.
 */
function searchLooksSuspicious(pattern: string): boolean {
  const keepCopy = pattern
    .replace(/([A-Za-z0-9])[*+?]/g, '$1')
    .replace(/\{[^}]*\}/g, '')
    .replace(/\\/g, '')
    .replace(/\[([^\]]*)\]/g, '$1')
    .replace(/[*+?()|^$.]/g, '')
  const dropChar = pattern
    .replace(/([A-Za-z0-9])[*+?]/g, '')
    .replace(/\{[^}]*\}/g, '')
    .replace(/\\/g, '')
    .replace(/\[([^\]]*)\]/g, '$1')
    .replace(/[*+?()|^$.]/g, '')
  return SEARCH_KEYWORD.test(pattern) || SEARCH_KEYWORD.test(keepCopy) || SEARCH_KEYWORD.test(dropChar)
}

function isBlocked(tool: string, c: Classification): boolean {
  if (c.effect === 'block') return true
  if (c.effect === 'block-read' && READ_LIKE.has(tool)) return true
  if (c.effect === 'block-write' && WRITE_LIKE.has(tool)) return true
  return false
}

function denyReason(tool: string, path: string, c: Classification): string {
  const rule = c.rule
  const parts = [
    `secret-guard blocked ${READ_LIKE.has(tool) ? 'read' : 'write'} of '${path}'`,
    rule !== undefined ? `(rule '${rule.id}', effect ${rule.effect})` : '',
    rule?.reason !== undefined ? `- ${rule.reason}` : '',
    'If you need to inspect this file safely, use sg_keys / sg_scan / sg_probe / sg_fingerprint; they never return raw values.',
    'To permit this path, add it to the plugin allow list (see README).',
  ]
  return parts.filter(Boolean).join(' ')
}

function searchDenyReason(): string {
  return "secret-guard blocked the search (search-keyword-guard): its pattern may select secret material. Narrow the pattern or path, or use sg_scan / sg_probe to inspect known env files."
}

export function createGateHandler(deps: {
  getEngine: () => PolicyEngine
  journal: Journal
  config: ResolvedConfig
}): PreExecuteHandler {
  return async (exec, next) => {
    const tool = exec.name
    if (!deps.config.gateTools.includes(tool)) return next()
    const args = exec.arguments
    const path = extractGatedPath(tool, args)
    if (path !== undefined) {
      const classification = deps.getEngine().classify(path)
      if (isBlocked(tool, classification)) {
        deps.journal.write({
          ts: new Date().toISOString(),
          kind: 'block',
          tool,
          path: normalizePath(path),
          rule: classification.rule?.id,
          effect: classification.rule?.effect,
        })
        return { kind: 'deny', reason: denyReason(tool, path, classification) }
      }
    }
    if (
      tool === 'grep'
      && deps.config.guardSearchPatterns
      && typeof args === 'object'
      && args !== null
      && typeof (args as Record<string, unknown>).pattern === 'string'
    ) {
      const pattern = (args as { pattern: string }).pattern
      if (searchLooksSuspicious(pattern)) {
        deps.journal.write({
          ts: new Date().toISOString(),
          kind: 'block',
          tool,
          message: 'search pattern matched sensitive keywords',
        })
        return { kind: 'deny', reason: searchDenyReason() }
      }
    }
    return next()
  }
}
