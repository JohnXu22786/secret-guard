/**
 * Plugin configuration: the schemastery schema validated by the loader, plus
 * `resolveConfig`, which applies defaults, resolves relative paths against the
 * harness working directory, assigns rule ids and validates invariants
 * fail-loud. Rule compilation is shared with the hot-reload path.
 */

import z from 'schemastery'
import { isAbsolute, join } from 'node:path'
import type { Rule, RuleEffect } from './policy.ts'

export const DEFAULT_SEAL_ENV = 'SECRET_GUARD_SEAL_KEY'
export const DEFAULT_SEAL_PATH = '.secret-guard/seal.key'
export const DEFAULT_AUDIT_DIR = '.secret-guard/logs'
export const DEFAULT_GATE_TOOLS = ['read', 'write', 'edit', 'glob', 'grep', 'read_image']
export const DEFAULT_AUDIT_MAX_BYTES = 1024 * 1024
export const DEFAULT_AUDIT_KEEP = 5

export const EFFECTS = ['allow', 'block-read', 'block-write', 'block'] as const

export interface RuleInput {
  id?: string
  match: string
  effect?: RuleEffect
  reason?: string
}

export interface PluginConfig {
  /** Custom rules, evaluated before the built-in table. */
  rules?: RuleInput[]
  /** Path patterns that are always allowed (checked before any rule). */
  allow?: string[]
  /** Tool names whose file arguments are gated. */
  gateTools?: string[]
  /** Also block `grep` patterns that look secret-oriented. */
  guardSearchPatterns?: boolean
  /** Mask secret-shaped values in tool results (defense in depth). */
  maskResults?: boolean
  /** HMAC seal key: env var name + file path. */
  sealKey?: { env?: string; path?: string }
  /** JSONL audit journal settings. */
  audit?: { enabled?: boolean; dir?: string; maxBytes?: number; keep?: number }
  /** External JSON rules file, hot-reloadable at runtime. */
  rulesFile?: string
  /** Watch `rulesFile` for changes and reload automatically. */
  watchRules?: boolean
}

export const Config = z.object({
  rules: z.array(z.object({
    id: z.string().default(''),
    match: z.string(),
    effect: z.union([
      z.const('allow'),
      z.const('block-read'),
      z.const('block-write'),
      z.const('block'),
    ]).default('block'),
    reason: z.string().default(''),
  })).default([]),
  allow: z.array(z.string()).default([]),
  gateTools: z.array(z.string()).default([...DEFAULT_GATE_TOOLS]),
  guardSearchPatterns: z.boolean().default(true),
  maskResults: z.boolean().default(true),
  sealKey: z.object({
    env: z.string().default(DEFAULT_SEAL_ENV),
    path: z.string().default(DEFAULT_SEAL_PATH),
  }),
  audit: z.object({
    enabled: z.boolean().default(true),
    dir: z.string().default(DEFAULT_AUDIT_DIR),
    maxBytes: z.number().default(DEFAULT_AUDIT_MAX_BYTES),
    keep: z.number().default(DEFAULT_AUDIT_KEEP),
  }),
  rulesFile: z.string().default(''),
  watchRules: z.boolean().default(true),
})

export interface ResolvedConfig {
  rules: Rule[]
  allow: string[]
  gateTools: string[]
  guardSearchPatterns: boolean
  maskResults: boolean
  sealKey: { env: string; path: string }
  audit: { enabled: boolean; dir: string; maxBytes: number; keep: number }
  rulesFile: string
  watchRules: boolean
  /** Base directory for every relative path in the config. */
  cwd: string
}

/** Validate raw rule entries and return them with guaranteed ids. */
export function compileRules(raw: unknown): Rule[] {
  if (raw === undefined) return []
  if (!Array.isArray(raw)) throw new Error('rules must be an array')
  return raw.map((item, i) => {
    if (typeof item !== 'object' || item === null) throw new Error(`rules[${i}] must be an object`)
    const o = item as Record<string, unknown>
    const id = typeof o.id === 'string' && o.id.trim() !== '' ? o.id.trim() : `custom-${i}`
    const reason = typeof o.reason === 'string' ? o.reason : undefined
    const match = typeof o.match === 'string' ? o.match.trim() : ''
    if (match === '') throw new Error(`rules[${i}].match must be a non-empty string`)
    const effect = o.effect
    if (effect === undefined) {
      // Consistent with the schemastery schema default for `rules` entries.
      return { id, match, effect: 'block' as RuleEffect, ...(reason !== undefined && reason !== '' ? { reason } : {}) }
    }
    if (typeof effect !== 'string' || !(EFFECTS as readonly string[]).includes(effect)) {
      throw new Error(`rules[${i}].effect must be one of: ${EFFECTS.join(', ')}`)
    }
    return { id, match, effect: effect as RuleEffect, ...(reason !== undefined && reason !== '' ? { reason } : {}) }
  })
}

/** Validate raw allow-list entries and drop blanks. */
export function compileAllowList(raw: unknown): string[] {
  if (raw === undefined) return []
  if (!Array.isArray(raw)) throw new Error('allow must be an array of patterns')
  return raw.map(s => (typeof s === 'string' ? s.trim() : '')).filter(s => s !== '')
}

export function resolveConfig(raw: unknown, cwd = process.cwd()): ResolvedConfig {
  let input: ReturnType<typeof Config>
  try {
    input = Config(raw ?? {})
  } catch (error) {
    throw new Error(`secret-guard: invalid plugin config: ${(error as Error).message}`)
  }
  const rules = compileRules(input.rules)
  const audit = input.audit
  if (!Number.isInteger(audit.maxBytes) || audit.maxBytes < 1) {
    throw new Error(`secret-guard: audit.maxBytes must be a positive integer (got ${audit.maxBytes})`)
  }
  if (!Number.isInteger(audit.keep) || audit.keep < 1) {
    throw new Error(`secret-guard: audit.keep must be a positive integer (got ${audit.keep})`)
  }
  const sealPath = input.sealKey.path
  if (sealPath.trim() === '') throw new Error('secret-guard: sealKey.path must not be empty')
  const auditDir = audit.dir
  if (auditDir.trim() === '') throw new Error('secret-guard: audit.dir must not be empty')
  return {
    rules,
    allow: compileAllowList(input.allow),
    gateTools: [...input.gateTools],
    guardSearchPatterns: input.guardSearchPatterns,
    maskResults: input.maskResults,
    sealKey: {
      env: input.sealKey.env,
      path: isAbsolute(sealPath) ? sealPath : join(cwd, sealPath),
    },
    audit: {
      enabled: audit.enabled,
      dir: isAbsolute(auditDir) ? auditDir : join(cwd, auditDir),
      maxBytes: audit.maxBytes,
      keep: audit.keep,
    },
    rulesFile: input.rulesFile === '' ? '' : isAbsolute(input.rulesFile) ? input.rulesFile : join(cwd, input.rulesFile),
    watchRules: input.watchRules,
    cwd,
  }
}
