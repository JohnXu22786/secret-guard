/**
 * secret-guard — a DeepSeek Harness (dsh) security plugin.
 *
 * What it does, in one paragraph:
 * - blocks agent file tools (`read`/`write`/`edit`, search tools) from
 *   touching sensitive files (.env, credentials, key material) before the
 *   tool body can run (`tools/pre-execute` waterfall);
 * - masks secret-shaped values that still reach tool results, as a
 *   defense-in-depth net (`tools/post-execute` waterfall);
 * - provides `sg_*` tools that inspect those same files safely (keys, shapes,
 *   fingerprints, boolean probes — never raw values);
 * - keeps a JSONL audit journal of blocks/masks/reloads, and can hot-reload
 *   its rules from an external JSON file (watched or via `sg_reload`).
 *
 * The plugin is self-contained and loads from source: dsh boots with a
 * TypeScript-aware loader, so no build step is needed.
 */

import type { Context } from '@deepseek-ai/cordis'
import { readFileSync } from 'node:fs'
import type {} from '@deepseek-ai/dsh-tools'
import {
  Config,
  compileAllowList,
  compileRules,
  resolveConfig,
  type PluginConfig,
} from './config.ts'
import { defaultRules, PolicyEngine } from './policy.ts'
import { Journal } from './journal.ts'
import { createGateHandler } from './gate.ts'
import { createScrubHandler } from './scrub.ts'
import { Fingerprinter } from './fingerprint.ts'
import { registerSafeTools, type ReloadResult } from './inspect.ts'
import { watchFile, type WatchHandle } from './watch.ts'

export { Config }
export type { PluginConfig }

/** Cordis plugin metadata. */
export const name = 'secret-guard'

/** Services required by this plugin. */
export const inject = ['tools']

const iso = (): string => new Date().toISOString()

/**
 * Mount the plugin. Registrations are context-scoped effects and are also
 * explicitly disposed by the returned cleanup (belt and suspenders for HMR).
 */
export function apply(ctx: Context, config: PluginConfig): () => void {
  const resolved = resolveConfig(config ?? {})
  const logger = ctx.logger('secret-guard')
  const journal = new Journal(resolved.audit.dir, {
    ...resolved.audit,
    onError: error => logger.warn(`journal write failed: ${error.message}`),
  })

  // The policy engine is swapped wholesale on hot reload; everything else
  // reaches it through this holder.
  const policy: { engine: PolicyEngine } = {
    engine: new PolicyEngine(resolved.allow, resolved.rules, defaultRules()),
  }

  let fingerprinter: Fingerprinter | null = null
  const getFingerprinter = (): Fingerprinter => (fingerprinter ??= Fingerprinter.create(resolved.sealKey))

  const reloadRules = (): ReloadResult => {
    const source = resolved.rulesFile
    if (source === '') {
      return { ok: false, source: '', rules: 0, allow: 0, message: 'no rulesFile configured' }
    }
    let parsed: unknown
    try {
      parsed = JSON.parse(readFileSync(source, 'utf8')) as unknown
    } catch (error) {
      const err = error as NodeJS.ErrnoException
      if (err.code === 'ENOENT') {
        journal.write({ ts: iso(), kind: 'reload', message: `rules file absent: ${source}` })
        return { ok: false, source, rules: 0, allow: 0, message: `rules file does not exist: ${source}` }
      }
      const message = `cannot parse ${source}: ${error instanceof Error ? error.message : String(error)}`
      journal.write({ ts: iso(), kind: 'error', message })
      logger.error(message)
      return { ok: false, source, rules: 0, allow: 0, message }
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      const message = 'rules file rejected: root must be a JSON object { rules?, allow? }'
      journal.write({ ts: iso(), kind: 'error', message })
      logger.error(`${message} (${source})`)
      return { ok: false, source, rules: 0, allow: 0, message }
    }
    const obj = parsed as Record<string, unknown>
    try {
      const rules = compileRules(obj.rules)
      const allow = compileAllowList(obj.allow)
      policy.engine = new PolicyEngine(allow, rules, defaultRules())
      journal.write({ ts: iso(), kind: 'reload', rules: rules.length, allow: allow.length, message: source })
      logger.info(`rules reloaded from ${source}: ${rules.length} rule(s), ${allow.length} allow entry(ies)`)
      return { ok: true, source, rules: rules.length, allow: allow.length }
    } catch (error) {
      const message = `rules file rejected: ${error instanceof Error ? error.message : String(error)}`
      journal.write({ ts: iso(), kind: 'error', message })
      logger.error(message)
      return { ok: false, source, rules: 0, allow: 0, message }
    }
  }

  journal.write({
    ts: iso(),
    kind: 'init',
    message: `secret-guard started: ${resolved.rules.length} custom rule(s), ${resolved.allow.length} allow entry(ies)`,
  })

  // Load the external rules file once at startup; a missing or invalid file is
  // journaled and the configured rules stay in effect (same semantics as hot
  // reload failures).
  if (resolved.rulesFile !== '') reloadRules()

  const disposers: (() => void)[] = [
    // `prepend` makes the gate the outermost pre-execute listener: its deny
    // short-circuits before any other policy runs.
    ctx.on('tools/pre-execute', createGateHandler({
      getEngine: () => policy.engine,
      journal,
      config: resolved,
    }), { prepend: true }),
    // `prepend` makes the scrubber the outermost post-execute listener, so the
    // masked content is the final decision — later listeners cannot overwrite it.
    ctx.on('tools/post-execute', createScrubHandler({ journal, config: resolved }), { prepend: true }),
    registerSafeTools(ctx, {
      config: resolved,
      getEngine: () => policy.engine,
      getFingerprinter,
      reloadRules,
    }),
  ]

  let watchHandle: WatchHandle | undefined
  if (resolved.watchRules && resolved.rulesFile !== '') {
    watchHandle = watchFile(resolved.rulesFile, () => {
      reloadRules()
    }, 300)
  }

  // Cordis lifecycles guarantee one apply per context (HMR unmounts before
  // remount), so no duplicate-apply guard is needed here.
  return () => {
    watchHandle?.close()
    for (const dispose of disposers) {
      try {
        dispose()
      } catch {
        // best-effort teardown
      }
    }
  }
}
