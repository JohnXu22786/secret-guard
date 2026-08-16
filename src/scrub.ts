/**
 * Defense-in-depth content scrubber. Even if a tool that was not gated (or a
 * path that slipped past the rules) surfaces secret-shaped text in its result,
 * this listener masks the values before the content reaches the model.
 *
 * Masking is deliberately context-aware to avoid noise: bare long base64 or
 * hex strings (git hashes, uuids) are NOT masked; only high-confidence shapes
 * (private key blocks, JWTs, bearer tokens, known key prefixes, URLs with
 * embedded credentials, and `key=value` assignments whose value is not a
 * placeholder) are redacted.
 */

import type { ContentBlock } from '@deepseek-ai/dsh-llm'
import type { PostToolDecision, ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import type { Journal } from './journal.ts'
import type { ResolvedConfig } from './config.ts'

export interface ScrubStats {
  count: number
  kinds: Record<string, number>
}

/** Values that look like documentation placeholders are left alone. */
const PLACEHOLDER = /^(?:<|>|\*+|x{4,}|\.{3,}|your[-_ ]|change[-_ ]?me|example|placeholder|redacted)/i

interface Pattern {
  kind: string
  re: RegExp
}

const PATTERNS: Pattern[] = [
  {
    kind: 'private-key',
    re: /-----BEGIN (?:[A-Z0-9 ]*?)PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]*?)PRIVATE KEY-----/g,
  },
  // Truncated blocks (e.g. a clipped tool result): BEGIN line plus a long
  // base64 body, no END required. Overlaps with the full-block pattern;
  // first-match-wins keeps the longer edit.
  {
    kind: 'private-key',
    re: /-----BEGIN (?:[A-Z0-9 ]*?)PRIVATE KEY-----[ \t]*\r?\n[A-Za-z0-9+/=\r\n]{40,}/g,
  },
  { kind: 'jwt', re: /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}/g },
  { kind: 'bearer', re: /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/g },
  {
    kind: 'wellknown',
    // The lookbehind excludes `-`/`_`/alnum before the key, so `risk-sk-…`
    // stays untouched while a bare `sk-…` still masks.
    re: /(?<![A-Za-z0-9_-])(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})/g,
  },
  {
    kind: 'connstr',
    re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s'"`/@]*:[^\s'"`@]{1,128}@[^\s'"`]+/gi,
  },
  {
    kind: 'assignment',
    // Quoted values (the usual dotenv form) mask whole; bare values allow
    // common password punctuation. Value lands in capture group 2, 3 or 4.
    re: /(?:^|[^A-Za-z0-9])(password|passwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?key)\s*[=:]\s*(?:"([^"\n]{12,})"|'([^'\n]{12,})'|([A-Za-z0-9._~+/=!@#$%^&*()-]{12,}))/gi,
  },
]

interface Edit {
  from: number
  to: number
  text: string
  kind: string
}

export function scrubText(text: string): { text: string; stats: ScrubStats } | null {
  const edits: Edit[] = []
  for (const { kind, re } of PATTERNS) {
    re.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = re.exec(text)) !== null) {
      const full = m[0]
      if (kind === 'assignment') {
        const quoted = m[2] !== undefined || m[3] !== undefined
        const value = m[2] ?? m[3] ?? m[4]
        if (value === undefined || PLACEHOLDER.test(value)) continue
        // Mask from the value's first character to the match end; for quoted
        // values that span includes the closing quote (harmless).
        const tail = quoted ? 1 : 0
        edits.push({
          from: m.index + full.length - value.length - tail,
          to: m.index + full.length,
          text: `[redacted:${kind}:${value.length}]`,
          kind,
        })
      } else {
        edits.push({ from: m.index, to: m.index + full.length, text: `[redacted:${kind}:${full.length}]`, kind })
      }
      if (re.lastIndex === m.index) re.lastIndex++ // defensive: never loop on zero-width
    }
  }
  if (edits.length === 0) return null

  // Non-overlapping first-match-wins application.
  edits.sort((a, b) => a.from - b.from || b.to - a.to)
  const accepted: Edit[] = []
  let lastTo = -1
  for (const edit of edits) {
    if (edit.from < lastTo) continue
    accepted.push(edit)
    lastTo = edit.to
  }
  const kinds: Record<string, number> = {}
  for (const edit of accepted) kinds[edit.kind] = (kinds[edit.kind] ?? 0) + 1
  let out = ''
  let pos = 0
  for (const edit of accepted) {
    out += text.slice(pos, edit.from) + edit.text
    pos = edit.to
  }
  out += text.slice(pos)
  return { text: out, stats: { count: accepted.length, kinds } }
}

export function scrubBlocks(
  blocks: readonly ContentBlock[],
): { blocks: ContentBlock[]; stats: ScrubStats } | null {
  const out: ContentBlock[] = []
  let count = 0
  const kinds: Record<string, number> = {}
  for (const block of blocks) {
    if (block.type !== 'text') {
      out.push(block)
      continue
    }
    const scrubbed = scrubText(block.text)
    if (!scrubbed) {
      out.push(block)
      continue
    }
    count += scrubbed.stats.count
    for (const [kind, n] of Object.entries(scrubbed.stats.kinds)) {
      kinds[kind] = (kinds[kind] ?? 0) + n
    }
    out.push({ type: 'text', text: scrubbed.text })
  }
  if (count === 0) return null
  const detail = Object.entries(kinds).map(([kind, n]) => `${kind} x${n}`).join(', ')
  out.push({
    type: 'text',
    text: `\n[secret-guard: redacted ${count} secret-shaped value(s) from this tool result (${detail})]`,
  })
  return { blocks: out, stats: { count, kinds } }
}

export type PostExecuteHandler = (
  exec: ToolExecution,
  result: ToolExecutionResult,
  next: () => Promise<PostToolDecision>,
) => Promise<PostToolDecision>

/** `tools/post-execute` listener: mask accepted content, journal the event. */
export function createScrubHandler(deps: { journal: Journal; config: ResolvedConfig }): PostExecuteHandler {
  return async (exec, result, next) => {
    const downstream = await next()
    if (!deps.config.maskResults) return downstream
    if (downstream.kind !== 'accept') return downstream
    // A downstream `value` replacement has no maskable text of its own (the
    // registry re-renders it through the tool's own render); pass it through.
    if (Object.hasOwn(downstream, 'value')) return downstream
    // The default accept decision carries no content; mask the result's own
    // content, or an earlier listener's replacement when one was supplied.
    // Note: registry-owned `error.message`/`error.info` fields are not
    // rewritten here — the model-facing text (content blocks) is what gets
    // masked, which is the leak surface this listener defends.
    const content = downstream.content ?? result.content
    if (content === undefined) return downstream
    const scrubbed = scrubBlocks(content)
    if (!scrubbed) return downstream
    deps.journal.write({
      ts: new Date().toISOString(),
      kind: 'mask',
      tool: exec.name,
      masked: scrubbed.stats.kinds,
    })
    return {
      kind: 'accept',
      content: scrubbed.blocks,
      additionalContexts: downstream.additionalContexts,
    }
  }
}
