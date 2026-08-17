/**
 * Append-only JSONL audit journal with size-based rotation. Entries carry
 * metadata only (tool names, paths, rule ids, shape counts) — by construction
 * the journal never receives raw secret values; callers are responsible for
 * honoring that contract.
 */

import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
} from 'node:fs'
import { join } from 'node:path'

export type JournalKind = 'init' | 'block' | 'mask' | 'reload' | 'error'

export interface JournalEntry {
  ts: string
  kind: JournalKind
  tool?: string
  path?: string
  rule?: string
  effect?: string
  masked?: Record<string, number>
  rules?: number
  allow?: number
  message?: string
}

export interface JournalOptions {
  enabled?: boolean
  maxBytes?: number
  keep?: number
  /** Called when a journal write fails; the write itself never throws. */
  onError?: (error: Error) => void
}

export class Journal {
  private readonly file: string
  private readonly dir: string
  private readonly opts: JournalOptions

  // NOTE: keep this constructor free of TypeScript parameter properties —
  // dsh loads plugin source with Node's strip-only TS support, which rejects
  // them. Same constraint applies to every other class in this package.
  constructor(dir: string, opts: JournalOptions = {}) {
    this.dir = dir
    this.opts = opts
    this.file = join(dir, 'events.jsonl')
  }

  write(entry: JournalEntry): void {
    if (this.opts.enabled === false) return
    const line = `${JSON.stringify(entry)}\n`
    try {
      mkdirSync(this.dir, { recursive: true })
      if (this.size() + line.length > (this.opts.maxBytes ?? 0)) this.rotate()
      appendFileSync(this.file, line, 'utf8')
    } catch (error) {
      // The journal must never take the tool pipeline down.
      this.opts.onError?.(error instanceof Error ? error : new Error(String(error)))
    }
  }

  /**
   * Parse the current journal file, best-effort. A single damaged line (e.g.
   * a torn write during rotation) must not hide the rest of the journal —
   * unparseable lines are skipped, and the surviving entries are returned.
   */
  readAll(): JournalEntry[] {
    try {
      if (!existsSync(this.file)) return []
      const entries: JournalEntry[] = []
      for (const line of readFileSync(this.file, 'utf8').split('\n')) {
        const trimmed = line.trim()
        if (trimmed === '') continue
        try {
          entries.push(JSON.parse(trimmed) as JournalEntry)
        } catch {
          // skip the damaged line, keep the rest
        }
      }
      return entries
    } catch {
      return []
    }
  }

  private size(): number {
    try {
      return statSync(this.file).size
    } catch {
      return 0
    }
  }

  private rotate(): void {
    const keep = this.opts.keep ?? 5
    for (let i = keep; i >= 1; i--) {
      const stale = join(this.dir, `events.${i}.jsonl`)
      if (existsSync(stale)) rmSync(stale, { force: true })
      const prev = join(this.dir, i === 1 ? 'events.jsonl' : `events.${i - 1}.jsonl`)
      if (existsSync(prev)) renameSync(prev, join(this.dir, `events.${i}.jsonl`))
    }
  }
}
