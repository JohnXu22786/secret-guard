/**
 * Hot-reload watcher for the external rules file.
 *
 * Implementation note: this deliberately polls the file's mtime/size instead
 * of using `fs.watch`. On Windows, deleting a directory that `fs.watch` is
 * watching leaks the loop's exit eligibility (a known platform quirk), and the
 * rules file is routinely replaced by editors and `sg_reload` in ways that
 * make per-file watchers fragile. Polling is uniform across platforms,
 * deterministic, and cheap: one stat call every `pollMs` milliseconds.
 * The interval is unref'd, so it can never keep the harness process alive.
 */

import { statSync } from 'node:fs'

export interface WatchHandle {
  close(): void
}

export function watchFile(
  file: string,
  onChange: () => void | Promise<void>,
  debounceMs = 200,
  pollMs = 400,
): WatchHandle {
  let closed = false
  let debounce: NodeJS.Timeout | undefined

  const snapshot = (): string => {
    try {
      const stat = statSync(file)
      return `${stat.mtimeMs}:${stat.size}`
    } catch {
      return ''
    }
  }

  let last = snapshot()
  const timer = setInterval(() => {
    const now = snapshot()
    if (now === last) return
    last = now
    if (closed) return
    clearTimeout(debounce)
    debounce = setTimeout(() => {
      void Promise.resolve(onChange()).catch(() => {
        // The caller owns error reporting (journal); never rethrow.
      })
    }, debounceMs)
    debounce.unref?.()
  }, pollMs)
  timer.unref()

  return {
    close(): void {
      closed = true
      clearTimeout(debounce)
      clearInterval(timer)
    },
  }
}
