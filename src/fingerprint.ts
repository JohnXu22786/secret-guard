/**
 * Deterministic, value-free fingerprinting of dotenv values using an HMAC-SHA256
 * "seal key". The same value always yields the same short fingerprint, but the
 * fingerprint cannot be dictionary-reversed without the key, and the key never
 * leaves the host. The seal key comes from an environment variable when set,
 * otherwise from a local file that is created automatically (0644-independent:
 * created 0600 where the platform supports it).
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

export interface SealKeyOptions {
  env: string
  path: string
}

export class Fingerprinter {
  private readonly key: Buffer

  // NOTE: no TypeScript parameter properties here — dsh loads plugin source
  // with Node's strip-only TS support, which rejects them.
  private constructor(key: Buffer) {
    this.key = key
  }

  static create(opts: SealKeyOptions): Fingerprinter {
    const fromEnv = process.env[opts.env]
    if (fromEnv !== undefined && fromEnv !== '') return new Fingerprinter(normalizeKey(fromEnv))
    let key: Buffer
    try {
      if (existsSync(opts.path)) {
        key = normalizeKey(readFileSync(opts.path, 'utf8'))
      } else {
        key = randomBytes(32)
        mkdirSync(dirname(opts.path), { recursive: true })
        writeFileSync(opts.path, `${key.toString('hex')}\n`, { mode: 0o600 })
        try {
          chmodSync(opts.path, 0o600)
        } catch {
          // Windows: the mode flag above is the best we can do.
        }
      }
    } catch (error) {
      throw new Error(
        `secret-guard: cannot initialize seal key at '${opts.path}': ${error instanceof Error ? error.message : String(error)}`,
      )
    }
    return new Fingerprinter(key)
  }

  private digest(value: string): Buffer {
    return createHmac('sha256', this.key).update(value, 'utf8').digest()
  }

  /** First 16 hex chars of the value's HMAC digest — stable, not reversible. */
  fingerprint(value: string): string {
    return this.digest(value).toString('hex').slice(0, 16)
  }

  /** Constant-time comparison of two values via their digests (never values). */
  equals(stored: string, candidate: string): boolean {
    return timingSafeEqual(this.digest(stored), this.digest(candidate))
  }
}

function normalizeKey(raw: string): Buffer {
  const trimmed = raw.trim()
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return Buffer.from(trimmed, 'hex')
  if (trimmed.length >= 8) return Buffer.from(trimmed, 'utf8')
  throw new Error('seal key must be a 64-character hex string or at least 8 characters of text')
}
