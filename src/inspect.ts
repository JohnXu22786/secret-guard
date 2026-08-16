/**
 * Safe inspection surface: dotenv parsing, value-shape classification, and the
 * `sg_*` tool family. These tools deliberately read sensitive files that the
 * gate blocks — that is their purpose — but they never return raw values:
 * they return key names, line numbers, booleans, shape labels, lengths, and
 * HMAC fingerprints only.
 */

import { readFileSync } from 'node:fs'
import { isAbsolute, join } from 'node:path'
import { Worker } from 'node:worker_threads'
import { defineTool, type ToolDefinition } from '@deepseek-ai/dsh-tools'
import type { PolicyEngine } from './policy.ts'
import type { Fingerprinter } from './fingerprint.ts'
import type { ResolvedConfig } from './config.ts'

export interface DotenvEntry {
  name: string
  value: string
  line: number
}

/**
 * Minimal dotenv parser: blank lines and `#` comments skipped, optional
 * `export` prefix, single/double-quoted values (double quotes honor the common
 * `\n` `\r` `\t` `\"` `\\` escapes), inline comments only after unquoted
 * values. Multi-line quoted values are not supported.
 */
export function parseDotenv(text: string): DotenvEntry[] {
  const entries: DotenvEntry[] = []
  const lines = text.split(/\r?\n/)
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim()
    if (line === '' || line.startsWith('#')) continue
    const eq = line.indexOf('=')
    if (eq < 0) continue
    let name = line.slice(0, eq).trim()
    if (name.startsWith('export ')) name = name.slice('export '.length).trim()
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) continue
    const raw = line.slice(eq + 1).trim()
    let value: string
    if (raw.length >= 2 && raw.startsWith('"') && raw.endsWith('"')) {
      value = raw
        .slice(1, -1)
        .replace(/\\n/g, '\n')
        .replace(/\\r/g, '\r')
        .replace(/\\t/g, '\t')
        .replace(/\\"/g, '"')
        .replace(/\\\\/g, '\\')
    } else if (raw.length >= 2 && raw.startsWith("'") && raw.endsWith("'")) {
      value = raw.slice(1, -1)
    } else {
      value = raw.replace(/\s*#.*$/, '')
    }
    entries.push({ name, value, line: i + 1 })
  }
  return entries
}

export type ValueShape = 'empty' | 'bool' | 'numeric' | 'jwt' | 'url' | 'hex' | 'base64' | 'opaque'

/** Shape classification only — never reveals the value itself. */
export function classifyShape(value: string): ValueShape {
  if (value === '') return 'empty'
  if (/^(true|false)$/i.test(value)) return 'bool'
  if (/^-?\d+(\.\d+)?$/.test(value)) return 'numeric'
  if (/^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}$/.test(value)) return 'jwt'
  if (/^[a-z][a-z0-9+.-]*:\/\/\S+$/i.test(value)) return 'url'
  if (/^[0-9a-fA-F]{16,}$/.test(value)) return 'hex'
  if (/^[A-Za-z0-9+/]{16,}={0,2}$/.test(value)) return 'base64'
  return 'opaque'
}

export function readDotenvFile(path: string): DotenvEntry[] {
  let text: string
  try {
    text = readFileSync(path, 'utf8')
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    throw new Error(`cannot read '${path}': ${reason}`)
  }
  return parseDotenv(text)
}

export interface ReloadResult {
  ok: boolean
  source: string
  rules: number
  allow: number
  message?: string
}

export interface InspectDeps {
  config: ResolvedConfig
  getEngine: () => PolicyEngine
  getFingerprinter: () => Fingerprinter
  reloadRules: () => ReloadResult
}

/** Resolve a tool-supplied file argument against the harness working dir. */
export function resolveFileArg(file: string | undefined, cwd: string): string {
  const target = file ?? '.env'
  return isAbsolute(target) ? target : join(cwd, target)
}

/** Last entry wins for duplicate keys (dotenv semantics). */
export function findEntry(entries: DotenvEntry[], key: string): DotenvEntry | undefined {
  for (let i = entries.length - 1; i >= 0; i--) {
    if (entries[i]!.name === key) return entries[i]
  }
  return undefined
}

const REGEX_PATTERN_MAX = 512

/**
 * Test a caller-supplied regular expression against a value OUTSIDE the main
 * thread. A hostile or pathological pattern (nested quantifiers like
 * `(a+)+$`) can otherwise freeze the harness's event loop for unbounded time
 * — synchronous RegExp execution cannot be aborted. The worker is terminated
 * on timeout, so a bad pattern can only cost one worker spawn.
 */
function testRegexInWorker(pattern: string, value: string, timeoutMs = 1000): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(
      `const { parentPort, workerData } = require('node:worker_threads');
       try {
         const result = new RegExp(workerData.pattern).test(workerData.value);
         parentPort.postMessage({ ok: true, result });
       } catch (error) {
         parentPort.postMessage({ ok: false, error: String(error && error.message ? error.message : error) });
       }`,
      { eval: true, workerData: { pattern, value } },
    )
    const timer = setTimeout(() => {
      void worker.terminate()
      reject(new Error('pattern evaluation timed out (possibly a pathological regular expression)'))
    }, timeoutMs)
    worker.once('message', message => {
      clearTimeout(timer)
      if (message.ok) resolve(message.result)
      else reject(new Error(message.error))
    })
    worker.once('error', error => {
      clearTimeout(timer)
      reject(error)
    })
    worker.once('exit', code => {
      clearTimeout(timer)
      if (code !== 0) reject(new Error(`pattern worker exited with code ${code}`))
    })
  })
}

export function registerSafeTools(
  ctx: { tools: { register(definition: ToolDefinition): () => void } },
  deps: InspectDeps,
): () => void {
  const disposers: (() => void)[] = []

  const add = (definition: ToolDefinition): void => {
    disposers.push(ctx.tools.register(definition))
  }

  add(defineTool({
    name: 'sg_keys',
    description:
      'List the keys defined in a dotenv file (default .env). Returns names, line numbers, whether each value is set, and its shape label. NEVER returns values. Use when a read of an env file was blocked.',
    parameters: {
      file: { type: 'string', description: 'Dotenv file path (default: .env relative to the harness cwd)' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          file: { type: 'string', required: true },
          keys: {
            type: 'array',
            required: true,
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                name: { type: 'string', required: true },
                line: { type: 'integer', required: true },
                hasValue: { type: 'boolean', required: true },
                shape: { type: 'string', required: true },
              },
            },
          },
        },
      },
      render: (args, value) => {
        const lines = value.keys.map(k => `${k.name.padEnd(24)} line ${k.line}\t${k.hasValue ? 'set (' + k.shape + ')' : 'empty'}`)
        return [{ type: 'text', text: `file: ${value.file}\n${value.keys.length} key(s):\n${lines.join('\n')}` }]
      },
    },
    execute: async (args) => {
      const file = resolveFileArg(args.file, deps.config.cwd)
      const entries = readDotenvFile(file)
      return {
        file,
        keys: entries.map(e => ({
          name: e.name,
          line: e.line,
          hasValue: e.value !== '',
          shape: classifyShape(e.value),
        })),
      }
    },
  }))

  add(defineTool({
    name: 'sg_scan',
    description:
      'Classify the value shapes of every key (or one key) in a dotenv file: empty, bool, numeric, jwt, url, hex, base64, opaque. Reports shape and length only, NEVER values.',
    parameters: {
      file: { type: 'string', description: 'Dotenv file path (default: .env)' },
      key: { type: 'string', description: 'Optional key to scan; omitting scans all keys' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          file: { type: 'string', required: true },
          results: {
            type: 'array',
            required: true,
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                name: { type: 'string', required: true },
                shape: { type: 'string', required: true },
                length: { type: 'integer', required: true },
              },
            },
          },
        },
      },
      render: (args, value) => {
        const rows = value.results.map(r => `${r.name.padEnd(24)} ${r.shape.padEnd(8)} len ${r.length}`)
        return [{ type: 'text', text: `file: ${value.file}\n${rows.join('\n')}` }]
      },
    },
    execute: async (args) => {
      const file = resolveFileArg(args.file, deps.config.cwd)
      const entries = readDotenvFile(file)
      const selected = args.key === undefined ? entries : [findEntryOrThrow(entries, args.key)]
      return {
        file,
        results: selected.map(e => ({ name: e.name, shape: classifyShape(e.value), length: e.value.length })),
      }
    },
  }))

  add(defineTool({
    name: 'sg_fingerprint',
    description:
      'Return the HMAC-SHA256 fingerprint (first 16 hex chars) of one key\'s value in a dotenv file. Deterministic per seal key, reversible only with the key. NEVER returns the value.',
    parameters: {
      file: { type: 'string', description: 'Dotenv file path (default: .env)' },
      key: { type: 'string', required: true, description: 'Key whose value is fingerprinted' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          file: { type: 'string', required: true },
          key: { type: 'string', required: true },
          fingerprint: { type: 'string', required: true },
        },
      },
      render: (args, value) => [{
        type: 'text',
        text: `fingerprint(${value.key}) = ${value.fingerprint}\n(file: ${value.file}; HMAC-SHA256, deterministic per seal key)`,
      }],
    },
    execute: async (args) => {
      const file = resolveFileArg(args.file, deps.config.cwd)
      const entry = findEntryOrThrow(readDotenvFile(file), args.key)
      return { file, key: args.key, fingerprint: deps.getFingerprinter().fingerprint(entry.value) }
    },
  }))

  add(defineTool({
    name: 'sg_probe',
    description:
      'Ask a boolean question about one key\'s value in a dotenv file: is-set, is-empty, starts-with, ends-with, contains, matches (regular expression), equals (constant-time, no value exchange). Returns a boolean only — NEVER the value.',
    parameters: {
      file: { type: 'string', description: 'Dotenv file path (default: .env)' },
      key: { type: 'string', required: true, description: 'Key to probe' },
      op: {
        type: 'string',
        required: true,
        enum: ['is-set', 'is-empty', 'starts-with', 'ends-with', 'contains', 'matches', 'equals'],
        description: 'The boolean question to answer',
      },
      value: { type: 'string', description: 'Candidate value for starts-with / ends-with / contains / equals' },
      pattern: { type: 'string', description: 'Regular expression for matches' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          file: { type: 'string', required: true },
          key: { type: 'string', required: true },
          op: { type: 'string', required: true },
          result: { type: 'boolean', required: true },
        },
      },
      render: (args, value) => [{ type: 'text', text: `probe(${value.key}, ${value.op}) = ${value.result}` }],
    },
    execute: async (args) => {
      const file = resolveFileArg(args.file, deps.config.cwd)
      const entries = readDotenvFile(file)
      const entry = findEntry(entries, args.key)
      if (args.op === 'is-set') return { file, key: args.key, op: args.op, result: entry !== undefined }
      if (args.op === 'is-empty') {
        return { file, key: args.key, op: args.op, result: entry === undefined || entry.value === '' }
      }
      if (entry === undefined) throw new Error(`key '${args.key}' not found in '${file}'`)
      let result: boolean
      switch (args.op) {
        case 'starts-with':
        case 'ends-with':
        case 'contains':
        case 'equals': {
          if (args.value === undefined) throw new Error(`sg_probe op '${args.op}' requires a value argument`)
          if (args.op === 'equals') {
            result = deps.getFingerprinter().equals(entry.value, args.value)
          } else if (args.op === 'starts-with') {
            result = entry.value.startsWith(args.value)
          } else if (args.op === 'ends-with') {
            result = entry.value.endsWith(args.value)
          } else {
            result = entry.value.includes(args.value)
          }
          break
        }
        case 'matches': {
          if (args.pattern === undefined) throw new Error("sg_probe op 'matches' requires a pattern argument")
          if (args.pattern.length > REGEX_PATTERN_MAX) {
            throw new Error(`pattern too long (max ${REGEX_PATTERN_MAX} characters)`)
          }
          result = await testRegexInWorker(args.pattern, entry.value)
          break
        }
        default:
          throw new Error(`unknown probe op '${args.op}'`)
      }
      return { file, key: args.key, op: args.op, result }
    },
  }))

  add(defineTool({
    name: 'sg_status',
    description:
      'Report the active policy: gated tools, mask/audit settings, rule counts, and — when a `check` path is given — the classification of that path (effect and matching rule). No file contents are read.',
    parameters: {
      check: { type: 'string', description: 'Optional path to classify against the current rules' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          ruleCount: { type: 'integer', required: true },
          allowCount: { type: 'integer', required: true },
          gateTools: { type: 'array', required: true, items: { type: 'string' } },
          maskResults: { type: 'boolean', required: true },
          guardSearchPatterns: { type: 'boolean', required: true },
          audit: {
            type: 'object',
            required: true,
            additionalProperties: false,
            properties: {
              enabled: { type: 'boolean', required: true },
              dir: { type: 'string', required: true },
            },
          },
          rulesFile: { type: 'string', required: true },
          check: {
            required: true,
            oneOf: [
              {
                type: 'object',
                additionalProperties: false,
                properties: {
                  path: { type: 'string', required: true },
                  effect: { type: 'string', required: true },
                  rule: {
                    required: true,
                    oneOf: [{ type: 'string' }, { type: 'null' }],
                  },
                },
              },
              { type: 'null' },
            ],
          },
        },
      },
      render: (args, value) => {
        const lines = [
          `secret-guard policy`,
          `- gated tools: ${value.gateTools.join(', ')}`,
          `- custom rules: ${value.ruleCount}  allow entries: ${value.allowCount}`,
          `- result masking: ${value.maskResults ? 'on' : 'off'}   search keyword guard: ${value.guardSearchPatterns ? 'on' : 'off'}`,
          `- audit journal: ${value.audit.enabled ? value.audit.dir : 'disabled'}`,
          `- rules file: ${value.rulesFile === '' ? 'none (config only)' : value.rulesFile}`,
        ]
        if (value.check !== null) {
          lines.push(`- check '${value.check.path}' -> ${value.check.effect}${value.check.rule !== null ? ` (rule '${value.check.rule}')` : ''}`)
        }
        return [{ type: 'text', text: lines.join('\n') }]
      },
    },
    execute: async (args) => {
      const engine = deps.getEngine()
      const listed = engine.list()
      let check: { path: string; effect: string; rule: string | null } | null = null
      if (args.check !== undefined) {
        const c = engine.classify(args.check)
        check = { path: args.check, effect: c.effect, rule: c.rule?.id ?? null }
      }
      return {
        ruleCount: listed.filter(l => l.source === 'custom').length,
        allowCount: listed.filter(l => l.source === 'allow').length,
        gateTools: deps.config.gateTools,
        maskResults: deps.config.maskResults,
        guardSearchPatterns: deps.config.guardSearchPatterns,
        audit: { enabled: deps.config.audit.enabled, dir: deps.config.audit.dir },
        rulesFile: deps.config.rulesFile,
        check,
      }
    },
  }))

  add(defineTool({
    name: 'sg_reload',
    description:
      'Re-read the external rules file (config `rulesFile`) and swap the active policy immediately. Returns the reload outcome. Use when rules changed on disk and auto-watch is disabled or missed the change.',
    parameters: {},
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          ok: { type: 'boolean', required: true },
          source: { type: 'string', required: true },
          rules: { type: 'integer', required: true },
          allow: { type: 'integer', required: true },
          message: {
            required: true,
            oneOf: [{ type: 'string' }, { type: 'null' }],
          },
        },
      },
      render: (args, value) => {
        const headline = value.ok ? 'rules reloaded' : 'rules reload failed'
        const detail = value.ok
          ? `${value.rules} rule(s), ${value.allow} allow entry(ies) from ${value.source}`
          : (value.message ?? 'unknown error')
        return [{ type: 'text', text: `${headline}: ${detail}` }]
      },
    },
    execute: async () => {
      const r = deps.reloadRules()
      return { ok: r.ok, source: r.source, rules: r.rules, allow: r.allow, message: r.message ?? null }
    },
  }))

  return () => {
    for (const dispose of disposers) {
      try {
        dispose()
      } catch {
        // best-effort teardown
      }
    }
  }
}

function findEntryOrThrow(entries: DotenvEntry[], key: string): DotenvEntry {
  const entry = findEntry(entries, key)
  if (entry === undefined) throw new Error(`key '${key}' not found in file`)
  return entry
}
