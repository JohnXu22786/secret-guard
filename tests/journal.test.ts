import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, readFileSync, readdirSync, existsSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Journal } from '../src/journal.ts'

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), 'sg-journal-'))
}

test('Journal: appends JSONL entries with all fields', () => {
  const dir = tempDir()
  try {
    const j = new Journal(join(dir, 'logs'), { enabled: true, maxBytes: 10_000_000, keep: 3 })
    j.write({ ts: '2026-01-01T00:00:00.000Z', kind: 'block', tool: 'read', path: '.env', rule: 'env-file', effect: 'block' })
    j.write({ ts: '2026-01-01T00:00:01.000Z', kind: 'mask', tool: 'grep', masked: { jwt: 1 } })
    const lines = readFileSync(join(dir, 'logs', 'events.jsonl'), 'utf8').trim().split('\n')
    assert.equal(lines.length, 2)
    const first = JSON.parse(lines[0]!) as Record<string, unknown>
    assert.equal(first.kind, 'block')
    assert.equal(first.rule, 'env-file')
    assert.equal(first.tool, 'read')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Journal: rotates files past maxBytes and honors keep', () => {
  const dir = tempDir()
  try {
    const logDir = join(dir, 'logs')
    const j = new Journal(logDir, { enabled: true, maxBytes: 120, keep: 2 })
    for (let i = 0; i < 6; i++) {
      j.write({ ts: `2026-01-01T00:00:0${i}.000Z`, kind: 'block', path: `.env-${i}` })
    }
    const files = readdirSync(logDir).sort()
    assert.ok(files.includes('events.jsonl'))
    assert.ok(files.length > 1, 'rotation must have happened')
    assert.ok(files.length <= 3, `keep must cap files: ${files.join(',')}`)
    // every file is valid JSONL
    for (const f of files) {
      for (const line of readFileSync(join(logDir, f), 'utf8').trim().split('\n')) {
        assert.ok(JSON.parse(line).ts, `invalid line in ${f}`)
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Journal: disabled journal writes nothing', () => {
  const dir = tempDir()
  try {
    const j = new Journal(join(dir, 'logs'), { enabled: false, maxBytes: 1000, keep: 2 })
    j.write({ ts: 'x', kind: 'block', path: '.env' })
    assert.ok(!existsSync(join(dir, 'logs')))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Journal: readAll returns parsed entries in order', () => {
  const dir = tempDir()
  try {
    const j = new Journal(join(dir, 'logs'), { enabled: true, maxBytes: 10_000_000, keep: 3 })
    j.write({ ts: 'a', kind: 'init', message: 'started' })
    j.write({ ts: 'b', kind: 'reload', rules: 3, allow: 1 })
    const entries = j.readAll()
    assert.equal(entries.length, 2)
    assert.equal(entries[0]!.kind, 'init')
    assert.equal(entries[1]!.kind, 'reload')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Journal: single-line entries never break JSONL even with odd content', () => {
  const dir = tempDir()
  try {
    const j = new Journal(join(dir, 'logs'), { enabled: true, maxBytes: 10_000_000, keep: 3 })
    j.write({ ts: 'x', kind: 'block', path: 'a\nb"c\\d', message: 'quote " backslash \\ newline \n' })
    const lines = readFileSync(join(dir, 'logs', 'events.jsonl'), 'utf8').trim().split('\n')
    assert.equal(lines.length, 1)
    const parsed = JSON.parse(lines[0]!)
    assert.equal(parsed.path, 'a\nb"c\\d')
    assert.equal(parsed.message, 'quote " backslash \\ newline \n')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Journal: readAll skips damaged lines instead of losing the whole journal', () => {
  const dir = tempDir()
  try {
    const j = new Journal(join(dir, 'logs'), { enabled: true, maxBytes: 10_000_000, keep: 3 })
    j.write({ ts: 'first', kind: 'init', message: 'started' })
    const file = join(dir, 'logs', 'events.jsonl')
    writeFileSync(file, readFileSync(file, 'utf8') + '{ torn line mid-write\n')
    j.write({ ts: 'last', kind: 'reload', rules: 1, allow: 0 })
    const entries = j.readAll()
    assert.equal(entries.length, 2, 'valid entries must survive a damaged line')
    assert.equal(entries[0]!.kind, 'init')
    assert.equal(entries[1]!.kind, 'reload')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
