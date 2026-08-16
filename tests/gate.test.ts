import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { ToolExecution, PreToolDecision } from '@deepseek-ai/dsh-tools'
import { createGateHandler, extractGatedPath } from '../src/gate.ts'
import { defaultRules, PolicyEngine } from '../src/policy.ts'
import { Journal } from '../src/journal.ts'
import { resolveConfig } from '../src/config.ts'

function makeContext(overrides: Record<string, unknown> = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'sg-gate-'))
  const config = resolveConfig({ audit: { dir: join(dir, 'logs') }, ...overrides })
  const engine = new PolicyEngine(config.allow, config.rules, defaultRules())
  const journal = new Journal(config.audit.dir, config.audit)
  return {
    dir,
    config,
    getEngine: () => engine,
    journal,
  }
}

function exec(name: string, args: unknown): ToolExecution {
  return {
    name,
    arguments: args,
    callId: `test-${name}` as never,
    signal: new AbortController().signal,
    agent: undefined,
    rootCallId: undefined as never,
    token: Symbol() as never,
  } as unknown as ToolExecution
}

async function run(gate: ReturnType<typeof createGateHandler>, e: ToolExecution): Promise<{ decision: PreToolDecision; nextCalls: number }> {
  let nextCalls = 0
  const decision = await gate(e, async () => {
    nextCalls++
    return { kind: 'allow' } as PreToolDecision
  })
  return { decision, nextCalls }
}

function cleanup(c: { dir: string }) {
  rmSync(c.dir, { recursive: true, force: true })
}

test('extractGatedPath: known tools and arg shapes', () => {
  assert.equal(extractGatedPath('read', { file_path: '.env' }), '.env')
  assert.equal(extractGatedPath('write', { file_path: 'a/b' }), 'a/b')
  assert.equal(extractGatedPath('edit', { file_path: 'a/b' }), 'a/b')
  assert.equal(extractGatedPath('read_image', { file_path: 'x.png' }), 'x.png')
  assert.equal(extractGatedPath('glob', { pattern: '*.ts', path: 'src' }), 'src')
  assert.equal(extractGatedPath('grep', { pattern: 'x', path: 'src' }), 'src')
  assert.equal(extractGatedPath('grep', { pattern: 'x' }), undefined)
  assert.equal(extractGatedPath('bash', { command: 'cat .env' }), undefined)
  assert.equal(extractGatedPath('read', { file_path: 42 }), undefined)
  assert.equal(extractGatedPath('read', 'not-an-object'), undefined)
})

test('gate: read/write/edit on .env are denied with guidance', async () => {
  const c = makeContext()
  try {
    const gate = createGateHandler(c)
    for (const tool of ['read', 'write', 'edit']) {
      const { decision, nextCalls } = await run(gate, exec(tool, { file_path: '.env' }))
      assert.equal(decision.kind, 'deny', `${tool} should be denied`)
      assert.equal(nextCalls, 0, `${tool} deny must short-circuit`)
      const reason = (decision as { reason: string }).reason
      assert.match(reason, /env-file/)
      assert.match(reason, /sg_/)
      assert.match(reason, /\.env/)
    }
  } finally {
    cleanup(c)
  }
})

test('gate: block-read vs block-write semantics', async () => {
  const c = makeContext()
  try {
    const gate = createGateHandler(c)
    assert.equal((await run(gate, exec('read', { file_path: 'api.env' }))).decision.kind, 'deny')
    const write = await run(gate, exec('write', { file_path: 'api.env' }))
    assert.equal(write.decision.kind, 'allow')
    assert.equal(write.nextCalls, 1)
    assert.equal((await run(gate, exec('read', { file_path: 'id_rsa' }))).decision.kind, 'deny')
    assert.equal((await run(gate, exec('write', { file_path: 'id_rsa' }))).decision.kind, 'allow')
  } finally {
    cleanup(c)
  }
})

test('gate: example env files and unclassified paths pass through', async () => {
  const c = makeContext()
  try {
    const gate = createGateHandler(c)
    for (const [tool, args] of [
      ['read', { file_path: '.env.example' }],
      ['write', { file_path: '.env.example' }],
      ['read', { file_path: 'README.md' }],
      ['read', { file_path: 'src/main.ts' }],
      ['read', { file_path: undefined }],
      ['read', {}],
      ['bash', { command: 'cat .env' }],
    ] as [string, Record<string, unknown>][]) {
      const { decision, nextCalls } = await run(gate, exec(tool, args))
      assert.equal(decision.kind, 'allow', `${tool} ${JSON.stringify(args)} should pass`)
      assert.equal(nextCalls, 1)
    }
  } finally {
    cleanup(c)
  }
})

test('gate: allow list overrides default block', async () => {
  const c = makeContext({ allow: ['tests/fixtures/.env'] })
  try {
    const gate = createGateHandler(c)
    assert.equal((await run(gate, exec('read', { file_path: 'tests/fixtures/.env' }))).decision.kind, 'allow')
    assert.equal((await run(gate, exec('read', { file_path: 'other/.env' }))).decision.kind, 'deny')
  } finally {
    cleanup(c)
  }
})

test('gate: custom rules and gateTools selection', async () => {
  const c = makeContext({
    rules: [{ id: 'db-config', match: '**/db.config', effect: 'block' }],
    gateTools: ['read'],
  })
  try {
    const gate = createGateHandler(c)
    assert.equal((await run(gate, exec('read', { file_path: 'db.config' }))).decision.kind, 'deny')
    // write is not gated
    assert.equal((await run(gate, exec('write', { file_path: '.env' }))).decision.kind, 'allow')
  } finally {
    cleanup(c)
  }
})

test('gate: search tools are gated by path; glob is path-only, grep also checks patterns', async () => {
  const c = makeContext()
  try {
    const gate = createGateHandler(c)
    // a directory path matches no file rule; the scrubber is the net for content leaks
    assert.equal((await run(gate, exec('glob', { pattern: '**/*.ts', path: '.aws' }))).decision.kind, 'allow')
    // a sensitive FILE path is denied for both search tools
    assert.equal((await run(gate, exec('glob', { pattern: '*', path: '.aws/credentials' }))).decision.kind, 'deny')
    assert.equal((await run(gate, exec('grep', { pattern: 'FOO', path: '.aws/credentials' }))).decision.kind, 'deny')
    assert.equal((await run(gate, exec('grep', { pattern: 'FOO', path: 'src' }))).decision.kind, 'allow')
    // glob pattern alone never triggers the keyword guard
    assert.equal((await run(gate, exec('glob', { pattern: '.env*', path: '.' }))).decision.kind, 'allow')
    // grep pattern with secret keywords is blocked even against an open path
    const blocked = await run(gate, exec('grep', { pattern: 'password', path: '.' }))
    assert.equal(blocked.decision.kind, 'deny')
    assert.match((blocked.decision as { reason: string }).reason, /search-keyword-guard/)
    // innocuous pattern passes
    assert.equal((await run(gate, exec('grep', { pattern: 'function main', path: '.' }))).decision.kind, 'allow')
  } finally {
    cleanup(c)
  }
})

test('gate: search keyword guard is disabled', async () => {
  const c = makeContext({ guardSearchPatterns: false })
  try {
    const gate = createGateHandler(c)
    assert.equal((await run(gate, exec('grep', { pattern: 'password', path: '.' }))).decision.kind, 'allow')
    assert.equal((await run(gate, exec('grep', { pattern: 'x', path: '.env' }))).decision.kind, 'deny')
  } finally {
    cleanup(c)
  }
})

test('gate: search keyword guard survives regex obfuscation', async () => {
  const c = makeContext()
  try {
    const gate = createGateHandler(c)
    for (const pattern of ['pass.?word', 'se.cret', 'p[a]ssw', 'aP\\Is*KeY', 'API_KEY', 'p*assword', 's*ecret', 'c*redential', 'pa*ssword']) {
      const r = await run(gate, exec('grep', { pattern, path: '.' }))
      assert.equal(r.decision.kind, 'deny', `pattern '${pattern}' should be blocked`)
    }
    // legitimately innocent patterns still pass
    for (const pattern of ['environment', 'env=', 'function main', 'ssl_certificate', 'x.y']) {
      const r = await run(gate, exec('grep', { pattern, path: '.' }))
      assert.equal(r.decision.kind, 'allow', `pattern '${pattern}' should pass`)
    }
  } finally {
    cleanup(c)
  }
})

test('gate: read_image is gated once added to gateTools (default includes it)', async () => {
  const c = makeContext()
  try {
    assert.ok(c.config.gateTools.includes('read_image'))
    const gate = createGateHandler(c)
    assert.equal((await run(gate, exec('read_image', { file_path: '.env' }))).decision.kind, 'deny')
    assert.equal((await run(gate, exec('read_image', { file_path: '.env.example' }))).decision.kind, 'allow')
  } finally {
    cleanup(c)
  }
})

test('gate: blocked calls are journaled without any value content', async () => {
  const c = makeContext()
  try {
    const gate = createGateHandler(c)
    // a secret-shaped value rides in a non-path argument; it must never
    // appear in the journal
    await run(gate, exec('read', { file_path: '.env', hint: 'API_KEY=sk-live-secret-abcdef1234567890' }))
    const entries = c.journal.readAll()
    assert.equal(entries.length, 1)
    const e = entries[0]!
    assert.equal(e.kind, 'block')
    assert.equal(e.tool, 'read')
    assert.equal(e.path, '.env')
    assert.equal(e.rule, 'env-file')
    const serialized = JSON.stringify(e)
    assert.ok(!serialized.includes('API_KEY'))
    assert.ok(!serialized.includes('sk-live-secret'))
  } finally {
    cleanup(c)
  }
})
