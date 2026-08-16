import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-tools'
import type { ToolExecution, ToolDefinition } from '@deepseek-ai/dsh-tools'
import { apply } from '../src/index.ts'

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), 'sg-int-'))
}

function fakeExec(name: string, args: unknown): ToolExecution {
  return {
    name,
    arguments: args,
    callId: `int-${name}` as never,
    signal: new AbortController().signal,
    agent: undefined,
    rootCallId: undefined as never,
    token: Symbol() as never,
  } as unknown as ToolExecution
}

interface Harness {
  dir: string
  disposer: () => void
  preHandlers: ((...a: never[]) => unknown)[]
  postHandlers: ((...a: never[]) => unknown)[]
  tools: ToolDefinition[]
  logs: string[]
  journalDir: string
  rulesFile: string
}

function mount(config: Record<string, unknown>): Harness {
  const dir = tempDir()
  const journalDir = join(dir, 'logs')
  const rulesFile = join(dir, 'rules.json')
  const tools: ToolDefinition[] = []
  const preHandlers: ((...a: never[]) => unknown)[] = []
  const postHandlers: ((...a: never[]) => unknown)[] = []
  const logs: string[] = []
  const mockCtx = {
    tools: {
      register: (def: ToolDefinition) => {
        tools.push(def)
        return () => {}
      },
    },
    on: (name: string, handler: (...a: never[]) => unknown) => {
      if (name === 'tools/pre-execute') preHandlers.push(handler)
      if (name === 'tools/post-execute') postHandlers.push(handler)
      return () => {}
    },
    logger: (scope: string) => ({
      info: (...m: unknown[]) => logs.push(`[${scope}] info ${m.join(' ')}`),
      warn: (...m: unknown[]) => logs.push(`[${scope}] warn ${m.join(' ')}`),
      error: (...m: unknown[]) => logs.push(`[${scope}] error ${m.join(' ')}`),
    }),
  }
  const disposer = apply(mockCtx as never, {
    audit: { dir: journalDir },
    sealKey: { path: join(dir, 'seal.key') },
    rulesFile,
    watchRules: true,
    ...config,
  })
  return { dir, disposer, preHandlers, postHandlers, tools, logs, journalDir, rulesFile }
}

async function dispatchPre(ctx: Context, exec: ToolExecution) {
  let nextCalls = 0
  const decision = await ctx.waterfall(
    'tools/pre-execute',
    exec,
    () => {
      nextCalls++
      return Promise.resolve({ kind: 'allow' })
    },
  )
  return { decision, nextCalls }
}

test('apply: wires listeners, tools and returns a disposer', () => {
  const h = mount({})
  try {
    assert.equal(h.preHandlers.length, 1)
    assert.equal(h.postHandlers.length, 1)
    const names = h.tools.map(t => t.name)
    for (const expected of ['sg_keys', 'sg_scan', 'sg_fingerprint', 'sg_probe', 'sg_status', 'sg_reload']) {
      assert.ok(names.includes(expected), `missing tool ${expected}`)
    }
    assert.equal(typeof h.disposer, 'function')
    h.disposer()
  } finally {
    rmSync(h.dir, { recursive: true, force: true })
  }
})

test('integration: real cordis waterfall enforces the gate', async () => {
  const h = mount({})
  try {
    const ctx = new Context()
    const handler = h.preHandlers[0]!
    ctx.on('tools/pre-execute', handler as never)
    const denied = await dispatchPre(ctx, fakeExec('read', { file_path: '.env' }))
    assert.equal(denied.decision.kind, 'deny')
    assert.equal(denied.nextCalls, 0)
    const allowed = await dispatchPre(ctx, fakeExec('read', { file_path: '.env.example' }))
    assert.equal(allowed.decision.kind, 'allow')
    assert.equal(allowed.nextCalls, 1)
    const write = await dispatchPre(ctx, fakeExec('write', { file_path: 'api.env' }))
    assert.equal(write.decision.kind, 'allow', 'block-read must not block writes')
    // the deny was journaled
    const entries = JSON.parse(readFileSync(join(h.journalDir, 'events.jsonl'), 'utf8').trim().split('\n').pop()!)
    assert.equal(entries.kind, 'block')
  } finally {
    rmSync(h.dir, { recursive: true, force: true })
  }
})

test('integration: post-execute scrubber masks result content', async () => {
  const h = mount({})
  try {
    const ctx = new Context()
    const handler = h.postHandlers[0]!
    ctx.on('tools/post-execute', handler as never)
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
    const secretResult = { isError: false, value: null, content: [{ type: 'text', text: `token=${jwt}` }] }
    const decision = await ctx.waterfall(
      'tools/post-execute',
      fakeExec('read', { file_path: 'x' }),
      secretResult as never,
      () => Promise.resolve({ kind: 'accept' }),
    ) as { kind: 'accept'; content: { type: 'text'; text: string }[] }
    assert.equal(decision.kind, 'accept')
    const text = decision.content.map(b => b.type === 'text' ? b.text : '').join('\n')
    assert.ok(!text.includes(jwt))
    assert.match(text, /redacted \d+ secret-shaped value/)
    // nothing changed -> the decision is passed through untouched
    // (in the real pipeline the registry keeps the result's own content)
    const clean = await ctx.waterfall(
      'tools/post-execute',
      fakeExec('read', { file_path: 'x' }),
      { isError: false, value: null, content: [{ type: 'text', text: 'hello world' }] } as never,
      () => Promise.resolve({ kind: 'accept' }),
    )
    assert.deepEqual(clean, { kind: 'accept' })
    // failed results carry content too; masking must not flip them to success
    const failed = await ctx.waterfall(
      'tools/post-execute',
      fakeExec('bash', { command: 'cat x' }),
      { isError: true, error: { message: 'boom' }, content: [{ type: 'text', text: `leaked=${jwt}` }] } as never,
      () => Promise.resolve({ kind: 'accept' }),
    ) as { kind: 'accept'; content: { type: 'text'; text: string }[] }
    const failedText = failed.content.map(b => b.text).join('\n')
    assert.ok(!failedText.includes(jwt))
    assert.match(failedText, /redacted \d+ secret-shaped value/)
    h.disposer()
  } finally {
    rmSync(h.dir, { recursive: true, force: true })
  }
})

test('integration: sg_keys never exposes values', async () => {
  const h = mount({})
  try {
    const envFile = join(h.dir, '.env')
    writeFileSync(envFile, 'API_KEY=sk-super-secret-value-123456\nDB_PASSWORD="hunter2hunter2"\nEMPTY=\n')
    const def = h.tools.find(t => t.name === 'sg_keys')!
    const value = await def.execute({ file: envFile }, {
      signal: new AbortController().signal,
    } as never) as { keys: { name: string; hasValue: boolean; shape: string }[] }
    assert.deepEqual(value.keys.map(k => k.name), ['API_KEY', 'DB_PASSWORD', 'EMPTY'])
    assert.equal(value.keys[0]!.hasValue, true)
    assert.equal(value.keys[2]!.hasValue, false)
    assert.equal(value.keys[0]!.shape, 'opaque')
    const rendered = def.output.render({ file: envFile }, value).map(b => b.type === 'text' ? b.text : '').join('\n')
    assert.ok(!rendered.includes('sk-super-secret'))
    assert.ok(!rendered.includes('hunter2hunter2'))
    assert.ok(rendered.includes('API_KEY'))
  } finally {
    rmSync(h.dir, { recursive: true, force: true })
  }
})

test('integration: sg_probe equals uses fingerprints, others answer booleans', async () => {
  const h = mount({})
  try {
    const envFile = join(h.dir, '.env')
    writeFileSync(envFile, 'SECRET=correct-horse-battery-staple\n')
    const def = h.tools.find(t => t.name === 'sg_probe')!
    const exec = { signal: new AbortController().signal } as never
    const eq = await def.execute({ file: envFile, key: 'SECRET', op: 'equals', value: 'correct-horse-battery-staple' }, exec) as { result: boolean }
    assert.equal(eq.result, true)
    const neq = await def.execute({ file: envFile, key: 'SECRET', op: 'equals', value: 'wrong' }, exec) as { result: boolean }
    assert.equal(neq.result, false)
    const empty = await def.execute({ file: envFile, key: 'MISSING', op: 'is-empty' }, exec) as { result: boolean }
    assert.equal(empty.result, true, 'absent key reads as empty')
    const unset = await def.execute({ file: envFile, key: 'MISSING', op: 'is-set' }, exec) as { result: boolean }
    assert.equal(unset.result, false, 'absent key is not set')
    const sw = await def.execute({ file: envFile, key: 'SECRET', op: 'starts-with', value: 'correct' }, exec) as { result: boolean }
    assert.equal(sw.result, true)
    const m = await def.execute({ file: envFile, key: 'SECRET', op: 'matches', pattern: '^correct' }, exec) as { result: boolean }
    assert.equal(m.result, true)
    await assert.rejects(
      def.execute({ file: envFile, key: 'NOPE', op: 'starts-with', value: 'x' }, exec),
      /not found/,
    )
  } finally {
    rmSync(h.dir, { recursive: true, force: true })
  }
})

test('integration: sg_scan and sg_fingerprint', async () => {
  const h = mount({})
  try {
    const envFile = join(h.dir, '.env')
    writeFileSync(envFile, 'TOKEN=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\nPORT=5432\n')
    const scan = h.tools.find(t => t.name === 'sg_scan')!
    const sval = await scan.execute({ file: envFile }, { signal: new AbortController().signal } as never) as { results: { name: string; shape: string }[] }
    assert.deepEqual(sval.results.map(r => [r.name, r.shape]), [['TOKEN', 'jwt'], ['PORT', 'numeric']])
    const fp = h.tools.find(t => t.name === 'sg_fingerprint')!
    const fval = await fp.execute({ file: envFile, key: 'TOKEN' }, { signal: new AbortController().signal } as never) as { fingerprint: string }
    assert.match(fval.fingerprint, /^[0-9a-f]{16}$/)
    // deterministic across calls
    const fval2 = await fp.execute({ file: envFile, key: 'TOKEN' }, { signal: new AbortController().signal } as never) as { fingerprint: string }
    assert.equal(fval.fingerprint, fval2.fingerprint)
  } finally {
    rmSync(h.dir, { recursive: true, force: true })
  }
})

test('integration: sg_status reports policy and classifies paths', async () => {
  const h = mount({ allow: ['tests/fixtures/.env'] })
  try {
    const def = h.tools.find(t => t.name === 'sg_status')!
    const exec = { signal: new AbortController().signal } as never
    const value = await def.execute({ check: '.env' }, exec) as { check: { path: string; effect: string; rule: string } | null }
    assert.equal(value.check?.effect, 'block')
    assert.equal(value.check?.rule, 'env-file')
    const allowed = await def.execute({ check: 'tests/fixtures/.env' }, exec) as { check: { effect: string; rule: string } | null }
    assert.equal(allowed.check?.effect, 'allow')
    const text = def.output.render({}, value).map(b => b.type === 'text' ? b.text : '').join('\n')
    assert.match(text, /env-file/)
  } finally {
    rmSync(h.dir, { recursive: true, force: true })
  }
})

test('integration: rules file is loaded at startup', async () => {
  const dir = tempDir()
  const rulesFile = join(dir, 'rules.json')
  writeFileSync(rulesFile, JSON.stringify({ rules: [{ id: 'boot-rule', match: '**/boot.env', effect: 'block' }] }))
  const h = mount({ rulesFile })
  try {
    const status = h.tools.find(t => t.name === 'sg_status')!
    const v = await status.execute({ check: 'boot.env' }, { signal: new AbortController().signal } as never) as { check: { rule: string | null } | null }
    assert.equal(v.check?.rule, 'boot-rule')
    h.disposer()
  } finally {
    rmSync(h.dir, { recursive: true, force: true })
    rmSync(dir, { recursive: true, force: true })
  }
})

test('integration: rules hot reload via sg_reload and file watch', async () => {
  const h = mount({})
  try {
    const reload = h.tools.find(t => t.name === 'sg_reload')!
    const exec = { signal: new AbortController().signal } as never
    writeFileSync(h.rulesFile, JSON.stringify({ rules: [{ id: 'custom-x', match: '**/extra.env', effect: 'block' }] }))
    const r = await reload.execute({}, exec) as { ok: boolean; rules: number }
    assert.equal(r.ok, true)
    assert.equal(r.rules, 1)
    // engine swapped: sg_status now sees the new rule
    const status = h.tools.find(t => t.name === 'sg_status')!
    const v = await status.execute({ check: 'extra.env' }, exec) as { check: { effect: string; rule: string } | null }
    assert.equal(v.check?.rule, 'custom-x')
    // hot reload through the file watcher: poll until the new rule shows up
    writeFileSync(h.rulesFile, JSON.stringify({ rules: [{ id: 'hot-y', match: '**/hot.env', effect: 'block-read' }], allow: ['tests/fixtures/.env'] }))
    const deadline = Date.now() + 6000
    let rule: string | null = null
    let allowEffect: string | null = null
    while (Date.now() < deadline) {
      const v2 = await status.execute({ check: 'hot.env' }, exec) as { check: { effect: string; rule: string | null } | null }
      rule = v2.check?.rule ?? null
      const v3 = await status.execute({ check: 'tests/fixtures/.env' }, exec) as { check: { effect: string; rule: string | null } | null }
      allowEffect = v3.check?.effect ?? null
      if (rule === 'hot-y' && allowEffect === 'allow') break
      await new Promise(resolve => setTimeout(resolve, 200))
    }
    assert.equal(rule, 'hot-y', 'watcher must hot-load the new rule')
    assert.equal(allowEffect, 'allow', 'watcher must hot-load allow entries too')
    // reload events were journaled
    const lines = readFileSync(join(h.journalDir, 'events.jsonl'), 'utf8').trim().split('\n').map(line => JSON.parse(line))
    assert.ok(lines.some(l => l.kind === 'reload'))
    h.disposer()
  } finally {
    rmSync(h.dir, { recursive: true, force: true })
  }
})

test('integration: malformed rules file keeps the old engine and journals an error', async () => {
  const h = mount({})
  try {
    const status = h.tools.find(t => t.name === 'sg_status')!
    const exec = { signal: new AbortController().signal } as never
    // non-object root must fail loud
    writeFileSync(h.rulesFile, '"just a string"')
    const reload = h.tools.find(t => t.name === 'sg_reload')!
    const r = await reload.execute({}, exec) as { ok: boolean; message?: string }
    assert.equal(r.ok, false)
    assert.ok(r.message)
    // array root must fail loud too
    writeFileSync(h.rulesFile, JSON.stringify([{ id: 'x', match: 'y', effect: 'block' }]))
    const r2 = await reload.execute({}, exec) as { ok: boolean }
    assert.equal(r2.ok, false)
    // invalid rule entries fail loud
    writeFileSync(h.rulesFile, JSON.stringify({ rules: [{ match: '', effect: 'block' }] }))
    const r3 = await reload.execute({}, exec) as { ok: boolean }
    assert.equal(r3.ok, false)
    // the engine still classifies with the configured defaults
    const v = await status.execute({ check: '.env' }, exec) as { check: { rule: string | null } | null }
    assert.equal(v.check?.rule, 'env-file')
    const lines = readFileSync(join(h.journalDir, 'events.jsonl'), 'utf8').trim().split('\n').map(line => JSON.parse(line))
    assert.ok(lines.some(l => l.kind === 'error'))
    h.disposer()
  } finally {
    rmSync(h.dir, { recursive: true, force: true })
  }
})

test('integration: block and mask events are journaled in order', async () => {
  const h = mount({})
  try {
    const ctx = new Context()
    ctx.on('tools/pre-execute', h.preHandlers[0]! as never)
    ctx.on('tools/post-execute', h.postHandlers[0]! as never)
    // a blocked read
    await ctx.waterfall('tools/pre-execute', fakeExec('read', { file_path: '.env' }), () => Promise.resolve({ kind: 'allow' }))
    // a masked grep result
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
    await ctx.waterfall(
      'tools/post-execute',
      fakeExec('grep', { pattern: 'FOO', path: 'src' }),
      { isError: false, value: null, content: [{ type: 'text', text: `token=${jwt}` }] } as never,
      () => Promise.resolve({ kind: 'accept' }),
    )
    const kinds = readFileSync(join(h.journalDir, 'events.jsonl'), 'utf8').trim().split('\n').map(line => JSON.parse(line)).map(e => e.kind)
    // init, then the startup rules-file probe (absent -> reload entry), then block, then mask
    assert.deepEqual(kinds, ['init', 'reload', 'block', 'mask'])
    h.disposer()
  } finally {
    rmSync(h.dir, { recursive: true, force: true })
  }
})

test('integration: scrubber (prepend) is the outermost post-execute decision', async () => {
  const h = mount({})
  try {
    const ctx = new Context()
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
    // a later-registered listener that tries to re-inject the secret
    const reInjector = (async (_exec: unknown, _result: unknown, next: () => Promise<unknown>) => {
      const downstream = await next() as { kind: 'accept'; content?: { type: 'text'; text: string }[] }
      if (downstream.kind === 'accept' && downstream.content !== undefined) {
        return { ...downstream, content: [{ type: 'text', text: `re-injected ${jwt}` }] }
      }
      return downstream
    })
    // the scrubber is registered with prepend:true (as apply does), so it runs
    // outermost: its masked decision is final and it re-masks the inner
    // listener's re-injection
    ctx.on('tools/post-execute', h.postHandlers[0]! as never, { prepend: true })
    ctx.on('tools/post-execute', reInjector as never)
    const decision = await ctx.waterfall(
      'tools/post-execute',
      fakeExec('read', { file_path: 'x' }),
      { isError: false, value: null, content: [{ type: 'text', text: `token=${jwt}` }] } as never,
      () => Promise.resolve({ kind: 'accept' }),
    ) as { kind: 'accept'; content: { type: 'text'; text: string }[] }
    const text = decision.content.map(b => b.text).join('\n')
    assert.ok(!text.includes(jwt), 'scrubber decision must be final')
    assert.match(text, /redacted \d+ secret-shaped value/)
    h.disposer()
  } finally {
    rmSync(h.dir, { recursive: true, force: true })
  }
})

test('integration: watchRules false and no rulesFile behave sanely', async () => {
  const h = mount({ watchRules: false })
  try {
    const reload = h.tools.find(t => t.name === 'sg_reload')!
    const r = await reload.execute({}, { signal: new AbortController().signal } as never) as { ok: boolean }
    assert.equal(r.ok, false, 'sg_reload without rulesFile must fail loudly')
    h.disposer()
    const h2 = mount({ watchRules: true, rulesFile: '' })
    try {
      const status = h2.tools.find(t => t.name === 'sg_status')!
      const v = await status.execute({}, { signal: new AbortController().signal } as never) as { rulesFile: string }
      assert.equal(v.rulesFile, '')
    } finally {
      h2.disposer()
    }
  } finally {
    rmSync(h.dir, { recursive: true, force: true })
  }
})

test('integration: sg_probe matches runs sandboxed and rejects pathological regexes', async () => {
  const h = mount({})
  try {
    const envFile = join(h.dir, '.env')
    writeFileSync(envFile, `A=${'a'.repeat(60)}\nB=${'a'.repeat(60)}!\n`)
    const def = h.tools.find(t => t.name === 'sg_probe')!
    const exec = { signal: new AbortController().signal } as never
    const normal = await def.execute({ file: envFile, key: 'A', op: 'matches', pattern: '^a+$' }, exec) as { result: boolean }
    assert.equal(normal.result, true)
    // a pathological pattern on a NON-matching string forces exponential
    // backtracking: the worker must time out instead of freezing the loop
    const t0 = Date.now()
    await assert.rejects(
      def.execute({ file: envFile, key: 'B', op: 'matches', pattern: '(a+)+$' }, exec),
      /timed out|exited/,
    )
    assert.ok(Date.now() - t0 < 8000, 'pathological regex must be cut off quickly')
    // invalid patterns produce a clean error
    await assert.rejects(
      def.execute({ file: envFile, key: 'A', op: 'matches', pattern: '(' }, exec),
      /[Ii]nvalid regular expression/,
    )
    h.disposer()
  } finally {
    rmSync(h.dir, { recursive: true, force: true })
  }
})

test('integration: plugin storage is created under .secret-guard style dirs only when used', async () => {
  const h = mount({})
  try {
    // seal key is created lazily on first fingerprint use
    const envFile = join(h.dir, '.env')
    writeFileSync(envFile, 'X=abc\n')
    const fp = h.tools.find(t => t.name === 'sg_fingerprint')!
    await fp.execute({ file: envFile, key: 'X' }, { signal: new AbortController().signal } as never)
    assert.equal(existsSync(join(h.dir, 'seal.key')), true)
    h.disposer()
  } finally {
    rmSync(h.dir, { recursive: true, force: true })
  }
})




