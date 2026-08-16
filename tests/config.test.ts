import { test } from 'node:test'
import assert from 'node:assert/strict'
import { resolveConfig } from '../src/config.ts'
import { join } from 'node:path'

test('resolveConfig: fills every default', () => {
  const c = resolveConfig({})
  assert.deepEqual(c.rules, [])
  assert.deepEqual(c.allow, [])
  assert.deepEqual(c.gateTools, ['read', 'write', 'edit', 'glob', 'grep', 'read_image'])
  assert.equal(c.guardSearchPatterns, true)
  assert.equal(c.maskResults, true)
  assert.equal(c.sealKey.env, 'SECRET_GUARD_SEAL_KEY')
  assert.equal(c.sealKey.path, join(process.cwd(), '.secret-guard/seal.key'))
  assert.equal(c.audit.enabled, true)
  assert.equal(c.audit.dir, join(process.cwd(), '.secret-guard/logs'))
  assert.equal(c.audit.maxBytes, 1048576)
  assert.equal(c.audit.keep, 5)
  assert.equal(c.rulesFile, '')
  assert.equal(c.watchRules, true)
})

test('resolveConfig: resolves relative seal/audit paths against cwd', () => {
  const c = resolveConfig({ sealKey: { path: 'keys/sg.key' }, audit: { dir: 'logs' } }, 'C:\\proj')
  assert.equal(c.sealKey.path, 'C:\\proj\\keys\\sg.key')
  assert.equal(c.audit.dir, 'C:\\proj\\logs')
  const abs = resolveConfig({ sealKey: { path: '/abs/keys/sg.key' }, audit: { dir: 'D:\\other\\logs' } }, 'C:\\proj')
  assert.equal(abs.sealKey.path, '/abs/keys/sg.key')
  assert.equal(abs.audit.dir, 'D:\\other\\logs')
})

test('resolveConfig: assigns auto ids to custom rules', () => {
  const c = resolveConfig({ rules: [{ match: '**/x.env', effect: 'block-read' }] })
  assert.equal(c.rules[0]!.id, 'custom-0')
  assert.equal(c.rules[0]!.match, '**/x.env')
  assert.equal(c.rules[0]!.effect, 'block-read')
})

test('resolveConfig: rejects invalid input fail-loud', () => {
  assert.throws(() => resolveConfig({ rules: [{ match: '', effect: 'block' }] }), /match/)
  assert.throws(() => resolveConfig({ rules: [{ match: '.env', effect: 'nuke' }] }), /nuke/)
  assert.throws(() => resolveConfig({ audit: { keep: 0 } }), /keep/)
  assert.throws(() => resolveConfig({ audit: { maxBytes: -1 } }), /maxBytes/)
  assert.throws(() => resolveConfig({ sealKey: { path: '' } }), /sealKey/)
  assert.throws(() => resolveConfig({ audit: { dir: '' } }), /audit\.dir/)
})

test('resolveConfig: schemastery Config schema validates and defaults', async () => {
  const { Config } = await import('../src/config.ts')
  const raw = Config({
    rules: [{ id: 'r1', match: '.env', effect: 'block' }],
    allow: ['a/.env'],
    gateTools: ['read'],
    maskResults: false,
  })
  assert.equal(raw.maskResults, false)
  assert.equal(raw.gateTools[0], 'read')
  assert.equal(raw.allow[0], 'a/.env')
  const empty = Config({})
  assert.equal(empty.maskResults, true)
  assert.equal(empty.watchRules, true)
  assert.throws(() => Config({ maskResults: 'yes' } as never))
  assert.throws(() => Config({ gateTools: 'read' } as never))
  assert.throws(() => Config({ rules: [{ match: '.env', effect: 'maybe' }] } as never))
})

test('resolveConfig: preserves explicit audit overrides', () => {
  const c = resolveConfig({
    audit: { enabled: false, maxBytes: 4096, keep: 2, dir: 'x/y' },
    guardSearchPatterns: false,
    watchRules: false,
  })
  assert.equal(c.audit.enabled, false)
  assert.equal(c.audit.maxBytes, 4096)
  assert.equal(c.audit.keep, 2)
  assert.equal(c.audit.dir, join(process.cwd(), 'x/y'))
  assert.equal(c.guardSearchPatterns, false)
  assert.equal(c.watchRules, false)
})

