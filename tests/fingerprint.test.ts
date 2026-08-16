import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Fingerprinter } from '../src/fingerprint.ts'

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), 'sg-fp-'))
}

test('Fingerprinter: deterministic per seal key, distinct across values', async () => {
  const dir = tempDir()
  try {
    const fp = await Fingerprinter.create({ env: 'SG_TEST_NONE', path: join(dir, 'seal.key') })
    const a = fp.fingerprint('secret-value')
    const b = fp.fingerprint('secret-value')
    assert.equal(a, b)
    assert.match(a, /^[0-9a-f]{16}$/)
    assert.notEqual(fp.fingerprint('secret-value'), fp.fingerprint('other-value'))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Fingerprinter: creates and persists the seal key file', async () => {
  const dir = tempDir()
  try {
    const path = join(dir, 'nested', 'seal.key')
    const fp = await Fingerprinter.create({ env: 'SG_TEST_NONE', path })
    assert.ok(existsSync(path))
    assert.match(readFileSync(path, 'utf8').trim(), /^[0-9a-f]{64}$/)
    const fp2 = await Fingerprinter.create({ env: 'SG_TEST_NONE', path })
    assert.equal(fp.fingerprint('x'), fp2.fingerprint('x'))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Fingerprinter: env var takes precedence over file', async () => {
  const dir = tempDir()
  try {
    const path = join(dir, 'seal.key')
    process.env.SG_TEST_ENV = 'a'.repeat(32)
    try {
      const fp = await Fingerprinter.create({ env: 'SG_TEST_ENV', path })
      assert.ok(!existsSync(path), 'seal key file must not be created when env is set')
      const fp2 = await Fingerprinter.create({ env: 'SG_TEST_ENV', path })
      assert.equal(fp.fingerprint('x'), fp2.fingerprint('x'))
    } finally {
      delete process.env.SG_TEST_ENV
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Fingerprinter: different seal keys produce different fingerprints', async () => {
  const dir = tempDir()
  try {
    const fpA = await Fingerprinter.create({ env: 'SG_TEST_A', path: join(dir, 'a.key') })
    process.env.SG_TEST_A = 'k'.repeat(32)
    const fpB = await Fingerprinter.create({ env: 'SG_TEST_A', path: join(dir, 'a.key') })
    assert.notEqual(fpA.fingerprint('same-value'), fpB.fingerprint('same-value'))
    delete process.env.SG_TEST_A
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Fingerprinter.equals: constant-time outside-in comparison', async () => {
  const dir = tempDir()
  try {
    const fp = await Fingerprinter.create({ env: 'SG_TEST_NONE', path: join(dir, 'seal.key') })
    assert.equal(fp.equals('the-stored-secret', 'the-stored-secret'), true)
    assert.equal(fp.equals('the-stored-secret', 'the-stored-secrex'), false)
    assert.equal(fp.equals('', ''), true)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Fingerprinter: accepts a hex seal key file', async () => {
  const dir = tempDir()
  try {
    const path = join(dir, 'seal.key')
    const hex = Buffer.alloc(32, 7).toString('hex')
    writeFileSync(path, hex + '\n')
    const fp = await Fingerprinter.create({ env: 'SG_TEST_NONE', path })
    assert.equal(fp.fingerprint('x'), fp.fingerprint('x'))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
