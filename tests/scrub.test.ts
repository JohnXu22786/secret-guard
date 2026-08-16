import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { ContentBlock } from '@deepseek-ai/dsh-llm'
import { scrubText, scrubBlocks } from '../src/scrub.ts'

function block(text: string): ContentBlock {
  return { type: 'text', text }
}

test('scrubText: masks JWTs', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
  const out = scrubText(`token=${jwt}`)
  assert.ok(out)
  assert.ok(!out.text.includes(jwt))
  assert.match(out.text, /\[redacted:jwt:\d+\]/)
  assert.equal(out.stats.count, 1)
  assert.equal(out.stats.kinds.jwt, 1)
})

test('scrubText: masks bearer tokens', () => {
  const token = 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789'
  const out = scrubText(token)
  assert.ok(out)
  assert.match(out.text, /\[redacted:bearer:\d+\]/)
  assert.ok(!out.text.includes('abcdefghijklmnopqrstuvwxyz0123456789'))
})

test('scrubText: masks well-known API key prefixes', () => {
  const cases: [string, string][] = [
    ['sk-proj-abcdefghijklmnopqrstuvwxyz123456', 'wellknown'],
    ['ghp_abcdefghijklmnopqrstuvwxyz1234567890', 'wellknown'],
    ['github_pat_abcdefghijklmnopqrstuvwxyz1234567', 'wellknown'],
    ['AKIAIOSFODNN7EXAMPLE', 'wellknown'],
    ['ASIAIOSFODNN7EXAMPLE', 'wellknown'],
    ['xoxb-123456789012-123456789012-abcdefghijkl', 'wellknown'],
  ]
  for (const [text, kind] of cases) {
    const out = scrubText(`key=${text}`)
    assert.ok(out, `expected mask for ${text.slice(0, 8)}...`)
    assert.ok(!out.text.includes(text), `value leaked: ${text.slice(0, 12)}`)
    assert.match(out.text, new RegExp(`\\[redacted:${kind}:\\d+\\]`))
  }
})

test('scrubText: does not mask sk- inside hyphen/underscore words', () => {
  const kept = [
    'task-sk-abcdefghijklmnopqrstuvwxyz123456',
    'risk_sk_abcdefghijklmnopqrstuvwxyz123456',
  ]
  for (const text of kept) {
    const out = scrubText(text)
    assert.equal(out, null, `must not mask word-embedded sk-: ${text}`)
  }
  // bare sk- at line start still masks
  const out = scrubText('sk-abcdefghijklmnopqrstuvwxyz123456')
  assert.ok(out)
})

test('scrubText: masks private key blocks', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----'
  const ssh = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA...\n-----END OPENSSH PRIVATE KEY-----'
  for (const text of [pem, ssh]) {
    const out = scrubText(text)
    assert.ok(out)
    assert.ok(!out.text.includes('MIIEpAIBAAKCAQEA0'))
    assert.match(out.text, /\[redacted:private-key:\d+\]/)
  }
})

test('scrubText: masks truncated private key blocks (no END line)', () => {
  const body = 'AAAAabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  const truncated = `-----BEGIN OPENSSH PRIVATE KEY-----\n${body}`
  const out = scrubText(truncated)
  assert.ok(out, 'truncated key block must be masked')
  assert.ok(!out.text.includes(body), 'base64 body must be removed')
  assert.match(out.text, /\[redacted:private-key:\d+\]/)
})

test('scrubText: masks connection strings with embedded credentials', () => {
  const urls = [
    'postgres://admin:hunter2hunter2@db.example.com:5432/app',
    'redis://:hunter2hunter2@cache:6379/0',
    'mongodb+srv://user:passw0rdpassw0rd@cluster0.abc.mongodb.net/app',
  ]
  for (const url of urls) {
    const out = scrubText(`db url: ${url}`)
    assert.ok(out, `expected mask for ${url.slice(0, 20)}`)
    assert.ok(!out.text.includes('hunter2hunter2') && !out.text.includes('passw0rdpassw0rd'))
    assert.match(out.text, /\[redacted:connstr:\d+\]/)
  }
})

test('scrubText: masks key=value assignments, keeps placeholder values intact', () => {
  const masked = [
    'password=hunter2hunter2hunter2',
    'API_TOKEN: "abcdefghijklmnopqrstuv"',
    'client_secret=AbCdEfGhIjKlMnOpQrStUvWxYz',
    'password="hunter2 hunter2 hunter2"', // quoted value with spaces
    'password=\'spaced quoted value here\'',
    'password=abcdefghijklmnop!qrstuvwxyz', // punctuation inside the value
  ]
  for (const text of masked) {
    const out = scrubText(text)
    assert.ok(out, `expected mask for ${text.slice(0, 20)}`)
    assert.match(out.text, /\[redacted:assignment:\d+\]/)
    assert.ok(!out.text.includes('hunter2hunter2hunter2'))
    assert.ok(!out.text.includes('hunter2 hunter2 hunter2'))
    assert.ok(!out.text.includes('abcdefghijklmnop!qrstuvwxyz'))
    assert.ok(!out.text.includes('AbCdEfGhIjKlMnOpQrStUvWxYz'))
  }
  const kept = [
    'password=<your-password>',
    'token: xxx',
    'secret=********',
    'password=change_me',
    'api_key=example',
    'token=...',
    'password=xxxxxxxxxxxxxxxxxxxx', // placeholder-ish, >= 12 chars
    'secret=example-example-example',
  ]
  for (const text of kept) {
    const out = scrubText(text)
    assert.equal(out, null, `placeholder must not be masked: ${text}`)
  }
})

test('scrubText: no false positives on hashes, urls without creds, short strings', () => {
  const safe = [
    '9faa50149750012e43a97f10e1f6af023beb271f', // git sha
    'https://example.com/docs/page?tab=2#top',
    'GET /api/v1/items HTTP/1.1',
    'plain text hello world',
    'base64ish AAAA',
    'line with equals sign a=b',
  ]
  for (const text of safe) {
    const out = scrubText(text)
    assert.equal(out, null, `unexpected mask: ${text}`)
  }
})

test('scrubBlocks: masks text blocks and appends a summary, preserves non-text blocks', () => {
  const blocks: ContentBlock[] = [
    { type: 'text', text: 'token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' },
    { type: 'text', text: 'second secret: AKIAIOSFODNN7EXAMPLE' },
  ]
  const out = scrubBlocks(blocks)
  assert.ok(out)
  assert.ok(out.blocks.length >= 3, 'summary block should be appended')
  const texts = out.blocks.map(b => (b.type === 'text' ? b.text : '')).join('\n')
  assert.ok(!texts.includes('SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'))
  assert.match(texts, /redacted \d+ secret-shaped value/)
  assert.equal(out.stats.count, 2)
})

test('scrubBlocks: returns null when nothing changed', () => {
  const out = scrubBlocks([block('nothing to see here')])
  assert.equal(out, null)
})

test('scrubBlocks: single mask counts twice across blocks', () => {
  const out = scrubBlocks([
    block('a=sk-abcdefghijklmnopqrstuvwxyz123456'),
    block('b=sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456'),
  ])
  assert.ok(out)
  assert.equal(out.stats.count, 2)
  assert.equal(out.stats.kinds.wellknown, 2)
})
