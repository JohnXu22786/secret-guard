import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseDotenv, classifyShape } from '../src/inspect.ts'

test('parseDotenv: basic key/value, comments, blanks, export', () => {
  const text = [
    '# leading comment',
    'API_KEY=abc123',
    '',
    'DB_PASSWORD="p@ss word"',
    'export FOO=bar',
    'EMPTY=',
    '   # indented comment',
    'TAIL=last',
  ].join('\n')
  const entries = parseDotenv(text)
  assert.deepEqual(entries.map(e => e.name), ['API_KEY', 'DB_PASSWORD', 'FOO', 'EMPTY', 'TAIL'])
  assert.equal(entries[0]!.value, 'abc123')
  assert.equal(entries[1]!.value, 'p@ss word')
  assert.equal(entries[2]!.value, 'bar')
  assert.equal(entries[3]!.value, '')
  assert.equal(entries[4]!.value, 'last')
  assert.equal(entries[0]!.line, 2)
  assert.equal(entries[3]!.line, 6)
})

test('parseDotenv: quoting and escapes', () => {
  const text = [
    'A="a b"',
    "B='x y'",
    'C="say \\"hi\\""',
    'D=val # inline comment',
    'E="val # kept"',
    "F='val # kept'",
  ].join('\n')
  const entries = parseDotenv(text)
  assert.equal(entries[0]!.value, 'a b')
  assert.equal(entries[1]!.value, 'x y')
  assert.equal(entries[2]!.value, 'say "hi"')
  assert.equal(entries[3]!.value, 'val')
  assert.equal(entries[4]!.value, 'val # kept')
  assert.equal(entries[5]!.value, 'val # kept')
})

test('parseDotenv: inline comments after quoted values do not leak quotes', () => {
  const text = [
    'A="a b" # trailing note',
    "B='x y' # note",
    'C="c"#attached comment',
    'D="x # inside" # outside',
    'E=val # plain comment',
  ].join('\n')
  const entries = parseDotenv(text)
  assert.equal(entries[0]!.value, 'a b', 'double-quoted value with trailing comment')
  assert.equal(entries[1]!.value, 'x y', 'single-quoted value with trailing comment')
  assert.equal(entries[2]!.value, 'c', 'comment attached without whitespace')
  assert.equal(entries[3]!.value, 'x # inside', 'comment inside quotes is part of the value')
  assert.equal(entries[4]!.value, 'val')
  // a quote not closing before another token stays unquoted
  const mixed = parseDotenv('A="a" "b"')
  assert.equal(mixed[0]!.value, '"a" "b"')
})

test('parseDotenv: CRLF and malformed lines', () => {
  const text = 'A=1\r\nB=2\r\njust a line\r\nC=3'
  const entries = parseDotenv(text)
  assert.deepEqual(entries.map(e => e.name), ['A', 'B', 'C'])
})

test('parseDotenv: values containing equals', () => {
  const entries = parseDotenv('JWT=eyJ.x.abc=def\nB=2')
  assert.equal(entries[0]!.value, 'eyJ.x.abc=def')
})

test('parseDotenv: empty input', () => {
  assert.deepEqual(parseDotenv(''), [])
  assert.deepEqual(parseDotenv('\n\n# only comment\n'), [])
})

test('classifyShape: discriminates value shapes without revealing them', () => {
  assert.equal(classifyShape(''), 'empty')
  assert.equal(classifyShape('true'), 'bool')
  assert.equal(classifyShape('FALSE'), 'bool')
  assert.equal(classifyShape('42'), 'numeric')
  assert.equal(classifyShape('-3.14'), 'numeric')
  assert.equal(classifyShape('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'), 'jwt')
  assert.equal(classifyShape('https://example.com/x?y=1'), 'url')
  assert.equal(classifyShape('postgres://u:p@db:5432/app'), 'url')
  assert.equal(classifyShape('QUJDRAEFGHIJKLMNOPQRSTUVWXYZ0123456789+/AA=='), 'base64')
  assert.equal(classifyShape('0123456789abcdef0123456789abcdef'), 'hex')
  assert.equal(classifyShape('a plain phrase with spaces'), 'opaque')
  assert.equal(classifyShape('short'), 'opaque')
})
