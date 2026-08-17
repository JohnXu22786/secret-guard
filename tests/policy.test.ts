import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  normalizePath,
  compileGlob,
  defaultRules,
  PolicyEngine,
  type Rule,
} from '../src/policy.ts'

test('normalizePath: strips drives, slashes, prefixes', () => {
  assert.equal(normalizePath('.env'), '.env')
  assert.equal(normalizePath('./.env'), '.env')
  assert.equal(normalizePath('src//.env'), 'src/.env')
  assert.equal(normalizePath('sub\\dir\\.env'), 'sub/dir/.env')
  assert.equal(normalizePath('C:\\proj\\.env'), 'proj/.env')
  assert.equal(normalizePath('file:///etc/.env'), 'etc/.env')
  assert.equal(normalizePath('../x/.env'), 'x/.env')
  assert.equal(normalizePath('../../../etc/passwd'), 'etc/passwd')
  assert.equal(normalizePath(''), '')
})

test('normalizePath: folds interior .. segments', () => {
  assert.equal(normalizePath('config/../prod/.env'), 'prod/.env')
  assert.equal(normalizePath('a/b/../../c'), 'c')
  assert.equal(normalizePath('a/./b'), 'a/b')
  assert.equal(normalizePath('file:///C:/foo/.env'), 'foo/.env')
  assert.equal(normalizePath('C:/a/../b/.env'), 'b/.env')
})

test('compileGlob: basename patterns are exact anchors', () => {
  const re = compileGlob('.env')
  assert.ok(re.test('.env'))
  assert.ok(!re.test('.env.example'))
  assert.ok(!re.test('api.env'))
  assert.ok(!re.test('src/.env')) // depth matching is the engine's job
})

test('PolicyEngine: basename rules match at any depth', () => {
  const e = new PolicyEngine([], [], [{ id: 'x', match: '.env', effect: 'block' }])
  assert.equal(e.classify('.env').effect, 'block')
  assert.equal(e.classify('src/.env').effect, 'block')
  assert.equal(e.classify('a/b/c/.env').effect, 'block')
})

test('compileGlob: full-path patterns are anchored', () => {
  const re = compileGlob('**/.aws/credentials')
  assert.ok(re.test('.aws/credentials'))
  assert.ok(re.test('x/.aws/credentials'))
  assert.ok(!re.test('notaws/credentials'))
  const nested = compileGlob('config/env/prod.env')
  assert.ok(nested.test('config/env/prod.env'))
  assert.ok(!nested.test('other/config/env/prod.env'))
  assert.ok(!nested.test('config/env/prod.env.bak'))
})

test('compileGlob: mid-pattern **/ matches zero directory levels (gitignore semantics)', () => {
  const mid = compileGlob('foo/**/bar')
  assert.ok(mid.test('foo/bar'), 'zero directory levels must match')
  assert.ok(mid.test('foo/x/bar'))
  assert.ok(mid.test('foo/x/y/bar'))
  assert.ok(!mid.test('foo/bar/baz'), 'anchored: must not match deeper paths')
  assert.ok(!mid.test('notfoo/bar'))
  const trailing = compileGlob('foo/**')
  assert.ok(trailing.test('foo/x'))
  assert.ok(trailing.test('foo/x/y'))
  assert.ok(trailing.test('foo/x/.env'), 'trailing ** keeps matching anything below')
  assert.ok(!trailing.test('notfoo/x'), 'anchored: other roots must not match')
})

test('compileGlob: star/question semantics', () => {
  const star = compileGlob('*.env')
  assert.ok(star.test('api.env'))
  assert.ok(!star.test('.env.local'))
  assert.ok(!star.test('a/api.env'))
  const question = compileGlob('id_rsa?')
  assert.ok(question.test('id_rsax'))
  assert.ok(!question.test('id_rsaxx'))
  const any = compileGlob('*credential*')
  assert.ok(any.test('credentials.json'))
  assert.ok(any.test('prod-credentials.yml'))
  assert.ok(!any.test('docs/index.md'))
})

test('defaultRules: covers the documented sensitive surface', () => {
  const ids = defaultRules().map(r => r.id)
  for (const expected of [
    'guard-vault', 'env-example', 'env-file', 'env-variant', 'env-suffixed',
    'aws-credentials', 'git-credentials', 'netrc', 'npmrc-auth', 'pypirc',
    'credential-files', 'ssh-rsa', 'ssh-ed25519', 'key-ext-pem', 'key-ext-key',
  ]) {
    assert.ok(ids.includes(expected), `missing default rule ${expected}`)
  }
})

function engine(overrides: { allow?: string[]; rules?: Rule[] } = {}): PolicyEngine {
  return new PolicyEngine(
    overrides.allow ?? [],
    overrides.rules ?? [],
    defaultRules(),
  )
}

test('PolicyEngine: default classifications', () => {
  const e = engine()
  const cases: [string, string][] = [
    ['.env', 'block'],
    ['src/.env', 'block'],
    ['.env.local', 'block'],
    ['config/.env.production', 'block'],
    ['api.env', 'block-read'],
    ['backend/api.env', 'block-read'],
    ['.env.example', 'allow'],
    ['docs/.env.sample', 'allow'],
    ['.env.template', 'allow'],
    ['.env.dist', 'allow'],
    ['.env.default', 'allow'],
    ['.aws/credentials', 'block'],
    ['home/.aws/credentials', 'block'],
    ['.git-credentials', 'block'],
    ['.netrc', 'block'],
    ['.npmrc', 'block-read'],
    ['.pypirc', 'block-read'],
    ['credentials.json', 'block'],
    ['ops/prod-credentials.yml', 'block'],
    ['id_rsa', 'block-read'],
    ['.ssh/id_ed25519', 'block-read'],
    ['keys/server.key', 'block-read'],
    ['certs/chain.pem', 'block-read'],
    ['vault.p12', 'block-read'],
    ['README.md', 'allow'],
    ['src/index.ts', 'allow'],
    ['.secret-guard/seal.key', 'block'],
    ['logs/.secret-guard/events.jsonl', 'block'],
  ]
  for (const [path, effect] of cases) {
    const c = e.classify(path)
    assert.equal(c.effect, effect, `expected ${path} -> ${effect}, got ${c.effect} (${c.rule?.id ?? 'no rule'})`)
  }
})

test('PolicyEngine: allow list overrides everything', () => {
  const e = engine({ allow: ['tests/fixtures/.env', '**/local.env'] })
  const c = e.classify('tests/fixtures/.env')
  assert.equal(c.effect, 'allow')
  assert.equal(c.rule?.id, 'allow:tests/fixtures/.env')
  assert.equal(e.classify('other/.env').effect, 'block')
  assert.equal(e.classify('x/local.env').effect, 'allow')
})

test('PolicyEngine: custom rules win over defaults, first match wins', () => {
  const e = engine({
    rules: [
      { id: 'sandbox', match: '**/sandbox.env', effect: 'block' },
      { id: 'readonly', match: '**/sandbox.env', effect: 'block-read' },
      { id: 'prod-open', match: '**/prod/**', effect: 'allow' },
    ],
  })
  const c = e.classify('a/sandbox.env')
  assert.equal(c.effect, 'block')
  assert.equal(c.rule?.id, 'sandbox')
  assert.equal(e.classify('prod/.env').effect, 'allow')
  // custom block beats default block (first-match, custom first)
  assert.equal(e.classify('prod/.env').rule?.id, 'prod-open')
})

test('PolicyEngine: classify on raw absolute Windows path', () => {
  const e = engine()
  assert.equal(e.classify('C:\\Users\\me\\proj\\.env').effect, 'block')
})

test('PolicyEngine: classification is case-insensitive', () => {
  const e = engine()
  assert.equal(e.classify('.ENV').effect, 'block')
  assert.equal(e.classify('CREDENTIALS.JSON').effect, 'block')
})

test('PolicyEngine: list() exposes allow/custom/default sources', () => {
  const e = engine({ allow: ['x'], rules: [{ id: 'r1', match: 'y', effect: 'block' }] })
  const entries = e.list()
  assert.equal(entries.filter(x => x.source === 'allow').length, 1)
  assert.equal(entries.filter(x => x.source === 'custom').length, 1)
  assert.ok(entries.filter(x => x.source === 'default').length > 10)
})
