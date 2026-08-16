/**
 * Path classification: rule types, the default rule table, and the matching
 * engine used by the gate and by `sg_status`.
 *
 * Rule patterns are gitignore-style globs:
 * - a pattern containing `/` is anchored to the normalized full path;
 * - a pattern without `/` matches the file's basename at any depth;
 * - `**` crosses path segments, `*` matches within one segment, `?` matches
 *   one character;
 * - matching is case-insensitive (safer for blocklists on every platform).
 */

export type RuleEffect = 'allow' | 'block-read' | 'block-write' | 'block'

export interface Rule {
  id: string
  match: string
  effect: RuleEffect
  reason?: string
}

export interface Classification {
  effect: RuleEffect
  rule?: Rule
}

export type RuleSource = 'allow' | 'custom' | 'default'

export interface ListedRule {
  source: RuleSource
  rule: Rule
}

/**
 * Collapse a raw tool-supplied path into one canonical, matchable form:
 * forward slashes, no `file://` prefix, no drive letter, no leading slashes,
 * no `.` segments, and interior `..` segments folded (`a/../b` -> `b`).
 * The result is what rules and allow entries are matched against; patterns
 * should therefore be written without drive letters and with `/` separators.
 */
export function normalizePath(raw: string): string {
  let p = raw.trim()
  if (p === '') return ''
  if (p.startsWith('file://')) p = p.slice('file://'.length)
  p = p.replaceAll('\\', '/')
  p = p.replace(/^\/+/, '')
  p = p.replace(/^[A-Za-z]:/, '')
  const out: string[] = []
  for (const segment of p.split('/')) {
    if (segment === '' || segment === '.') continue
    if (segment === '..') {
      if (out.length > 0) out.pop()
      continue
    }
    out.push(segment)
  }
  return out.join('/')
}

/** Compile a gitignore-style glob into an anchored, case-insensitive RegExp. */
export function compileGlob(pattern: string): RegExp {
  const fullPath = pattern.includes('/')
  let src = pattern
  let prefix = ''
  // A leading `**/` matches zero or more leading directories (gitignore
  // semantics). A MID-pattern `**` requires at least one segment boundary,
  // i.e. `foo/**/bar` does not match `foo/bar` — the default rule table only
  // uses leading `**/`, so this distinction is documented, not relied on.
  if (fullPath && src.startsWith('**/')) {
    prefix = '(?:.*/)?'
    src = src.slice(3)
  }
  let out = ''
  for (let i = 0; i < src.length; i++) {
    const ch = src[i]!
    if (ch === '*') {
      if (src[i + 1] === '*') {
        out += '.*'
        i++
      } else {
        out += '[^/]*'
      }
    } else if (ch === '?') {
      out += '[^/]'
    } else {
      out += /[|\\{}()[\]^$+.]/.test(ch) ? `\\${ch}` : ch
    }
  }
  return new RegExp(`^${prefix}${out}$`, 'i')
}

/**
 * The built-in sensitive-surface table. Evaluated in order after the user's
 * allow list and custom rules; the first matching entry decides.
 */
export function defaultRules(): Rule[] {
  return [
    { id: 'guard-vault', match: '**/.secret-guard/**', effect: 'block', reason: 'plugin storage: seal key and audit journal' },
    { id: 'env-example', match: '.env.example', effect: 'allow', reason: 'safe example file' },
    { id: 'env-sample', match: '.env.sample', effect: 'allow', reason: 'safe example file' },
    { id: 'env-template', match: '.env.template', effect: 'allow', reason: 'safe example file' },
    { id: 'env-dist', match: '.env.dist', effect: 'allow', reason: 'safe example file' },
    { id: 'env-default', match: '.env.default', effect: 'allow', reason: 'safe example file' },
    { id: 'env-file', match: '.env', effect: 'block', reason: 'may hold live secrets' },
    { id: 'env-variant', match: '.env.*', effect: 'block', reason: 'environment-specific secret files' },
    { id: 'env-suffixed', match: '*.env', effect: 'block-read', reason: 'non-standard env files (e.g. api.env)' },
    { id: 'aws-credentials', match: '**/.aws/credentials', effect: 'block' },
    { id: 'git-credentials', match: '**/.git-credentials', effect: 'block' },
    { id: 'netrc', match: '**/.netrc', effect: 'block' },
    { id: 'npmrc-auth', match: '**/.npmrc', effect: 'block-read', reason: 'registry auth tokens' },
    { id: 'pypirc', match: '**/.pypirc', effect: 'block-read', reason: 'registry auth tokens' },
    { id: 'credential-files', match: '*credential*', effect: 'block', reason: 'credential stores' },
    { id: 'ssh-rsa', match: 'id_rsa', effect: 'block-read', reason: 'SSH private key' },
    { id: 'ssh-ed25519', match: 'id_ed25519', effect: 'block-read', reason: 'SSH private key' },
    { id: 'ssh-ecdsa', match: 'id_ecdsa', effect: 'block-read', reason: 'SSH private key' },
    { id: 'ssh-dsa', match: 'id_dsa', effect: 'block-read', reason: 'SSH private key' },
    { id: 'key-ext-pem', match: '*.pem', effect: 'block-read', reason: 'key or certificate material' },
    { id: 'key-ext-key', match: '*.key', effect: 'block-read', reason: 'private key material' },
    { id: 'key-ext-ppk', match: '*.ppk', effect: 'block-read', reason: 'private key material' },
    { id: 'key-ext-p12', match: '*.p12', effect: 'block-read', reason: 'key store' },
    { id: 'key-ext-pfx', match: '*.pfx', effect: 'block-read', reason: 'key store' },
    { id: 'key-ext-jks', match: '*.jks', effect: 'block-read', reason: 'key store' },
    { id: 'key-ext-keystore', match: '*.keystore', effect: 'block-read', reason: 'key store' },
    { id: 'key-ext-kdbx', match: '*.kdbx', effect: 'block-read', reason: 'password database' },
  ]
}

interface CompiledEntry {
  source: RuleSource
  rule: Rule
  fullPath: boolean
  re: RegExp
}

/** Immutable rule set with precompiled matchers; swap the whole engine to reload. */
export class PolicyEngine {
  private readonly compiled: CompiledEntry[]

  constructor(allow: string[], custom: Rule[], defaults: Rule[]) {
    const allowRules: Rule[] = allow.map(pattern => ({
      id: `allow:${pattern}`,
      match: pattern,
      effect: 'allow',
      reason: 'explicit allow-list entry',
    }))
    this.compiled = [
      ...allowRules.map<CompiledEntry>(rule => ({ source: 'allow', rule, fullPath: rule.match.includes('/'), re: compileGlob(rule.match) })),
      ...custom.map<CompiledEntry>(rule => ({ source: 'custom', rule, fullPath: rule.match.includes('/'), re: compileGlob(rule.match) })),
      ...defaults.map<CompiledEntry>(rule => ({ source: 'default', rule, fullPath: rule.match.includes('/'), re: compileGlob(rule.match) })),
    ]
  }

  classify(path: string): Classification {
    const normalized = normalizePath(path)
    if (normalized === '') return { effect: 'allow' }
    const base = normalized.slice(normalized.lastIndexOf('/') + 1)
    for (const entry of this.compiled) {
      const target = entry.fullPath ? normalized : base
      if (entry.re.test(target)) return { effect: entry.rule.effect, rule: entry.rule }
    }
    return { effect: 'allow' }
  }

  /** Every rule in evaluation order, with its origin — for `sg_status`. */
  list(): ListedRule[] {
    return this.compiled.map(({ source, rule }) => ({ source, rule }))
  }
}
