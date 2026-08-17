[简体中文](README.zh.md)

# secret-guard

A security plugin for the DeepSeek Harness (dsh): it intercepts reads and writes of sensitive files (`.env`, credentials, key material, etc.) by the agent's file tools **before** they execute, preventing API keys and other secrets from leaking into the conversation context; it also applies a **content-masking fallback** on tool results so that even content that slips past the interception gets scrubbed.

- Zero build: loads as pure TypeScript source (dsh loads `.ts` via Node's native strip-only type stripping, so the source **must not** use syntax unsupported by strip, such as parameter properties — this repo complies and ships an `npm run smoke:strip` smoke check); self-contained, with only `@deepseek-ai/dsh-tools` (tool definitions) and `schemastery` (config validation) as runtime dependencies.
- Interception layer: `tools/pre-execute` waterfall event (short-circuits before the tool body runs).
- Fallback layer: `tools/post-execute` waterfall event (shape-recognition masking of result content).
- Companion `sg_*` safety inspection tools: they only return key names, line numbers, shapes, booleans, and HMAC fingerprints — **they never return raw values**.
- Audit journal: JSONL append-only, rotated by size; rule files hot-reload (automatic polling + manual `sg_reload`).

## Directory Structure

```
secret-guard/
  package.json         # dsh.bundle.patch declaration; main points at the source
  cordis.patch.yml     # bundle patch layer (plugin line: id / name / config)
  src/
    index.ts           # plugin entry: name / inject / Config / apply
    config.ts          # config schema (schemastery) + validation and defaults
    policy.ts          # rule engine: path normalization, glob compilation, default rule table
    gate.ts            # tools/pre-execute interception listener
    scrub.ts           # tools/post-execute content-masking listener
    inspect.ts         # dotenv parsing, value shape classification, sg_* safety tools
    fingerprint.ts     # HMAC-SHA256 seal key and fingerprints
    journal.ts         # JSONL audit journal + rotation
    watch.ts           # rule-file hot-reload poller
  tests/               # node:test + tsx, runs without compilation
  README.md
  LICENSE
```

## Installing in DSH

```bash
dsh plugin --profile demo add github:JohnXu22786/secret-guard
```

The default configuration takes effect after installation. To remove:

```bash
dsh plugin --profile demo remove dsh-secret-guard
```

## Installation and Integration (how dsh loads it)

The plugin follows dsh's Cordis plugin conventions: an ESM module (entry `src/index.ts`) exporting `name` / `inject` / `Config` / `apply(ctx, config)`, inserted into the plugin tree by `cordis.patch.yml` as a bundle layer. All registered side effects (event listeners, tool registration, file polling) are reversibly cleaned up by the function returned from `apply` and by the Cordis context.

```sh
# install from this directory into the web profile (equivalent to pnpm link + bundle-layer load)
dsh plugin --profile web add .

# or the headless profile
dsh plugin --profile headless add .
```

The default configuration is active right after installation. Inspect the plugin tree:

```sh
dsh --profile web --dump-config | grep -A 6 secret-guard
```

### Local Development (without installing)

When the plugin is not installed in a profile, the package name in the patch line cannot be resolved from the profile directory, so you need an **absolute-path overlay** pointing at the source entry. Note that on Windows, Node's ESM does not recognize drive-letter paths (`D:/…` is treated as a protocol) and requires a `file:///` prefix:

```yaml
# dev-overlay.yml
- insert:
    - id: secret-guard-dev
      name: 'file:///D:/path/to/secret-guard/src/index.ts'
      config:
        maskResults: true
```

```sh
dsh --profile headless --patch D:/path/to/secret-guard/dev-overlay.yml "list the current directory"
```

### Requirements

- dsh ≥ 0.1.0-rc.6 (the `@deepseek-ai/dsh-tools` typings match the 0.1.0-rc.6 interface surface)
- Node.js ≥ 22.19 (or ≥ 24)
- peer dependencies: `@deepseek-ai/cordis`, `@deepseek-ai/dsh-tools`, `@deepseek-ai/dsh-llm` (types only), `schemastery` (must be provided by the host profile; `dsh plugin add` installs peers automatically)

### Plugin Interface at a Glance

| Interface | Description |
| --- | --- |
| Manifest | `dsh.bundle.patch` in `package.json` → `cordis.patch.yml` |
| Entry | `src/index.ts`: `name='secret-guard'`, `inject=['tools']`, `apply(ctx, config)` |
| Interception event | consumes `tools/pre-execute` (returns `{kind:'deny', reason}` on refusal, short-circuiting the waterfall) |
| Masking event | consumes `tools/post-execute` (returns an `accept` decision with the replacement content) |
| Tools | registers `sg_keys` / `sg_scan` / `sg_fingerprint` / `sg_probe` / `sg_status` / `sg_reload` |
| Config | the `config` field of the plugin line (see below), validated by the schemastery `Config` |

## Configuration

Configuration lives under the `config` key of the plugin line in `cordis.patch.yml`, or can be overridden via the profile's `cordis.patch.yml` patch:

```yaml
- insert:
    - id: secret-guard
      name: 'dsh-secret-guard'
      config:
        # custom rules (evaluated before the default rules; first match wins)
        rules:
          - id: my-prod-creds
            match: '**/prod-secrets.yml'
            effect: block            # block | block-read | block-write | allow
            reason: 'production credentials, no access'
        # allowlist (checked before any rules; also supports globs)
        allow:
          - 'tests/fixtures/.env'
          - '**/sandbox.env'
        # tools participating in interception (file-type tools whose args contain file_path / path; includes read_image by default)
        gateTools: [read, write, edit, glob, grep, read_image]
        # also intercept grep whose pattern hits sensitive keywords (env/credential/password…)
        guardSearchPatterns: true
        # content-masking fallback for results
        maskResults: true
        # seal key (HMAC): environment variable first, then a local file (auto-created, 0600)
        sealKey:
          env: SECRET_GUARD_SEAL_KEY
          path: .secret-guard/seal.key
        # audit journal
        audit:
          enabled: true
          dir: .secret-guard/logs
          maxBytes: 1048576   # rotate when a single file exceeds this
          keep: 5             # number of rotation files to keep
        # external rule file (JSON, hot-reloadable): { "rules": [...], "allow": [...] }
        rulesFile: .secret-guard/rules.json
        watchRules: true      # automatic polling hot-reload (~400ms interval)
```

Relative paths (`sealKey.path`, `audit.dir`, `rulesFile`) resolve against dsh's startup working directory.

## Rule Syntax and the Default Rule Table

Rule `match` uses a .gitignore-like glob:

- Patterns containing `/` anchor the **full path** (`**/.aws/credentials` matches at any depth); a `**/` prefix can match zero directory levels;
- Patterns without `/` only match the **file name** (`.env` matches `.env` in any directory);
- `**` spans directory segments, `*` matches anything within a segment, `?` matches a single character; a mid-pattern `**/` also matches zero directory levels (`foo/**/bar` matches `foo/bar`, gitignore semantics);
- Matching is case-insensitive (safer for interception rules).

Evaluation order: `allow` allowlist → custom `rules` (in declaration order) → built-in default rules (first match stops). The allowlist behaves like `allow` in rules, but is always checked first.

**Match target**: both rules and the allowlist operate on **normalized paths** — forward slashes, drive letter and leading `/` stripped, `..` collapsed (`a/../b` → `b`). So write patterns in relative form (e.g., `tests/fixtures/.env`), without drive letters (`C:\…`); allowlist entries written as absolute paths will silently fail.

Built-in default rules (the id is the `rule` field in the journal):

| id | Matches | Effect | Description |
| --- | --- | --- | --- |
| `guard-vault` | `**/.secret-guard/**` | block | The plugin's own storage (seal key, audit journal) |
| `env-example` ~ `env-default` | `.env.example` / `.env.sample` / `.env.template` / `.env.dist` / `.env.default` | allow | Safe example files |
| `env-file` | `.env` | block | May contain real secrets |
| `env-variant` | `.env.*` | block | Environment-specific secret files |
| `env-suffixed` | `*.env` | block-read | Non-standard naming (e.g., `api.env`) |
| `aws-credentials` | `**/.aws/credentials` | block | |
| `git-credentials` | `**/.git-credentials` | block | |
| `netrc` | `**/.netrc` | block | |
| `npmrc-auth` | `**/.npmrc` | block-read | Contains registry tokens |
| `pypirc` | `**/.pypirc` | block-read | Contains registry tokens |
| `credential-files` | `*credential*` | block | Credential stores |
| `ssh-rsa` / `ssh-ed25519` / `ssh-ecdsa` / `ssh-dsa` | `id_rsa` etc. | block-read | SSH private keys (writes allowed, supporting key-generation flows) |
| `key-ext-*` | `*.pem` `*.key` `*.ppk` `*.p12` `*.pfx` `*.jks` `*.keystore` `*.kdbx` | block-read | Private key / keystore material |

Effect semantics: `block` intercepts both reads and writes; `block-read` only intercepts read-type tools (read/read_image/glob/grep), writes pass; `block-write` is the opposite; `allow` passes everything.

## Safety Inspection Tools (`sg_*`)

These tools are **intentionally** allowed to read blocked files — that is their whole purpose — but they only return metadata, and no output path ever contains raw values.

| Tool | Purpose | Returns |
| --- | --- | --- |
| `sg_keys` | List the keys of a dotenv file | key names, line numbers, empty-or-not, value shape labels |
| `sg_scan` | Value-shape scan | each key's shape (empty/bool/numeric/jwt/url/hex/base64/opaque) and length |
| `sg_fingerprint` | Deterministic fingerprint of a single key | first 16 hex chars of HMAC-SHA256 (stable under the same seal key) |
| `sg_probe` | Boolean questions about a single key | boolean results of `is-set` / `is-empty` / `starts-with` / `ends-with` / `contains` / `matches` (regex, executed in a separate worker thread with a timeout so pathological regexes cannot hang the host) / `equals` (constant-time comparison, no plaintext exchange) |
| `sg_status` | View the current policy | rule count, allowlist, gated tools, mask/audit toggles; the `check` parameter trial-classifies any path |
| `sg_reload` | Immediately re-read the external rule file | reload result (rule count / allowlist count / error message) |

Usage examples (agent's perspective):

```
sg_status { check: ".env" }        # -> block (rule 'env-file')
sg_keys { file: ".env" }           # lists only key names
sg_probe { file: ".env", key: "DB_PASSWORD", op: "equals", value: "candidate" }   # true/false
sg_fingerprint { file: ".env", key: "DB_PASSWORD" }   # 9f2c… stable fingerprint
```

## Content-Masking Fallback (scrub)

Even if interception is bypassed (e.g., `cat .env` via a `bash`-type tool, MCP tools, or tools not listed in `gateTools`), `tools/post-execute` still runs shape recognition on result text, replacing suspected secrets with `[redacted:<type>:<length>]`, and appends a summary line stating how much was scrubbed.

**Capability boundary (important)**: masking is **text-shape matching**, not a security boundary. Transforming content before output (`cat .env | base64`, `rev`, splitting and rejoining lines, etc.) defeats all shape rules; likewise, symlinks and path aliases like `..` are known limitations of string classification (see "Security Notes"). It only stops the most common path — the model reading secrets verbatim into context — and is not a substitute for the interception layer.

Recognized shapes (deliberately conservative, to avoid harming hashes, UUIDs, and ordinary long strings):

- PEM private key blocks (`-----BEGIN … PRIVATE KEY-----`)
- JWTs (`eyJ…` three segments)
- Bearer tokens (`Bearer <16+ chars>`)
- Known key prefixes: `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`, `sk-`, `AKIA…`, `xox[baprs]-`
- Connection strings with plaintext (`scheme://user:pass@host`, requires a `:password@`)
- `key=value` assignments (key name containing password/passwd/secret/token/api_key/access_key/client_secret/private_key/auth_key, value ≥ 12 chars and not a doc placeholder like `<placeholder>`/`xxx`/`example`)

**Deliberately not masked**: bare base64/hex long strings (git commit hashes, UUIDs, etc. have high false-positive rates); they are only handled when they appear in the contexts above.

## Audit Journal

Every interception (block), masking (mask), rule reload (reload), and error (error) is written to `audit.dir/events.jsonl` (JSONL, append-only). When a file exceeds `maxBytes` it is automatically rotated to `events.1.jsonl`, `events.2.jsonl`, …, keeping at most `keep` files.

**Journal contract: values are never recorded** — entries only contain timestamp, event type, tool name, path, rule id, effect, shape counts, and message. The journal path itself is covered by the default rule `guard-vault`.

## Rule Hot-Reload

Point `rulesFile` at a JSON file (`{ "rules": [...], "allow": [...] }`, same structure as the identically named config fields):

- With `watchRules: true`, it polls every 400ms and, after a 300ms debounce on file change (mtime/size), auto-reloads;
- Or call `sg_reload` at any time to reload immediately;
- Successful and failed reloads are both written to the audit journal and shown on the console; a failed load **never** destroys the currently active rules (the old engine is kept).

Implementation note: polling is used instead of `fs.watch` because on Windows, deleting a watched directory leaks the event loop's exit eligibility (a platform defect), and rule files are often replaced by editors via rename; polling behaves consistently across platforms and leaks nothing (timers are unref'd).

## Security Notes

- The seal key is the root key for HMAC fingerprints: **never commit** `.secret-guard/seal.key` — add it to `.gitignore`; fingerprints change after moving machines or resetting the key (expected behavior).
- **Keep `sealKey.path` / `audit.dir` under `.secret-guard/` by default** (the built-in `guard-vault` rule protects them). If you move them elsewhere, configure equivalent interception rules yourself, or the agent may read the key file or audit journal.
- The default rules are deliberately conservative (prefer over-blocking); when over-blocked, use the `allow` allowlist for precise exemptions, or verify classification first with `sg_status {check: …}`.
- This plugin does not migrate, encrypt, or move any secret files; it only prevents "reading secrets into the model context".
- **Known limitations (design trade-offs)**: path classification is pure string matching — it does not resolve symlink targets, and `..` collapsing only covers the string layer; reading sensitive files through execution-type tools like `bash` is not constrained by the interception layer (the masking fallback does its best to scrub output). `sg_probe`'s boolean questions are a "value oracle" — in theory, multi-round `contains`/`equals` queries could reconstruct a value; it is designed for agents to verify values safely and should not be used in untrusted contexts.

## Development and Testing

```sh
npm install        # devDependencies only (tsx / typescript / cordis runtime / schemastery)
npm test           # node --import tsx --test tests/*.test.ts (77 test cases, ~5s) + strip-only load smoke test
npm run typecheck  # tsc --noEmit
```

Test coverage: rule engine (normalization/glob/default table/allowlist/custom rule precedence), dotenv parsing, fingerprints and seal keys, masking patterns and false-positive control, the interception decision matrix (including search tools and the keyword guard), audit rotation, and integration tests driving the waterfall events with a real Cordis context (including end-to-end hot reload).

## License

This project is released under the [MIT](LICENSE) License.
