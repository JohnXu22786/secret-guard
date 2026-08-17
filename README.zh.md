[English](README.md)

# secret-guard

面向 DeepSeek Harness（dsh）的安全插件：在 agent 的文件工具执行**之前**拦截对敏感文件的读写（`.env`、credentials、密钥文件等），防止 API 密钥等机密泄漏到对话上下文；并对工具结果做**内容掩码兜底**，即使有内容绕过了拦截也会被清洗。

- 零构建：纯 TypeScript 源码加载（dsh 用 Node 原生 strip-only 类型剥离加载 `.ts`，因此源码**不得使用**参数属性等 strip 不支持的语法——本仓库已遵守，并有 `npm run smoke:strip` 冒烟检查）；自包含，运行时依赖仅 `@deepseek-ai/dsh-tools`（工具定义）与 `schemastery`（配置校验）。
- 拦截层：`tools/pre-execute` 瀑布事件（在工具体执行前短路）。
- 兜底层：`tools/post-execute` 瀑布事件（对结果内容做形状识别掩码）。
- 配套 `sg_*` 安全检查工具：只返回键名、行号、形状、布尔值与 HMAC 指纹，**永不返回原始值**。
- 审计日志：JSONL 追加式、按大小轮转；规则文件热加载（自动轮询 + 手动 `sg_reload`）。

## 目录结构

```
secret-guard/
  package.json         # dsh.bundle.patch 声明；main 指向源码
  cordis.patch.yml     # bundle 补丁层（插件行：id / name / config）
  src/
    index.ts           # 插件入口：name / inject / Config / apply
    config.ts          # 配置 schema（schemastery）+ 校验与默认值
    policy.ts          # 规则引擎：路径归一化、glob 编译、默认规则表
    gate.ts            # tools/pre-execute 拦截监听器
    scrub.ts           # tools/post-execute 内容掩码监听器
    inspect.ts         # dotenv 解析、值形状分类、sg_* 安全工具
    fingerprint.ts     # HMAC-SHA256 封印密钥（seal key）与指纹
    journal.ts         # JSONL 审计日志 + 轮转
    watch.ts           # 规则文件热加载轮询器
  tests/               # node:test + tsx，无需编译即可运行
  README.md
  LICENSE
```

## 在 DSH 中安装

```bash
dsh plugin --profile demo add github:JohnXu22786/secret-guard
```

安装后默认配置即生效。卸载：

```bash
dsh plugin --profile demo remove dsh-secret-guard
```

## 安装与接入（dsh 如何加载它）

插件遵循 dsh 的 Cordis 插件约定：一个导出 `name` / `inject` / `Config` / `apply(ctx, config)` 的 ESM 模块（入口 `src/index.ts`），由 `cordis.patch.yml` 作为 bundle 层插入插件树。注册的副作用（事件监听、工具注册、文件轮询）都在 `apply` 返回的清理函数与 Cordis 上下文中可逆卸载。

```sh
# 从本目录安装到 web profile（等效于 pnpm 链接 + bundle 层加载）
dsh plugin --profile web add .

# 或 headless profile
dsh plugin --profile headless add .
```

安装后默认配置即生效。检查插件树：

```sh
dsh --profile web --dump-config | grep -A 6 secret-guard
```

### 本地开发（不安装）

未安装到 profile 时，patch 行里的包名无法从 profile 目录解析，需要用**绝对路径 overlay** 指向源码入口。注意 Windows 上 Node 的 ESM 不认盘符路径（`D:/…` 会被当成协议），必须加 `file:///` 前缀：

```yaml
# dev-overlay.yml
- insert:
    - id: secret-guard-dev
      name: 'file:///D:/path/to/secret-guard/src/index.ts'
      config:
        maskResults: true
```

```sh
dsh --profile headless --patch D:/path/to/secret-guard/dev-overlay.yml "请列出当前目录"
```

### 环境要求

- dsh ≥ 0.1.0-rc.6（`@deepseek-ai/dsh-tools` 类型即 0.1.0-rc.6 的接口面）
- Node.js ≥ 22.19（或 ≥ 24）
- peer 依赖：`@deepseek-ai/cordis`、`@deepseek-ai/dsh-tools`、`@deepseek-ai/dsh-llm`（仅类型）、`schemastery`（宿主 profile 需提供，`dsh plugin add` 会自动安装 peer）

### 插件接口一览

| 接口 | 说明 |
| --- | --- |
| 清单 | `package.json` 的 `dsh.bundle.patch` → `cordis.patch.yml` |
| 入口 | `src/index.ts`：`name='secret-guard'`，`inject=['tools']`，`apply(ctx, config)` |
| 拦截事件 | 消费 `tools/pre-execute`（拒绝则返回 `{kind:'deny', reason}`，短路瀑布） |
| 掩码事件 | 消费 `tools/post-execute`（返回替换内容后的 `accept` 决策） |
| 工具 | 注册 `sg_keys` / `sg_scan` / `sg_fingerprint` / `sg_probe` / `sg_status` / `sg_reload` |
| 配置 | 插件行的 `config` 字段（见下），由 schemastery `Config` 校验 |

## 配置

配置写在 `cordis.patch.yml` 的插件行 `config` 下，或通过 profile 的 `cordis.patch.yml` 补丁覆盖：

```yaml
- insert:
    - id: secret-guard
      name: 'dsh-secret-guard'
      config:
        # 自定义规则（在默认规则之前求值，先匹配者胜）
        rules:
          - id: my-prod-creds
            match: '**/prod-secrets.yml'
            effect: block            # block | block-read | block-write | allow
            reason: '生产凭据，禁止读写'
        # 放行名单（在任何规则之前检查；同样支持 glob）
        allow:
          - 'tests/fixtures/.env'
          - '**/sandbox.env'
        # 参与拦截的工具（参数含 file_path / path 的文件类工具；默认含 read_image）
        gateTools: [read, write, edit, glob, grep, read_image]
        # grep 的 pattern 命中敏感关键词（env/credential/password…）时也拦截
        guardSearchPatterns: true
        # 结果内容掩码兜底
        maskResults: true
        # 封印密钥（HMAC）：优先读环境变量，其次本地文件（自动创建，0600）
        sealKey:
          env: SECRET_GUARD_SEAL_KEY
          path: .secret-guard/seal.key
        # 审计日志
        audit:
          enabled: true
          dir: .secret-guard/logs
          maxBytes: 1048576   # 单文件超过即轮转
          keep: 5             # 保留的轮转文件数
        # 外部规则文件（JSON，可热加载）：{ "rules": [...], "allow": [...] }
        rulesFile: .secret-guard/rules.json
        watchRules: true      # 自动轮询热加载（约 400ms 周期）
```

相对路径（`sealKey.path`、`audit.dir`、`rulesFile`）均相对 dsh 的启动工作目录解析。

## 规则语法与默认规则表

规则 `match` 使用类似 .gitignore 的 glob：

- 包含 `/` 的模式锚定**完整路径**（`**/.aws/credentials` 匹配任意深度）；`**/` 前缀可匹配零层目录；
- 不含 `/` 的模式只匹配**文件名**（`.env` 匹配任意目录下的 `.env`）；
- `**` 跨目录段，`*` 单段内任意，`?` 单字符；中间的 `**/` 也匹配零层或多层目录（`foo/**/bar` 同样匹配 `foo/bar`，与 gitignore 一致）；
- 匹配不区分大小写（对拦截型规则更安全）。

求值顺序：`allow` 放行名单 → 自定义 `rules`（按声明顺序）→ 内置默认规则（首条命中即止）。放行名单与规则中的 `allow` 效果一致，但放行名单永远最先检查。

**匹配目标**：规则与放行名单都作用于**归一化路径**——正斜杠、去掉盘符与前导 `/`、折叠 `..`（`a/../b` → `b`）。因此模式请按相对形式书写（如 `tests/fixtures/.env`），不要带盘符（`C:\…`）；按绝对路径写放行名单会静默失效。

内置默认规则（id 即日志中的 `rule` 字段）：

| id | 匹配 | 效果 | 说明 |
| --- | --- | --- | --- |
| `guard-vault` | `**/.secret-guard/**` | block | 插件自身存储（封印密钥、审计日志） |
| `env-example` ~ `env-default` | `.env.example` / `.env.sample` / `.env.template` / `.env.dist` / `.env.default` | allow | 安全的示例文件 |
| `env-file` | `.env` | block | 可能含真实机密 |
| `env-variant` | `.env.*` | block | 环境特定机密文件 |
| `env-suffixed` | `*.env` | block-read | 非标准命名（如 `api.env`） |
| `aws-credentials` | `**/.aws/credentials` | block | |
| `git-credentials` | `**/.git-credentials` | block | |
| `netrc` | `**/.netrc` | block | |
| `npmrc-auth` | `**/.npmrc` | block-read | 含 registry 令牌 |
| `pypirc` | `**/.pypirc` | block-read | 含 registry 令牌 |
| `credential-files` | `*credential*` | block | 凭据存储 |
| `ssh-rsa` / `ssh-ed25519` / `ssh-ecdsa` / `ssh-dsa` | `id_rsa` 等 | block-read | SSH 私钥（写入放行，支持密钥生成流程） |
| `key-ext-*` | `*.pem` `*.key` `*.ppk` `*.p12` `*.pfx` `*.jks` `*.keystore` `*.kdbx` | block-read | 私钥/密钥库材料 |

效果语义：`block` 读与写都拦；`block-read` 只拦读取类工具（read/read_image/glob/grep），写放行；`block-write` 反之；`allow` 全放行。

## 安全检查工具（`sg_*`）

这些工具**故意**可以读取被拦截的文件——这正是它们的存在意义——但它们只返回元信息，任何输出路径都不会包含原始值。

| 工具 | 用途 | 返回 |
| --- | --- | --- |
| `sg_keys` | 列出 dotenv 文件的键 | 键名、行号、是否为空、值形状标签 |
| `sg_scan` | 值形状扫描 | 每个键的形状（empty/bool/numeric/jwt/url/hex/base64/opaque）与长度 |
| `sg_fingerprint` | 单个键的确定性指纹 | HMAC-SHA256 前 16 位十六进制（同一封印密钥下稳定） |
| `sg_probe` | 对单个键做布尔提问 | `is-set` / `is-empty` / `starts-with` / `ends-with` / `contains` / `matches`(正则，在独立 worker 线程中执行并限时，防病态正则卡死宿主) / `equals`(常数时间比较，不交换明文) 的布尔结果 |
| `sg_status` | 查看当前策略 | 规则数、放行名单、拦截工具、掩码/审计开关；`check` 参数可对任意路径做试分类 |
| `sg_reload` | 立即重读外部规则文件 | 重载结果（规则数/放行数/错误信息） |

用法示例（agent 视角）：

```
sg_status { check: ".env" }        # -> block (rule 'env-file')
sg_keys { file: ".env" }           # 只列出键名
sg_probe { file: ".env", key: "DB_PASSWORD", op: "equals", value: "候选值" }   # true/false
sg_fingerprint { file: ".env", key: "DB_PASSWORD" }   # 9f2c… 稳定指纹
```

## 内容掩码兜底（scrub）

即使拦截被绕过（例如通过 `bash` 执行 `cat .env`、MCP 工具、未列入 `gateTools` 的工具），`tools/post-execute` 仍会对结果文本做形状识别，将疑似机密替换为 `[redacted:<类型>:<长度>]`，并追加一行摘要说明清洗数量。

**能力边界（重要）**：掩码是**文本形状匹配**，不是安全边界。把内容变换后输出（`cat .env | base64`、`rev`、拆行拼接等）可以击穿全部形状规则；同理，符号链接、`..` 等路径别名属于字符串分类的已知限制（见「安全注意事项」）。它只用于拦住"模型直接把机密原样读进上下文"这一最常见路径，不能替代拦截层。

识别形状（刻意保守，避免误伤哈希、UUID、普通长字符串）：

- PEM 私钥块（`-----BEGIN … PRIVATE KEY-----`）
- JWT（`eyJ…` 三段式）
- Bearer 令牌（`Bearer <16+ 字符>`）
- 知名密钥前缀：`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`、`sk-`、`AKIA…`、`xox[baprs]-`
- 带明文的连接串（`scheme://user:pass@host`，要求存在 `:密码@`）
- `key=value` 赋值（键名含 password/passwd/secret/token/api_key/access_key/client_secret/private_key/auth_key，值 ≥ 12 字符且不是 `<占位符>`/`xxx`/`example` 等文档占位）

**刻意不掩码**：裸 base64/十六进制长串（git 提交哈希、UUID 等误伤率高）；仅当它们出现在上述上下文中才处理。

## 审计日志

所有拦截（block）、掩码（mask）、规则重载（reload）、错误（error）都会写入 `audit.dir/events.jsonl`（JSONL，追加式），超过 `maxBytes` 自动轮转为 `events.1.jsonl`、`events.2.jsonl`…，最多保留 `keep` 份。

**日志契约：永不记录值**——条目只含时间戳、事件类型、工具名、路径、规则 id、效果、形状计数、消息。日志路径本身也在默认规则 `guard-vault` 的保护范围内。

## 规则热加载

配置 `rulesFile` 指向一个 JSON 文件（`{ "rules": [...], "allow": [...] }`，结构与配置中的同名字段一致）：

- `watchRules: true` 时每 400ms 轮询一次，文件变化（mtime/大小）后去抖 300ms 自动重载；
- 或随时调用 `sg_reload` 立即重载；
- 重载成功/失败都会写审计日志并在控制台提示；失败的加载**不会**破坏当前生效的规则（保留旧引擎）。

实现说明：轮询而非 `fs.watch`，是因为 Windows 上删除被监视目录会泄漏事件循环的退出资格（平台缺陷），且规则文件常被编辑器以重命名方式替换；轮询跨平台行为一致且无泄漏（定时器已 unref）。

## 安全注意事项

- 封印密钥（seal key）是 HMAC 指纹的根密钥：**不要提交** `.secret-guard/seal.key`，建议加入 `.gitignore`；换机或重置后指纹会变化（属预期行为）。
- **默认把 `sealKey.path` / `audit.dir` 留在 `.secret-guard/` 下**（内置规则 `guard-vault` 会保护它们）。若改到别处，请自行配置等价拦截规则，否则 agent 可能读到密钥文件或审计日志。
- 默认规则刻意偏保守（宁可误拦），误拦时用 `allow` 放行名单精确放行，或 `sg_status {check: …}` 先验证分类结果。
- 本插件不迁移、不加密、不移动任何机密文件；它只阻止"把机密读进模型上下文"这一件事。
- **已知限制（设计取舍）**：路径分类是纯字符串匹配，不解析符号链接目标，`..` 折叠只覆盖字符串层；通过 `bash` 等执行类工具读取敏感文件不受拦截层约束（掩码兜底尽力清洗输出）。`sg_probe` 的布尔提问是"值预言机"——理论上可用多轮 `contains`/`equals` 查询重构出值，它是为方便 agent 安全核对而设计，不应用于不可信上下文。

## 开发与测试

```sh
npm install        # 仅 devDependencies（tsx / typescript / cordis 运行时 / schemastery）
npm test           # node --import tsx --test tests/*.test.ts（74 个用例，约 5 秒）+ strip-only 加载冒烟
npm run typecheck  # tsc --noEmit
```

测试覆盖：规则引擎（归一化/glob/默认表/放行名单/自定义规则优先级）、dotenv 解析、指纹与封印密钥、掩码模式与误伤控制、拦截决策矩阵（含搜索工具与关键词守卫）、审计轮转、以及用真实 Cordis 上下文驱动瀑布事件的集成测试（含热加载端到端）。

## 许可

本项目以 [MIT](LICENSE) 许可协议发布。
