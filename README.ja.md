# AgentScope

[English](README.md) | 日本語

AIコーディングエージェント（Claude Code / Cursor）の **権限設定を静的に分析し、セキュリティ上のリスクを可視化する** CLI ツールです。

設定ファイルを読むだけで、エージェントや MCP サーバーの起動、設定されたコマンドの実行、外部への送信は行いません。

- 許可・禁止・承認が必要な操作の一覧
- 接続されている MCP サーバーの一覧（名前・接続方式・起動コマンド名・接続先ホスト・環境変数名）
- 権限設定に潜むリスク（ルールベースで5種類）
- 解析できなかった項目の明示

> v0.1 は MVP です。設定に**書かれている**権限を示すもので、実際に**行使できる**権限を保証するものではありません（[制約](#制約)を参照）。

## 動作環境

- Node.js 22.12 以上
- macOS / Linux / Windows

## インストール

npm には未公開です。ソースからビルドして使います。

```bash
git clone https://github.com/yotatameguchi-boop/agentscope.git
cd agentscope
npm install
npm run build
npm link   # agentscope コマンドとして使えるようにする（任意）
```

`npm link` をしない場合は `node dist/cli.js` で実行できます。

## 使い方

```bash
agentscope scan                    # カレントディレクトリの設定を分析
agentscope scan path/to/project    # ディレクトリを指定
agentscope scan --agent claude     # Claude Code の設定だけ
agentscope scan --agent cursor     # Cursor の設定だけ
agentscope scan --format json      # JSON で出力
agentscope scan --include-global   # ユーザー単位の設定も分析
agentscope scan --launch "claude -p --dangerously-skip-permissions"   # 起動コマンドも分析（実行はしない）
agentscope scan --include-env      # 実行中のシェルの環境変数も分析
agentscope --help
```

| オプション | 説明 | 既定値 |
| --- | --- | --- |
| `-a, --agent <claude\|cursor\|all>` | 対象エージェント | `all` |
| `-f, --format <text\|json>` | 出力形式 | `text` |
| `-g, --include-global` | ホームディレクトリのユーザー設定も読む | 読まない |
| `--no-color` | 色を付けない（`NO_COLOR` 環境変数でも無効化） | TTY のとき色付き |
| `--lang <ja\|en>` | 表示言語（レポート・JSON・ヘルプ） | 環境から判定 |
| `--launch <command>` | 起動時のオプションを分析する起動コマンド。文字列として解析し、実行はしない。複数指定可 | なし |
| `--no-launch-files` | プロジェクト内のファイルから起動コマンド・環境変数を探さない（[起動時のオプション](#起動時のオプション)を参照） | 探す |
| `-e, --include-env` | 実行中のシェルの環境変数も分析する（[環境変数](#環境変数)を参照） | 読まない |

表示言語は `--lang` を最優先し、次に環境変数 `AGENTSCOPE_LANG`、`LC_ALL` / `LC_MESSAGES` / `LANG` の順で判定します。日本語のロケールなら日本語、それ以外は英語です。

終了コードは、分析できたとき（検出の有無によらない。`--help` / `--version` も含む）`0`、不正なオプション・対象ディレクトリが見つからない・ディレクトリではないなどのエラー時に `2` です。

### 出力例

`test/fixtures/risky-project`（テスト用のダミー設定）を分析した結果の抜粋です。

```text
AgentScope Security Report (v0.1.0)
対象エージェント: Claude Code, Cursor
設定ファイル: 6  権限ルール: 29  MCPサーバー: 4  起動コマンド: 0  検出: HIGH 6 / MEDIUM 13 / LOW 0 / INFO 5

■ 検出されたリスク
  [HIGH] R001 広範囲のコマンド実行を自動承認する設定  (Claude Code)
      理由: 「python3」は引数次第で任意のコードを実行できるため、実質的に広範囲のコマンド実行を許可しています
      場所: .claude/settings.json  permissions.allow[1]
      該当: Bash(python3 *)
      対応: 「Bash(npm run test *)」のようにサブコマンドまで含めた具体的なルールに置き換え、破壊的な操作は ask か deny に入れてください。
  [MEDIUM] R004 設定ファイルに認証情報らしき文字列が直接書かれている  (Claude Code)
      理由: 「MY_SERVICE_PASSWORD」に、参照（${VAR} など）ではない値が直接書かれており、認証情報の可能性があります（値は表示しません）。
      場所: .claude/settings.local.json  env.MY_SERVICE_PASSWORD
      該当: env.MY_SERVICE_PASSWORD: [REDACTED]
  [INFO] I001 MCP サーバーの実際のツール一覧は未検証  (Claude Code)
  ...
```

## 分析対象

存在しないファイルはエラーにせずスキップします。ディレクトリの再帰走査はせず、下表の場所だけを見ます。

| エージェント | ファイル | 範囲 | 既定 | 内容 |
| --- | --- | --- | --- | --- |
| Claude Code | `.claude/settings.json` | プロジェクト共有 | ○ | 権限ルール、権限モード、MCP 承認、サンドボックスなど |
| Claude Code | `.claude/settings.local.json` | プロジェクト個人 | ○ | 同上 |
| Claude Code | `.mcp.json` | プロジェクト共有 | ○ | MCP サーバー定義 |
| Claude Code | `~/.claude/settings.json` | ユーザー全体 | `-g` | 権限ルールなど |
| Claude Code | `~/.claude.json` | ユーザー全体 / プロジェクト個人 | `-g` | **MCP に関わる部分のみ**（トップレベルの `mcpServers` と、対象ディレクトリの `projects[...]` の `mcpServers` / `enabledMcpjsonServers` / `disabledMcpjsonServers`）。他のキーは読み飛ばし、列挙もしません |
| Cursor | `.cursor/mcp.json` | プロジェクト共有 | ○ | MCP サーバー定義 |
| Cursor | `.cursor/permissions.json` | プロジェクト共有 | ○ | `mcpAllowlist` / `terminalAllowlist` / `autoRun` |
| Cursor | `~/.cursor/mcp.json` | ユーザー全体 | `-g` | MCP サーバー定義 |
| Cursor | `~/.cursor/permissions.json` | ユーザー全体 | `-g` | 同上 |
| Cursor | `.cursor/cli.json` | プロジェクト共有 | ○ | Cursor CLI の `permissions.allow` / `deny`（`Shell` / `Read` / `Write` / `WebFetch` / `Mcp`） |
| Cursor | `~/.cursor/cli-config.json` | ユーザー全体 | `-g` | 同上（CLI の他の設定は読み飛ばす） |
| Claude Code | `~/.claude/remote-settings.json`（サーバー配信の管理設定のローカルキャッシュ）、macOS の構成プロファイル `/Library/Managed Preferences/[<ユーザー>/]com.anthropic.claudecode.plist`（XML・バイナリとも、`plutil` を使わずに読む） | 組織の管理設定 | `-g` | [組織の管理設定](#組織の管理設定)を参照 |
| Claude Code | `managed-settings.json`、`managed-settings.d/*.json`、`managed-mcp.json` | 組織の管理設定 | `-g` | `/Library/Application Support/ClaudeCode/`（macOS）、`/etc/claude-code/`（Linux / WSL）、`C:\Program Files\ClaudeCode\`（Windows）。最優先。Claude Code と同じく `managed-settings.json` を先に、続いて `managed-settings.d/*.json` を名前順に合成します（隠しファイルは除外）。単一値は後のファイルが勝ち、リストは結合し、`env` / `sandbox` はキーごとに合成します |

JSON と JSONC（コメント・末尾カンマ）の両方を読めます。

### 起動時のオプション

`claude --dangerously-skip-permissions` や `agent --force` のような起動オプションは、その起動に限って権限を変えます。AgentScope は起動コマンドを文字列として読み（実行はしません）、次の場所から探します。

| 場所 | 対象になる条件 |
| --- | --- |
| `--launch "<コマンド>"` | 常に |
| `package.json` の `scripts` | 既定（`--no-launch-files` で無効） |
| `.vscode/tasks.json`、`.devcontainer/devcontainer.json` / `.devcontainer.json` のライフサイクルコマンド | 既定 |
| `Makefile`、`justfile` | 既定 |
| `.github/workflows/*.yml` の `run:` 行と、`anthropics/claude-code-action` の `claude_args:` 入力 | 既定 |
| `~/.zshrc`、`~/.bashrc`、`~/.bash_profile`、`~/.profile`、`~/.zprofile`、`~/.config/fish/config.fish`（alias とコマンド） | `-g` 指定時 |

オプションの解析は `--` で止め、それ以降は位置引数として扱います。認識する起動は `claude`、`npx @anthropic-ai/claude-code`、`agent`、`cursor-agent` です。`env`・`exec`・`timeout` や、先頭の `VAR=値` の代入を挟んでいても認識します。

| エージェント | 解析するオプション |
| --- | --- |
| Claude Code | `--permission-mode`、`--dangerously-skip-permissions`、`--allow-dangerously-skip-permissions`、`--allowedTools`、`--disallowedTools`、`--add-dir`、`--settings`（インライン JSON か対象ディレクトリ内のファイル）、`--mcp-config`（同）、`--tools`、`--setting-sources`、`--strict-mcp-config`、`--bare`、`--safe-mode`、`--restricted` |
| Cursor（`agent`） | `--force` / `--yolo`、`--approve-mcps`、`--sandbox`、`--trust`、`--api-key`（値は表示しない） |

起動オプションは `cli` という独立したスコープとして扱います。

- その起動に限って効くため、設定ファイルの値を上書きしたとは扱いません
- 設定ファイルの deny / ask は `--allowedTools` も打ち消します。`--disallowedTools` が打ち消すのは同じ起動のルールだけです
- 設定ファイルの `disableBypassPermissionsMode: "disable"` や、同じ起動の `--restricted` があれば、`--dangerously-skip-permissions` は効かないと判定します
- 起動コマンド中の秘密情報（`ANTHROPIC_API_KEY=...`、`--api-key ...`）は R004 で検出し、値は表示しません

### 環境変数

環境変数には、安全チェックを止めたり、データの送信先を変えたりするものがあります。AgentScope は [src/env/catalog.ts](src/env/catalog.ts) にある変数だけを見て、それ以外は読み捨てます。

| 場所 | 対象になる条件 |
| --- | --- |
| Claude Code の設定ファイルの `env` ブロック | 常に |
| 起動コマンドの前の `VAR=値` | 常に |
| `.devcontainer` の `containerEnv` / `remoteEnv`、`.github/workflows/*.yml` の `env:` | 既定（`--no-launch-files` で無効） |
| シェルの設定ファイル（`~/.zshrc` など）の `export` / `set -x` | `-g` 指定時 |
| AgentScope を実行しているシェルの環境変数 | `-e` / `--include-env` 指定時 |

| 変数 | 検査内容 |
| --- | --- |
| `NODE_TLS_REJECT_UNAUTHORIZED=0` | TLS 証明書の検証の無効化（HIGH） |
| `CLAUDE_CODE_DISABLE_INLINE_SHELL_RM_PROMPT`、`CLAUDE_CODE_DISABLE_SUBSTITUTION_RM_PROMPT`、`CLAUDE_CODE_DISABLE_POWERSHELL_CMD_RM_DENY`、`CLAUDE_CODE_DISABLE_DANGEROUS_RM_TIMEOUT` | 削除の安全チェックの無効化（MEDIUM / LOW） |
| `--require` / `--import` を含む `NODE_OPTIONS` | Node.js で動くすべてのプロセスへのコード読み込み（MEDIUM） |
| `ANTHROPIC_BASE_URL` などの `*_BASE_URL` | 共有ファイルでの接続先変更、または http（MEDIUM）。それ以外は INFO。公式の `https://api.anthropic.com` は報告しない |
| `CLAUDE_CONFIG_DIR`、`NODE_EXTRA_CA_CERTS` | INFO |
| `ANTHROPIC_API_KEY`、`ANTHROPIC_AUTH_TOKEN`、`CURSOR_API_KEY` などの資格情報 | 設定されているかどうかだけ。ファイルに値が直接書かれていれば R004 |

- 資格情報の値は表示せず、URL はスキームとホスト名だけを保持します
- 公式ドキュメントに従い、設定ファイルの `env` では無視される変数（`CLAUDE_CODE_DISABLE_INLINE_SHELL_RM_PROMPT` など）や、project / local 設定では無視される変数（`CLAUDE_CONFIG_DIR` など）は `ignored` と判定します
- 設定ファイル間では、`env` のキーごとに通常の優先順位（managed > local > project > user）で解決します。シェルの値は、設定ファイルの値が勝つかがセッションによって異なるため、上書きされたとは扱いません
- 実行中の環境の値はファイルに書かれたものではないため、R004 の対象にしません

### 権限モデルの違いの扱い

両エージェントの設定は共通形式（`PermissionRule`）に変換しますが、意味の違いは `nativeKind` と `note` に残します。

| | Claude Code | Cursor（IDE） | Cursor CLI |
| --- | --- | --- | --- |
| 許可 | `permissions.allow` | `mcpAllowlist`, `terminalAllowlist`（前方一致。IDE 側の許可リストを置き換える） | `permissions.allow` |
| 要承認 | `permissions.ask` | （なし） | （なし） |
| 禁止 | `permissions.deny` | （なし） | `permissions.deny`（allow より優先） |
| ヒント | （なし） | `autoRun.allow_instructions` / `block_instructions`（分類器へのヒントで強制力なし。`guidance-allow` / `guidance-block` として区別） | （なし） |

### 組織の管理設定

Claude Code は管理設定を複数の配布元から読みます。優先順位は サーバー配信 > MDM（macOS の構成プロファイル / Windows の HKLM レジストリ）> ファイル です。既定（`"first-wins"`）では、ポリシーのキーを持つ最上位の配布元だけが使われます。最上位の配布元に `managedSourcesBehavior: "merge"` があれば、すべての配布元を使い、上位の値が勝ちます。AgentScope も同じ規則で判定します。

- 使われない配布元のルール・設定は `ignored` にします。ただし、Claude Code がすべての配布元から読むキー（変数ごとの `env`、`allowManagedMcpServersOnly`、`deniedMcpServers`、`disableClaudeAiConnectors`、`sandbox.filesystem.disabled`、`forceRemoteSettingsRefresh`）は残します
- 管理設定のファイルが厳密な JSON でない場合（コメント・末尾カンマ・構文エラー・トップレベルがオブジェクト以外）や、構成プロファイルが壊れている場合は、Claude Code が起動を拒否するため R008 で報告します（LOW）。空のファイルは `{}` として扱います。OS の権限で現在のユーザーが読めない管理設定は、そのユーザーのセッションが管理設定なしで起動するため MEDIUM で報告します
- I004 で、見つかった配布元・使われる配布元・確認できなかった範囲を示します

### 優先順位と有効性

ファイルに書かれたルールが、常に効いているとは限りません。各ルール・設定には `status` が付きます。

| status | 意味 | 例 |
| --- | --- | --- |
| `active` | 有効 | |
| `ignored` | エージェントが読み込まない | 括弧付きの `mcp__x(...)`、ツール名にワイルドカードを含む allow（`B*`）、`Write(パス)`、`Bash(command:...)`、置けない場所のキー（project 設定の `skipDangerousModePermissionPrompt`）、`disableBypassPermissionsMode: "disable"` で使えないモード、`allowManagedPermissionRulesOnly` 下の管理設定以外のルール |
| `overridden` | 他の設定に打ち消される | deny / ask に完全に覆われる allow（評価順は deny → ask → allow）、上位スコープに上書きされる単一値のキー（managed > local > project > user） |

根拠の設定が `active` でない検出は INFO に下げ、元のレベル（`originalLevel`）と理由（`effectNote`）を付けます。消さずに残すのは、他の設定が変われば再び有効になるためです。

打ち消しと判定するのは確実な場合だけです。deny が allow の一部だけを覆う場合（例: allow `Bash` と deny `Bash(rm *)`）は allow を `active` のままにし、推測で危険を過小評価しません。

## 検査ルール

| ID | 内容 | 主なリスクレベル |
| --- | --- | --- |
| R001 | 広範囲のコマンド実行を自動承認する設定（`Bash`、`Bash(python3 *)`、`Bash(python3 -c *)`、`Bash(npm exec *)`、`Bash(timeout *)`、Cursor の `bash`、Cursor CLI の `Shell(*)` など） | HIGH / MEDIUM |
| R002 | すべての MCP ツールを自動承認する設定（`mcp__server`、`*:*`、`enableAllProjectMcpServers` など） | HIGH / MEDIUM / INFO |
| R003 | 権限チェックを大幅に緩和する設定（`defaultMode: bypassPermissions`、`skipDangerousModePermissionPrompt` など） | HIGH / MEDIUM / LOW |
| R004 | 認証情報らしき文字列の直書き（既知のトークン形式、キー名、URL 内の認証情報） | HIGH / MEDIUM |
| R005 | 広範囲のファイル操作を許可する設定（パス限定のない `Edit`、`Read(~/**)`、`.claude/**` や `.github/workflows/**` の書き換え、`~/.aws` の読み取りなど） | HIGH / MEDIUM / LOW |
| R006 | 任意の通信先へのアクセスを許可する設定（`WebFetch`、`WebFetch(domain:*)`、`sandbox.network.allowedDomains` の `"*"`、Cursor CLI の `WebFetch(*)`） | MEDIUM |
| R007 | 安全機能や通信先を変える環境変数（[環境変数](#環境変数)を参照） | HIGH / MEDIUM / LOW / INFO |
| R008 | 組織の管理設定が正しく適用されない（Claude Code が起動を拒否する、管理設定を読めない） | MEDIUM / LOW |
| I001 | MCP サーバーの実際のツール一覧は未検証であることの明示 | INFO |
| I002 | Cursor の IDE 側設定（Run Mode など）は未検証であることの明示 | INFO |
| I003 | 自動実行されるコマンド（フック、`statusLine`、`apiKeyHelper` など）が設定されていることの明示。中身は表示しない | INFO |
| I004 | 組織の管理設定の配布元（見つかったもの・使われるもの・確認できなかった範囲）を示す（`-g` 指定時） | INFO |

各検出には、ルールID・リスクレベル・検出理由・根拠ファイル・該当する設定項目（JSON 上の位置）・推奨される対応が付きます。リスクレベルは固定のルールで決まり、推測による判定はしません。

## 安全性についての方針

- 読み取り専用で動作します。ファイルは `O_RDONLY` で開き、書き込み系の API はソースコード上で使っていません（テストで検査しています）
- エージェント、MCP サーバー、設定に書かれたコマンドを起動・実行しません
- ネットワーク通信をしません（`http` / `net` / `child_process` などのモジュールを読み込まないことをテストで検査しています）
- 認証情報の値・その一部・長さを出力しません。MCP サーバーは起動コマンドの実行ファイル名、URL のホスト名、環境変数・ヘッダーの**名前**だけを扱い、引数や値は保持しません。秘密情報を含む権限ルール文字列（`API_KEY=...`、`--token ...`、`curl -u user:pass` なども含む）は `[REDACTED]` に置き換えます。キー名・サーバー名などの名前が秘密情報らしい場合も伏せます
- 秘密情報の検出と出力保護を分けています。値がどの経路（設定・起動オプション・環境変数・検出結果・注記）から来ても、結果を返す直前に全体へ伏せ字処理をかけ、既知形式の秘密情報・URL 内の認証情報・秘密情報らしい `key=値` / `--flag 値` を `[REDACTED]` に置き換えます
- 検出で秘密情報と判定した値（`*_TOKEN` のキーの値のように、形式に特徴のない値も含む）は、スキャン1回の間だけメモリに保持し、同じ値が出力の別の場所に現れたときにも伏せます。大文字・小文字・数字を含む長くランダム性の高い文字列も伏せます。16進のハッシュ、UUID、人が付けた名前（キャメルケースやハイフンでつないだ単語）は残します
- `${VAR}` は参照として扱いますが、`${VAR:-値}` はリテラルの既定値を含むため、既定値を直接書かれた値として検査します
- 端末に出す前に、設定ファイル由来の制御文字（ANSI エスケープ、改行など）と双方向制御文字・不可視文字をエスケープし、設定ファイルでレポートの表示を書き換えたり偽装したりできないようにしています
- シンボリックリンクは解決先を確認し、プロジェクトの設定が対象ディレクトリの外を指している場合は読みません。通常ファイル以外（FIFO など）、20MB を超えるファイル、入れ子が 256 段を超える JSON も読みません
- オブジェクトはプロトタイプなしで組み立てるため、`"__proto__"` キーで書かれていないキーを見せかけることはできません。1つのファイルの解析が想定外に失敗しても、他のファイルの分析は続けます
- ホームディレクトリ全体は走査しません。`--include-global` でも上表の決まったファイルだけを読みます

## 制約

- **設定に書かれた権限と、実際に行使できる権限は一致しません。** 次の要素は分析していません
  - Windows のレジストリ（`HKLM` / `HKCU` の `SOFTWARE\Policies\ClaudeCode`。読むには外部コマンドかネイティブモジュールが必要なため）、サーバー配信の最新の内容（ローカルのキャッシュだけを読み、通信はしません）、Cursor のチーム管理者設定
  - 上記の場所に書かれていない起動オプション・環境変数（ターミナルで直接入力したものなど）。`--launch` や `--include-env` を使えば分析できます。一覧にない環境変数
  - Cursor の IDE 設定（Run Mode、設定画面で登録した許可リスト）
  - MCP サーバーが実際に提供するツールと、その操作範囲
  - プラグイン、フック、`apiKeyHelper` などのコマンドの中身
- 優先順位は確実に言える場合だけ解決します（[優先順位と有効性](#優先順位と有効性)を参照）。ルールの部分的な重なりや、起動時のオプションは考慮しません
- 検出がないことは安全を意味しません。不明な設定や解析できなかった項目は「解析できなかった項目」に表示します
- 認証情報の検出はパターンとキー名による推定のため、見逃しや誤検知がありえます
- 仕様は各エージェントの公式ドキュメント（2026年10月時点）に基づきます
  - Claude Code: [Settings](https://code.claude.com/docs/en/settings) / [Permissions](https://code.claude.com/docs/en/permissions)
  - Cursor: [permissions.json Reference](https://cursor.com/docs/reference/permissions) / [MCP](https://cursor.com/docs/context/mcp)

## JSON 出力

`--format json` は次の構造を出力します（型定義は [src/types.ts](src/types.ts)）。

```jsonc
{
  "tool": { "name": "agentscope", "version": "0.1.0" },
  "lang": "ja",
  "target": "/path/to/project",
  "agents": ["claude-code", "cursor"],
  "includeGlobal": false,
  "files": [{ "agent": "claude-code", "kind": "claude-settings", "scope": "project", "displayPath": ".claude/settings.json", "status": "parsed", ... }],
  "rules": [{ "agent": "claude-code", "effect": "allow", "category": "command", "tool": "Bash", "specifier": "python3 *", "nativeKind": "claude.permissions.allow", "source": { "file": ".claude/settings.json", "pointer": "permissions.allow[1]" }, "status": "active", ... }],
  "settings": [{ "key": "permissions.defaultMode", "value": "bypassPermissions", ... }],
  "mcpServers": [{ "name": "github", "transport": "stdio", "commandName": "npx", "envNames": ["GITHUB_TOKEN"], "approval": "approved", "toolPermissions": "unknown", ... }],
  "launches": [{ "agent": "claude-code", "executable": "claude", "source": { "file": "package.json", "pointer": "scripts.ai" }, "options": [{ "flag": "--dangerously-skip-permissions" }], ... }],
  "findings": [{ "ruleId": "R001", "level": "HIGH", "reason": "...", "file": "...", "pointer": "...", "evidence": "...", "recommendation": "...", "originalLevel": "HIGH (only when lowered)", "effectNote": "..." }],
  "unparsed": [{ "file": ".claude/settings.json", "pointer": "hooks", "reason": "..." }],
  "summary": { "files": 3, "rules": 12, "mcpServers": 3, "launches": 1, "findings": { "HIGH": 1, "MEDIUM": 2, "LOW": 0, "INFO": 1 } },
  "disclaimer": "..."
}
```

## 開発

```bash
npm install
npm test           # Vitest
npm run typecheck
npm run build      # dist/ に出力
npm run e2e        # ビルドした CLI を起動して終了コードとパイプ切断を確認
node dist/cli.js scan test/fixtures/risky-project
```

テストは実在しないダミー設定だけを使います。トークン形式のダミー値はリポジトリのシークレットスキャンに反応しないよう、テスト実行時に組み立てています（[test/helpers.ts](test/helpers.ts)）。

### 構成

```
src/
  cli.ts / program.ts      CLI（Commander.js）
  scan.ts                  検出 → 解析 → 正規化 → 検査 の流れをまとめる
  discovery/discover.ts    Config Discovery：決まった場所の候補を列挙
  parsers/claude.ts        Claude Code パーサー
  parsers/cursor.ts        Cursor パーサー
  parsers/common.ts        MCP サーバー定義など共通処理
  rules/r00x-*.ts          Security Rule Engine：検査ルール（1ルール1ファイル）
  report/terminal.ts|json.ts  Report Generator
  util/safeRead.ts         読み取り専用・シンボリックリンク対策付きのファイル読み込み
  precedence.ts            ファイル間の優先順位とルールの有効性
  util/secrets.ts          認証情報らしき文字列の検出と伏せ字
  util/pointer.ts          表示用の JSON パス（秘密情報らしいキー名は伏せる）
  types.ts                 共通データ形式
  i18n.ts                  表示文言の日英切り替え
```

### 検査ルールを追加する

1. `src/rules/` に `SecurityRule`（`id` / `title` / `description` / `check`）を実装したファイルを追加します
2. `src/rules/index.ts` の `SECURITY_RULES` に登録します
3. `test/rules.test.ts` に検出する例・検出しない例を追加します

`check` には全エージェントのルール・設定・MCP サーバーが共通形式で渡されます。秘密情報を `evidence` に入れないでください。

利用者に見せる文言（`title` / `description` / `reason` / `recommendation`）は `tx('日本語', 'English')` で日英の両方を書きます。言語は出力の直前に選ばれます。`test/i18n.test.ts` が英語訳の欠けや日本語の混入を検出します。

### 対応エージェントを追加する

1. `src/types.ts` の `AgentId` に追加します
2. `src/discovery/discover.ts` に設定ファイルの場所を追加します
3. `src/parsers/` にパーサーを追加し、`src/scan.ts` の `parseByKind` から呼びます。知らないキーは `unparsed` に入れ、推測で権限を補わないでください

## ライセンス

[Apache License 2.0](LICENSE)
