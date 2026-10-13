# AgentScope

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
agentscope --help
```

| オプション | 説明 | 既定値 |
| --- | --- | --- |
| `-a, --agent <claude\|cursor\|all>` | 対象エージェント | `all` |
| `-f, --format <text\|json>` | 出力形式 | `text` |
| `-g, --include-global` | ホームディレクトリのユーザー設定も読む | 読まない |
| `--no-color` | 色を付けない（`NO_COLOR` 環境変数でも無効化） | TTY のとき色付き |

終了コードは、分析できたとき `0`、対象ディレクトリが見つからないなどのエラー時に `2` です。検出の有無では変わりません。

### 出力例

`test/fixtures/risky-project`（テスト用のダミー設定）を分析した結果の抜粋です。

```text
AgentScope Security Report (v0.1.0)
対象エージェント: Claude Code, Cursor
設定ファイル: 5  権限ルール: 23  MCPサーバー: 4  検出: HIGH 5 / MEDIUM 11 / LOW 0 / INFO 4

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
| Cursor | `.cursor/cli.json`, `~/.cursor/cli-config.json` | — | — | 存在は検出するが **未対応** と表示 |

JSON と JSONC（コメント・末尾カンマ）の両方を読めます。

### 権限モデルの違いの扱い

両エージェントの設定は共通形式（`PermissionRule`）に変換しますが、意味の違いは `nativeKind` と `note` に残します。

| | Claude Code | Cursor |
| --- | --- | --- |
| 許可 | `permissions.allow` | `mcpAllowlist`, `terminalAllowlist`（前方一致。IDE 側の許可リストを置き換える） |
| 要承認 | `permissions.ask` | （なし） |
| 禁止 | `permissions.deny` | （なし） |
| ヒント | （なし） | `autoRun.allow_instructions` / `block_instructions`（分類器へのヒントで強制力なし。`guidance-allow` / `guidance-block` として区別） |

## 検査ルール

| ID | 内容 | 主なリスクレベル |
| --- | --- | --- |
| R001 | 広範囲のコマンド実行を自動承認する設定（`Bash`、`Bash(python3 *)`、Cursor の `bash` など） | HIGH / MEDIUM |
| R002 | すべての MCP ツールを自動承認する設定（`mcp__server`、`*:*`、`enableAllProjectMcpServers` など） | HIGH / MEDIUM / INFO |
| R003 | 権限チェックを大幅に緩和する設定（`defaultMode: bypassPermissions`、`skipDangerousModePermissionPrompt` など） | HIGH / MEDIUM / LOW |
| R004 | 認証情報らしき文字列の直書き（既知のトークン形式、キー名、URL 内の認証情報） | HIGH / MEDIUM |
| R005 | 広範囲のファイル操作を許可する設定（パス限定のない `Edit`、`Read(~/**)`、`.claude/**` の書き換え許可など） | HIGH / MEDIUM / LOW |
| I001 | MCP サーバーの実際のツール一覧は未検証であることの明示 | INFO |
| I002 | Cursor の IDE 側設定（Run Mode など）は未検証であることの明示 | INFO |

各検出には、ルールID・リスクレベル・検出理由・根拠ファイル・該当する設定項目（JSON 上の位置）・推奨される対応が付きます。リスクレベルは固定のルールで決まり、推測による判定はしません。

## 安全性についての方針

- 読み取り専用で動作します。ファイルは `O_RDONLY` で開き、書き込み系の API はソースコード上で使っていません（テストで検査しています）
- エージェント、MCP サーバー、設定に書かれたコマンドを起動・実行しません
- ネットワーク通信をしません（`http` / `net` / `child_process` などのモジュールを読み込まないことをテストで検査しています）
- 認証情報の値・その一部・長さを出力しません。MCP サーバーは起動コマンドの実行ファイル名、URL のホスト名、環境変数・ヘッダーの**名前**だけを扱い、引数や値は保持しません。秘密情報を含む権限ルール文字列は `[REDACTED]` に置き換えます
- シンボリックリンクは解決先を確認し、プロジェクトの設定が対象ディレクトリの外を指している場合は読みません。通常ファイル以外（FIFO など）や 20MB を超えるファイルも読みません
- ホームディレクトリ全体は走査しません。`--include-global` でも上表の決まったファイルだけを読みます

## 制約

- **設定に書かれた権限と、実際に行使できる権限は一致しません。** 次の要素は分析していません
  - 組織の管理設定（Claude Code の managed settings、Cursor のチーム管理者設定）
  - 起動時のオプション（`--permission-mode`、`--allowedTools` など）
  - Cursor の IDE 設定（Run Mode、設定画面で登録した許可リスト）
  - MCP サーバーが実際に提供するツールと、その操作範囲
  - プラグイン、フック、`apiKeyHelper` などのコマンドの中身
- 複数ファイルの設定を合成した「最終的な有効権限」は計算せず、ファイルごとのルールを並べて表示します
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
  "target": "/path/to/project",
  "agents": ["claude-code", "cursor"],
  "includeGlobal": false,
  "files": [{ "agent": "claude-code", "kind": "claude-settings", "scope": "project", "displayPath": ".claude/settings.json", "status": "parsed", ... }],
  "rules": [{ "agent": "claude-code", "effect": "allow", "category": "command", "tool": "Bash", "specifier": "python3 *", "nativeKind": "claude.permissions.allow", "source": { "file": ".claude/settings.json", "pointer": "permissions.allow[1]" }, ... }],
  "settings": [{ "key": "permissions.defaultMode", "value": "bypassPermissions", ... }],
  "mcpServers": [{ "name": "github", "transport": "stdio", "commandName": "npx", "envNames": ["GITHUB_TOKEN"], "approval": "approved", "toolPermissions": "unknown", ... }],
  "findings": [{ "ruleId": "R001", "level": "HIGH", "reason": "...", "file": "...", "pointer": "...", "evidence": "...", "recommendation": "..." }],
  "unparsed": [{ "file": ".claude/settings.json", "pointer": "hooks", "reason": "..." }],
  "summary": { "files": 3, "rules": 12, "mcpServers": 3, "findings": { "HIGH": 1, "MEDIUM": 2, "LOW": 0, "INFO": 1 } },
  "disclaimer": "..."
}
```

## 開発

```bash
npm install
npm test           # Vitest
npm run typecheck
npm run build      # dist/ に出力
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
  util/secrets.ts          認証情報らしき文字列の検出と伏せ字
  types.ts                 共通データ形式
```

### 検査ルールを追加する

1. `src/rules/` に `SecurityRule`（`id` / `title` / `description` / `check`）を実装したファイルを追加します
2. `src/rules/index.ts` の `SECURITY_RULES` に登録します
3. `test/rules.test.ts` に検出する例・検出しない例を追加します

`check` には全エージェントのルール・設定・MCP サーバーが共通形式で渡されます。秘密情報を `evidence` に入れないでください。

### 対応エージェントを追加する

1. `src/types.ts` の `AgentId` に追加します
2. `src/discovery/discover.ts` に設定ファイルの場所を追加します
3. `src/parsers/` にパーサーを追加し、`src/scan.ts` の `parseByKind` から呼びます。知らないキーは `unparsed` に入れ、推測で権限を補わないでください

## ライセンス

[Apache License 2.0](LICENSE)
