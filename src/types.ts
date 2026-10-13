/**
 * AgentScope の共通データ形式。
 *
 * Claude Code と Cursor は権限モデルが異なるため、共通形式に変換しつつ
 * `nativeKind` に元の設定項目の種類を残し、意味の違いを失わないようにする。
 */

export type AgentId = 'claude-code' | 'cursor';

export const AGENT_LABELS: Record<AgentId, string> = {
  'claude-code': 'Claude Code',
  cursor: 'Cursor',
};

/** 設定が適用される範囲 */
export type ConfigScope =
  | 'project' // リポジトリで共有される設定（.claude/settings.json, .mcp.json, .cursor/*）
  | 'project-local' // 個人のプロジェクト設定（.claude/settings.local.json, ~/.claude.json の projects[...]）
  | 'user'; // ユーザー全体の設定（~/.claude/settings.json, ~/.cursor/*）

export type ConfigKind =
  | 'claude-settings'
  | 'claude-mcp'
  | 'claude-global-state'
  | 'cursor-mcp'
  | 'cursor-permissions'
  | 'unsupported';

export type FileStatus =
  | 'parsed' // 解析できた
  | 'parse-error' // JSON/JSONC として読めなかった、または想定外の形
  | 'skipped' // 安全上の理由などで読まなかった（シンボリックリンク、サイズ超過など）
  | 'unsupported'; // 存在は検出したが v0.1 では解析対象外

export interface ConfigFile {
  agent: AgentId;
  kind: ConfigKind;
  scope: ConfigScope;
  /** 絶対パス */
  path: string;
  /** 表示用パス（ホームは ~ に、対象ディレクトリ配下は相対パスに置き換える） */
  displayPath: string;
  status: FileStatus;
  /** status が parsed 以外のときの理由 */
  reason?: string;
  /** シンボリックリンクだった場合のリンク先（表示用） */
  symlinkTarget?: string;
}

/** 設定箇所への参照 */
export interface SourceRef {
  file: string; // displayPath
  /** JSON 上の位置。例: permissions.allow[2] */
  pointer: string;
}

export type RuleEffect =
  | 'allow' // 承認なしで実行できる
  | 'ask' // 毎回承認を求める
  | 'deny' // 禁止
  | 'guidance-allow' // 分類器への自然言語ヒント（許可寄り）。強制力はない
  | 'guidance-block'; // 分類器への自然言語ヒント（拒否寄り）。強制力はない

export type RuleCategory =
  | 'command' // シェル・ターミナルコマンド
  | 'file-read'
  | 'file-write'
  | 'mcp'
  | 'network'
  | 'other'
  | 'unknown';

export interface PermissionRule {
  agent: AgentId;
  scope: ConfigScope;
  effect: RuleEffect;
  category: RuleCategory;
  /** ツール名（Bash, Edit, mcp__github__create_issue, Shell など） */
  tool: string;
  /** 括弧内の指定子やパターン。ツール全体を対象にするときは undefined */
  specifier?: string;
  /** 設定ファイルに書かれた元の文字列 */
  raw: string;
  /** エージェント固有の設定項目の種類（例: claude.permissions.allow, cursor.terminalAllowlist） */
  nativeKind: string;
  source: SourceRef;
  /** 権限モデル上の注意（例: Cursor の autoRun は強制力のないヒント） */
  note?: string;
}

/** 権限ルール以外の、権限に関わる設定値 */
export interface PermissionSetting {
  agent: AgentId;
  scope: ConfigScope;
  key: string;
  /** 表示用の値。秘密情報になりうる値は入れない */
  value: string;
  source: SourceRef;
}

export type McpTransport = 'stdio' | 'http' | 'sse' | 'unknown';

export type McpApproval =
  | 'approved' // 承認済み（設定で明示的に有効化）
  | 'rejected' // 設定で明示的に無効化
  | 'not-required' // ユーザー自身が追加したサーバーなど、プロジェクト承認の対象外
  | 'unknown'; // 設定ファイルからは判断できない

export interface McpServer {
  agent: AgentId;
  scope: ConfigScope;
  name: string;
  transport: McpTransport;
  /** 起動コマンドの実行ファイル名のみ（引数は秘密情報を含みうるため保持しない） */
  commandName?: string;
  /** 接続先URLのホスト名のみ */
  urlHost?: string;
  /** 環境変数の名前のみ（値は保持しない） */
  envNames: string[];
  /** HTTP ヘッダーの名前のみ（値は保持しない） */
  headerNames: string[];
  approval: McpApproval;
  approvalNote?: string;
  source: SourceRef;
  /** 設定ファイルから分からないツール権限は常に unknown として扱う */
  toolPermissions: 'unknown';
}

export type RiskLevel = 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export const RISK_ORDER: Record<RiskLevel, number> = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };

export interface Finding {
  ruleId: string;
  level: RiskLevel;
  agent: AgentId;
  title: string;
  /** 検出理由 */
  reason: string;
  /** 根拠となる設定ファイル（displayPath） */
  file: string;
  /** 該当する設定項目（JSON 上の位置） */
  pointer: string;
  /** 該当する設定値（秘密情報は含めない） */
  evidence?: string;
  recommendation: string;
}

/** 解析できなかった項目 */
export interface UnparsedItem {
  agent: AgentId;
  file: string;
  pointer: string;
  reason: string;
}

/** パーサー1回分の出力 */
export interface ParsedConfig {
  rules: PermissionRule[];
  settings: PermissionSetting[];
  mcpServers: McpServer[];
  unparsed: UnparsedItem[];
  /** R004 用：秘密情報らしき文字列の検出結果（値そのものは含まない） */
  secretHits: SecretHit[];
}

export interface SecretHit {
  agent: AgentId;
  file: string;
  pointer: string;
  /** どの根拠で判定したか */
  kind: 'value-pattern' | 'key-name' | 'url-credential';
  /** 判定に使ったパターン名（例: GitHub token）。値は含めない */
  label: string;
}

export interface ScanResult {
  tool: { name: 'agentscope'; version: string };
  target: string;
  agents: AgentId[];
  includeGlobal: boolean;
  files: ConfigFile[];
  rules: PermissionRule[];
  settings: PermissionSetting[];
  mcpServers: McpServer[];
  findings: Finding[];
  unparsed: UnparsedItem[];
  summary: {
    files: number;
    rules: number;
    mcpServers: number;
    findings: Record<RiskLevel, number>;
  };
  disclaimer: string;
}
