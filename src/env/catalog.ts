import { tx, type Text } from '../i18n.js';
import type { AgentId, RiskLevel } from '../types.js';

/**
 * 権限・安全性に関わる環境変数の一覧。
 * 仕様: https://code.claude.com/docs/en/env-vars , https://cursor.com/docs/cli/reference/authentication
 *
 * 値の扱い（display）:
 * - secret: 値は保持も表示もしない（「設定あり」だけ）
 * - url: スキームとホスト名だけを保持する（ユーザー情報・パス・クエリは捨てる）
 * - flag: 短い設定値（"1" や "bundled,system" など）をそのまま保持する
 * - path: パスを保持する（秘密情報らしければ伏せる）
 */

export type EnvDisplay = 'secret' | 'url' | 'flag' | 'path';

export interface EnvRisk {
  level: RiskLevel;
  reason: Text;
  recommendation: Text;
}

export interface EnvSpec {
  agent: AgentId;
  display: EnvDisplay;
  /** 設定ファイルの env ブロックでは無視される（起動する環境で設定する必要がある） */
  ignoredInSettingsEnv?: boolean;
  /** project / local 設定の env ブロックでは無視される */
  ignoredInProjectEnv?: boolean;
  /** 値（display に応じて正規化済み）から危険性を判定する */
  risk?: (value: string, ctx: { projectShared: boolean }) => EnvRisk | undefined;
}

const REC_UNSET = (name: string) => tx(`理由がなければ ${name} を設定しないでください。`, `Do not set ${name} unless you have a reason to.`);

function safetyCheckOff(name: string, ja: string, en: string, level: RiskLevel = 'MEDIUM'): EnvSpec {
  return {
    agent: 'claude-code',
    display: 'flag',
    ignoredInSettingsEnv: true,
    risk: (v) => (v === '1' ? { level, reason: tx(ja, en), recommendation: REC_UNSET(name) } : undefined),
  };
}

function baseUrl(name: string): EnvSpec {
  return {
    agent: 'claude-code',
    display: 'url',
    risk: (v, { projectShared }) => {
      // 公式の接続先は変更とみなさない
      if (v === 'https://api.anthropic.com') return undefined;
      if (v.startsWith('http:')) {
        return {
          level: 'MEDIUM',
          reason: tx(`${name} が暗号化されていない http の接続先（${v}）を指しています。プロンプトやコードが平文で送られます`, `${name} points to an unencrypted http endpoint (${v}). Prompts and code are sent in plain text`),
          recommendation: tx('https の接続先を使ってください。', 'Use an https endpoint.'),
        };
      }
      if (projectShared) {
        return {
          level: 'MEDIUM',
          reason: tx(
            `リポジトリで共有される場所で ${name} が ${v} に設定されています。プロンプトやコードの送信先がリポジトリの内容で変わります`,
            `${name} is set to ${v} in a location shared through the repository, so the repository decides where prompts and code are sent`,
          ),
          recommendation: tx('接続先の変更は、ユーザー設定または組織の管理設定で行ってください。', 'Change the endpoint in user settings or organization-managed settings instead.'),
        };
      }
      return {
        level: 'INFO',
        reason: tx(`API 通信は ${v} を経由します。`, `API traffic goes through ${v}.`),
        recommendation: tx('信頼できる接続先であることを確認してください。', 'Make sure the endpoint is trusted.'),
      };
    },
  };
}

const credential = (agent: AgentId = 'claude-code'): EnvSpec => ({ agent, display: 'secret' });

export const ENV_CATALOG: Record<string, EnvSpec> = {
  // 認証情報（値は扱わない。ファイルに直接書かれていれば R004 が検出する）
  ANTHROPIC_API_KEY: credential(),
  ANTHROPIC_AUTH_TOKEN: credential(),
  ANTHROPIC_FOUNDRY_API_KEY: credential(),
  ANTHROPIC_FOUNDRY_AUTH_TOKEN: credential(),
  ANTHROPIC_AWS_API_KEY: credential(),
  AWS_BEARER_TOKEN_BEDROCK: credential(),
  CLAUDE_CODE_OAUTH_TOKEN: credential(),
  CLAUDE_CODE_OAUTH_REFRESH_TOKEN: credential(),
  CLAUDE_CODE_CLIENT_KEY_PASSPHRASE: credential(),
  ANTHROPIC_CUSTOM_HEADERS: credential(),
  CURSOR_API_KEY: credential('cursor'),

  // API の接続先
  ANTHROPIC_BASE_URL: baseUrl('ANTHROPIC_BASE_URL'),
  ANTHROPIC_BEDROCK_BASE_URL: baseUrl('ANTHROPIC_BEDROCK_BASE_URL'),
  ANTHROPIC_VERTEX_BASE_URL: baseUrl('ANTHROPIC_VERTEX_BASE_URL'),
  ANTHROPIC_FOUNDRY_BASE_URL: baseUrl('ANTHROPIC_FOUNDRY_BASE_URL'),
  ANTHROPIC_AWS_BASE_URL: baseUrl('ANTHROPIC_AWS_BASE_URL'),

  // 安全チェックを止める変数（設定ファイルの env では無視される）
  CLAUDE_CODE_DISABLE_INLINE_SHELL_RM_PROMPT: safetyCheckOff(
    'CLAUDE_CODE_DISABLE_INLINE_SHELL_RM_PROMPT',
    'bash -c などに渡すスクリプト内の、重要なパスの削除チェックが無効になっています',
    'The critical-path removal check for scripts passed to a shell with -c is turned off',
  ),
  CLAUDE_CODE_DISABLE_SUBSTITUTION_RM_PROMPT: safetyCheckOff(
    'CLAUDE_CODE_DISABLE_SUBSTITUTION_RM_PROMPT',
    'rm -rf "$(pwd)" のような、コマンド置換を対象にした再帰削除のチェックが無効になっています',
    'The check for recursive rm whose target is a command substitution, such as rm -rf "$(pwd)", is turned off',
  ),
  CLAUDE_CODE_DISABLE_POWERSHELL_CMD_RM_DENY: safetyCheckOff(
    'CLAUDE_CODE_DISABLE_POWERSHELL_CMD_RM_DENY',
    'PowerShell でドライブのルートやホームを rd / del で削除することを拒否するチェックが無効になっています',
    'The PowerShell check that denies rd / del on system paths such as a drive root or home is turned off',
  ),
  CLAUDE_CODE_DISABLE_DANGEROUS_RM_TIMEOUT: safetyCheckOff(
    'CLAUDE_CODE_DISABLE_DANGEROUS_RM_TIMEOUT',
    '重要なパスの削除確認の時間制限が無効になり、auto モードでは確認が分類器に任されます',
    'The time limit on critical-path removal prompts is off; in auto mode those removals are left to the classifier',
    'LOW',
  ),

  // 通信・証明書
  NODE_TLS_REJECT_UNAUTHORIZED: {
    agent: 'claude-code',
    display: 'flag',
    risk: (v) =>
      v === '0'
        ? {
            level: 'HIGH',
            reason: tx(
              'NODE_TLS_REJECT_UNAUTHORIZED=0 により、Node.js で動くプロセス（npm 版の Claude Code、npx で起動する MCP サーバーなど）の TLS 証明書の検証が無効になります。通信の盗聴・改ざんを防げません',
              'NODE_TLS_REJECT_UNAUTHORIZED=0 turns off TLS certificate verification for Node.js processes (the npm build of Claude Code, MCP servers started with npx, etc.), so traffic can be intercepted or modified',
            ),
            recommendation: tx(
              'この変数を外し、社内の証明書が必要なら NODE_EXTRA_CA_CERTS や CLAUDE_CODE_CERT_STORE で追加してください。',
              'Remove it. If you need a corporate CA, add it with NODE_EXTRA_CA_CERTS or CLAUDE_CODE_CERT_STORE.',
            ),
          }
        : undefined,
  },
  NODE_EXTRA_CA_CERTS: {
    agent: 'claude-code',
    display: 'path',
    risk: (v) => ({
      level: 'INFO',
      reason: tx(`追加の CA 証明書（${v}）が信頼されます。`, `An extra CA certificate (${v}) is trusted.`),
      recommendation: tx('意図した証明書であることを確認してください。', 'Make sure it is the certificate you intended.'),
    }),
  },
  NODE_OPTIONS: {
    agent: 'claude-code',
    display: 'flag',
    risk: (v) =>
      /(?:^|\s)(?:--require|-r|--import|--loader|--experimental-loader)\b/.test(v)
        ? {
            level: 'MEDIUM',
            reason: tx(
              'NODE_OPTIONS で、Node.js で動くすべてのプロセス（MCP サーバーなど）に別のコードを読み込ませています',
              'NODE_OPTIONS makes every Node.js process (MCP servers, etc.) load extra code',
            ),
            recommendation: tx('読み込むコードが信頼できるか確認し、不要なら外してください。', 'Make sure the loaded code is trusted, and remove it if not needed.'),
          }
        : undefined,
  },
  HTTPS_PROXY: { agent: 'claude-code', display: 'url' },
  HTTP_PROXY: { agent: 'claude-code', display: 'url' },

  // MCP サーバーへの環境変数の受け渡し（1 なら安全側）
  CLAUDE_CODE_MCP_ALLOWLIST_ENV: { agent: 'claude-code', display: 'flag' },

  // 設定の読み込み元
  CLAUDE_CONFIG_DIR: {
    agent: 'claude-code',
    display: 'path',
    ignoredInProjectEnv: true,
    risk: (v) => ({
      level: 'INFO',
      reason: tx(
        `CLAUDE_CONFIG_DIR により、ユーザー設定は ${v} から読まれます。AgentScope が -g で読む ~/.claude の内容とは異なる可能性があります`,
        `CLAUDE_CONFIG_DIR makes Claude Code read user settings from ${v}, which may differ from ~/.claude that AgentScope reads with -g`,
      ),
      recommendation: tx('そのディレクトリの settings.json も確認してください。', 'Also review settings.json in that directory.'),
    }),
  },

  // 送信を止める変数（安全側。project / local では無視される）
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: { agent: 'claude-code', display: 'flag', ignoredInProjectEnv: true },
  DISABLE_TELEMETRY: { agent: 'claude-code', display: 'flag', ignoredInProjectEnv: true },
  DISABLE_ERROR_REPORTING: { agent: 'claude-code', display: 'flag', ignoredInProjectEnv: true },
  CLAUDE_CODE_DISABLE_ATTACHMENTS: { agent: 'claude-code', display: 'flag', ignoredInProjectEnv: true },
  CLAUDE_CODE_PLUGIN_DIRS: { agent: 'claude-code', display: 'path', ignoredInProjectEnv: true },
};

/** Claude Code が自分のサブプロセスに設定する読み取り専用の変数。環境から読んでも分析しない */
export const READ_ONLY_ENV = new Set(['CLAUDECODE', 'CLAUDE_CODE_CHILD_SESSION', 'CLAUDE_CODE_BRIDGE_SESSION_ID', 'CLAUDE_CODE_MESSAGING_SOCKET', 'CLAUDE_CODE_MESSAGING_TOKEN']);
