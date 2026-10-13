import { tx, type Text } from '../i18n.js';
import type { AgentId, Finding, RiskLevel } from '../types.js';
import { redactIfSecret } from '../util/secrets.js';
import { finding, type SecurityRule } from './types.js';

const rule = { id: 'R005', title: tx('広範囲のファイル操作を許可する設定', 'Broad file access is allowed') };

const GLOB_TAIL = '(?:\\*\\*?(?:\\/\\*\\*?)*)?\\/?$';

/**
 * ファイルシステム全体、またはホームディレクトリ全体を指すパターン。
 * Claude Code は「//」が絶対パスで「/」は設定ファイル基準。Cursor CLI は「/」が絶対パス。
 */
function isMachineWide(spec: string, agent: AgentId): boolean {
  const s = spec.trim().replace(/\\/g, '/');
  const root = agent === 'claude-code' ? '(?:\\/\\/(?:[a-zA-Z]\\/)?|~\\/?)' : '(?:\\/|~\\/?|[a-zA-Z]:\\/)';
  return new RegExp(`^${root}${GLOB_TAIL}`).test(s);
}

/** 作業ディレクトリ全体（どの深さにも一致）を指すパターン */
function isProjectWide(spec: string, agent: AgentId): boolean {
  const re = agent === 'claude-code' ? /^(?:\.\/|\/)?\*\*?(?:\/\*+)?$/ : /^(?:\.\/)?\*\*?(?:\/\*+)?$/;
  return re.test(spec.trim());
}

/** 書き換えられると権限設定や自動実行に影響するファイル */
const SENSITIVE_WRITE: Array<{ re: RegExp; label: Text }> = [
  { re: /(?:^|\/)\.claude(?:\/|$)/, label: tx('Claude Code 自身の設定', "Claude Code's own settings") },
  { re: /(?:^|\/)\.cursor(?:\/|$)/, label: tx('Cursor 自身の設定', "Cursor's own settings") },
  { re: /(?:^|\/)\.mcp\.json$/, label: tx('MCP サーバー設定', 'the MCP server config') },
  { re: /(?:^|\/)\.git\/(?:hooks|config)/, label: tx('Git フック・設定', 'Git hooks or config') },
  { re: /(?:^|\/)\.git(?:\/\*\*)?$/, label: tx('Git ディレクトリ', 'the Git directory') },
  { re: /(?:^|\/)\.(?:bashrc|zshrc|profile|bash_profile|zprofile|zshenv)$/, label: tx('シェルの起動ファイル', 'shell startup files') },
  { re: /(?:^|\/)\.ssh(?:\/|$)/, label: tx('SSH の鍵・設定', 'SSH keys or config') },
  { re: /(?:^|\/)\.github\/workflows(?:\/|$)/, label: tx('GitHub Actions のワークフロー', 'GitHub Actions workflows') },
  { re: /(?:^|\/)\.vscode\/(?:tasks|settings|launch)\.json$|(?:^|\/)\.vscode(?:\/\*\*)?$/, label: tx('VS Code のタスク・設定', 'VS Code tasks or settings') },
  { re: /(?:^|\/)\.husky(?:\/|$)/, label: tx('Git フック（husky）', 'Git hooks (husky)') },
  { re: /(?:^|\/)\.(?:npmrc|yarnrc(?:\.yml)?|pypirc)$/, label: tx('パッケージマネージャーの設定', 'package manager config') },
];

const SENSITIVE_READ: Array<{ re: RegExp; label: Text }> = [
  { re: /(?:^|\/)\.ssh(?:\/|$)/, label: tx('SSH の鍵', 'SSH keys') },
  { re: /(?:^|\/)\.aws(?:\/|$)/, label: tx('AWS の認証情報', 'AWS credentials') },
  { re: /(?:^|\/)\.env(?:\.[\w.-]+)?$/, label: tx('.env ファイル', '.env files') },
  { re: /(?:^|\/)\.gnupg(?:\/|$)/, label: tx('GPG の鍵', 'GPG keys') },
  { re: /(?:^|\/)\.(?:netrc|git-credentials|npmrc|pypirc)$/, label: tx('認証情報を含む設定ファイル', 'files that hold credentials') },
  { re: /(?:^|\/)\.docker\/config\.json$|(?:^|\/)\.kube(?:\/|$)|(?:^|\/)\.config\/(?:gh|gcloud)(?:\/|$)|(?:^|\/)\.azure(?:\/|$)/, label: tx('クラウド・コンテナの認証情報', 'cloud or container credentials') },
  { re: /\.(?:pem|key|p12|pfx)$|(?:^|\/)id_(?:rsa|ed25519|ecdsa)$/, label: tx('秘密鍵ファイル', 'private key files') },
];

const REC_CURSOR = tx(
  'Write(src/**) のように、作業に必要なディレクトリだけに限定してください。秘密情報を含むパスは deny に入れてください。',
  'Limit it to the directories the work needs, such as Write(src/**). Put paths that hold secrets in deny.',
);
const REC_RULE = tx(
  'Edit(/src/**) のように、作業に必要なディレクトリだけに限定してください。秘密情報を含むパスは Read の deny ルールに入れてください。',
  'Limit it to the directories the work needs, such as Edit(/src/**). Put paths that hold secrets in Read deny rules.',
);

export const r005: SecurityRule = {
  ...rule,
  description: tx(
    'ファイルの読み書きをマシン全体・ホーム全体に広げる設定や、権限設定そのものを書き換えられる設定を検出します。',
    'Detects settings that extend file reads or writes to the whole machine or home directory, or that allow rewriting the permission settings themselves.',
  ),
  check(ctx) {
    const out: Finding[] = [];

    for (const r of ctx.rules) {
      if (r.effect !== 'allow') continue;
      if (r.category !== 'file-write' && r.category !== 'file-read') continue;
      const write = r.category === 'file-write';
      const spec = r.specifier?.trim();
      const base = { agent: r.agent, file: r.source.file, pointer: r.source.pointer, evidence: redactIfSecret(r.raw) };
      let level: RiskLevel | undefined;
      let reason: Text | undefined;

      if (spec === undefined || spec === '') {
        level = write ? 'HIGH' : 'MEDIUM';
        reason = write
          ? tx(
              `${r.tool} がパスの限定なしで許可されており、作業ディレクトリ外を含むファイルの書き換えが承認なしで行えます`,
              `${r.tool} is allowed without a path restriction, so files can be modified without approval, including outside the working directory`,
            )
          : tx(
              `${r.tool} がパスの限定なしで許可されており、作業ディレクトリ外のファイルも承認なしで読めます`,
              `${r.tool} is allowed without a path restriction, so files outside the working directory can be read without approval`,
            );
      } else if (isMachineWide(spec, r.agent)) {
        level = write ? 'HIGH' : 'MEDIUM';
        reason = tx(`「${spec}」はファイルシステム全体またはホームディレクトリ全体を指します`, `"${spec}" covers the entire filesystem or home directory`);
      } else if (write && isProjectWide(spec, r.agent)) {
        level = 'LOW';
        reason = tx(
          `「${spec}」は作業ディレクトリ内のすべてのファイル（設定ファイルを含む）の書き換えを許可します`,
          `"${spec}" allows modifying every file in the working directory, including config files`,
        );
      } else {
        const list = write ? SENSITIVE_WRITE : SENSITIVE_READ;
        const hit = list.find((x) => x.re.test(spec.replace(/\\/g, '/').replace(/\/\*\*$|\/\*$/, '')));
        if (hit) {
          level = 'MEDIUM';
          reason = write
            ? tx(
                `${hit.label.ja}の書き換えを承認なしで許可しています。権限設定や自動実行される処理を変更される可能性があります`,
                `Modifying ${hit.label.en} is allowed without approval. Permission settings or automatically executed code could be changed`,
              )
            : tx(`${hit.label.ja}の読み取りを承認なしで許可しています`, `Reading ${hit.label.en} is allowed without approval`);
        }
      }
      if (level && reason) out.push(finding(rule, { ...base, level, reason, recommendation: r.agent === 'cursor' ? REC_CURSOR : REC_RULE }));
    }

    for (const s of ctx.settings) {
      if (s.agent !== 'claude-code' || s.key !== 'permissions.additionalDirectories' || typeof s.value !== 'string') continue;
      const v = s.value.trim().replace(/\\/g, '/').replace(/\/+$/, '');
      const home = ctx.home?.replace(/\\/g, '/').replace(/\/+$/, '');
      if (v === '' || v === '/' || v === '~' || /^[a-zA-Z]:$/.test(v) || v === '//' || (home !== undefined && v === home)) {
        out.push(finding(rule, {
          level: 'MEDIUM',
          agent: s.agent,
          reason: tx(
            `作業ディレクトリとして「${s.value}」が追加されており、ファイルシステム全体またはホーム全体が操作対象になります`,
            `"${s.value}" is added as a working directory, which puts the entire filesystem or home directory in scope`,
          ),
          file: s.source.file,
          pointer: s.source.pointer,
          evidence: s.value,
          recommendation: tx('必要なディレクトリだけを additionalDirectories に追加してください。', 'Add only the directories you need to additionalDirectories.'),
        }));
      }
    }
    return out;
  },
};
