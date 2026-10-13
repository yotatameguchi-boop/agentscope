import type { Finding, RiskLevel } from '../types.js';
import { redactIfSecret } from '../util/secrets.js';
import { finding, type SecurityRule } from './types.js';

const rule = { id: 'R005', title: '広範囲のファイル操作を許可する設定' };

/** ファイルシステム全体、またはホームディレクトリ全体を指すパターン */
function isMachineWide(spec: string): boolean {
  const s = spec.trim().replace(/\\/g, '/');
  return /^(?:\/\/|~\/?)(?:\*\*?(?:\/\*\*?)*)?\/?$/.test(s) || /^\/\/[a-zA-Z]\/\*\*$/.test(s);
}

/** 作業ディレクトリ全体（どの深さにも一致）を指すパターン */
function isProjectWide(spec: string): boolean {
  return /^(?:\.\/|\/)?\*\*?(?:\/\*+)?$/.test(spec.trim());
}

/** 書き換えられると権限設定や自動実行に影響するファイル */
const SENSITIVE_WRITE = [
  { re: /(?:^|\/)\.claude(?:\/|$)/, label: 'Claude Code 自身の設定' },
  { re: /(?:^|\/)\.cursor(?:\/|$)/, label: 'Cursor 自身の設定' },
  { re: /(?:^|\/)\.mcp\.json$/, label: 'MCP サーバー設定' },
  { re: /(?:^|\/)\.git\/(?:hooks|config)/, label: 'Git フック・設定' },
  { re: /(?:^|\/)\.git(?:\/\*\*)?$/, label: 'Git ディレクトリ' },
  { re: /(?:^|\/)\.(?:bashrc|zshrc|profile|bash_profile|zprofile|zshenv)$/, label: 'シェルの起動ファイル' },
  { re: /(?:^|\/)\.ssh(?:\/|$)/, label: 'SSH の鍵・設定' },
];

const SENSITIVE_READ = [
  { re: /(?:^|\/)\.ssh(?:\/|$)/, label: 'SSH の鍵' },
  { re: /(?:^|\/)\.aws(?:\/|$)/, label: 'AWS の認証情報' },
  { re: /(?:^|\/)\.env(?:\.[\w.-]+)?$/, label: '.env ファイル' },
  { re: /(?:^|\/)\.gnupg(?:\/|$)/, label: 'GPG の鍵' },
];

export const r005: SecurityRule = {
  ...rule,
  description: 'ファイルの読み書きをマシン全体・ホーム全体に広げる設定や、権限設定そのものを書き換えられる設定を検出します。',
  check(ctx) {
    const out: Finding[] = [];
    const rec = 'Edit(/src/**) のように、作業に必要なディレクトリだけに限定してください。秘密情報を含むパスは Read の deny ルールに入れてください。';

    for (const r of ctx.rules) {
      if (r.agent !== 'claude-code' || r.effect !== 'allow') continue;
      if (r.category !== 'file-write' && r.category !== 'file-read') continue;
      const write = r.category === 'file-write';
      const spec = r.specifier?.trim();
      const base = { agent: r.agent, file: r.source.file, pointer: r.source.pointer, evidence: redactIfSecret(r.raw) };
      let level: RiskLevel | undefined;
      let reason = '';

      if (spec === undefined || spec === '') {
        level = write ? 'HIGH' : 'MEDIUM';
        reason = write
          ? `${r.tool} がパスの限定なしで許可されており、作業ディレクトリ外を含むファイルの書き換えが承認なしで行えます`
          : `${r.tool} がパスの限定なしで許可されており、作業ディレクトリ外のファイルも承認なしで読めます`;
      } else if (isMachineWide(spec)) {
        level = write ? 'HIGH' : 'MEDIUM';
        reason = `「${spec}」はファイルシステム全体またはホームディレクトリ全体を指します`;
      } else if (write && isProjectWide(spec)) {
        level = 'LOW';
        reason = `「${spec}」は作業ディレクトリ内のすべてのファイル（設定ファイルを含む）の書き換えを許可します`;
      } else {
        const list = write ? SENSITIVE_WRITE : SENSITIVE_READ;
        const hit = list.find((x) => x.re.test(spec.replace(/\\/g, '/').replace(/\/\*\*$|\/\*$/, '')));
        if (hit) {
          level = 'MEDIUM';
          reason = write
            ? `${hit.label}の書き換えを承認なしで許可しています。権限設定や自動実行される処理を変更される可能性があります`
            : `${hit.label}の読み取りを承認なしで許可しています`;
        }
      }
      if (level) out.push(finding(rule, { ...base, level, reason, recommendation: rec }));
    }

    for (const s of ctx.settings) {
      if (s.agent !== 'claude-code' || s.key !== 'permissions.additionalDirectories') continue;
      const v = s.value.trim().replace(/\\/g, '/').replace(/\/+$/, '');
      if (v === '' || v === '/' || v === '~' || /^[a-zA-Z]:$/.test(v) || v === '//') {
        out.push(finding(rule, {
          level: 'MEDIUM',
          agent: s.agent,
          reason: `作業ディレクトリとして「${s.value}」が追加されており、ファイルシステム全体またはホーム全体が操作対象になります`,
          file: s.source.file,
          pointer: s.source.pointer,
          evidence: s.value,
          recommendation: '必要なディレクトリだけを additionalDirectories に追加してください。',
        }));
      }
    }
    return out;
  },
};
