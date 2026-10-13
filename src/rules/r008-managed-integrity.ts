import { tx } from '../i18n.js';
import type { Finding } from '../types.js';
import { finding, type SecurityRule } from './types.js';

const rule = { id: 'R008', title: tx('組織の管理設定が正しく適用されない', 'Organization-managed settings are not applied correctly') };

/**
 * 管理設定の不備を検出する。https://code.claude.com/docs/en/managed-settings
 * - 厳密な JSON でない、または壊れた plist → Claude Code は起動を拒否する（利用できなくなる）
 * - OS の権限で読めない → そのユーザーのセッションは管理設定なしで起動する（制限がかからない）
 */
export const r008: SecurityRule = {
  ...rule,
  description: tx(
    '管理設定のファイルや構成プロファイルが壊れていて Claude Code が起動しない状態や、読めないため制限がかからない状態を検出します。',
    'Detects managed settings files or profiles that are broken (Claude Code refuses to start) or unreadable (the policy is not enforced).',
  ),
  check(ctx) {
    const out: Finding[] = [];
    for (const f of ctx.files) {
      if (!f.managedIssue) continue;
      const notApplied = f.managedIssue.kind === 'not-applied';
      out.push(finding(rule, {
        level: notApplied ? 'MEDIUM' : 'LOW',
        agent: f.agent,
        reason: f.managedIssue.reason,
        file: f.displayPath,
        pointer: '(file)',
        recommendation: notApplied
          ? tx(
              '管理設定のファイルを、Claude Code を使う利用者が読めるアクセス権にしてください（書き込みは管理者だけに限ってください）。',
              'Make the managed settings file readable by the users who run Claude Code (keep write access limited to administrators).',
            )
          : tx(
              'ファイルを厳密な JSON（コメント・末尾カンマなし、トップレベルはオブジェクト）に直してください。`claude doctor` でも確認できます。',
              'Fix the file so it is strict JSON (no comments or trailing commas, with an object at the top level). You can also check it with `claude doctor`.',
            ),
      }));
    }
    return out;
  },
};
