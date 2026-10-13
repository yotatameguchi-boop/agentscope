import { tx } from '../i18n.js';
import type { Finding } from '../types.js';
import { finding, type SecurityRule } from './types.js';

const rule = { id: 'R003', title: tx('権限チェックを大幅に緩和する設定', 'Permission checks are significantly relaxed') };

// project / local の設定ファイルからは bypassPermissions と auto が効かない（Claude Code v2.1.257 以降）
const PROJECT_MODE_NOTE = tx(
  'なお Claude Code v2.1.257 以降、この値はプロジェクト・ローカル設定からは適用されませんが、それ以前のバージョンでは有効です。',
  'Since Claude Code v2.1.257 this value is not applied from project or local settings, but it takes effect in earlier versions.',
);

export const r003: SecurityRule = {
  ...rule,
  description: tx(
    '権限確認を省略するモードや、その確認ダイアログを省略する設定を検出します。',
    'Detects modes that skip permission prompts and settings that skip the confirmation for such modes.',
  ),
  check(ctx) {
    const out: Finding[] = [];
    for (const s of ctx.settings) {
      if (s.agent !== 'claude-code' || typeof s.value !== 'string') continue;
      const base = { agent: s.agent, file: s.source.file, pointer: s.source.pointer, evidence: `${s.key}: ${s.value}` };
      const note = s.scope !== 'user' ? PROJECT_MODE_NOTE : tx('', '');

      if (s.key === 'permissions.defaultMode') {
        if (s.value === 'bypassPermissions') {
          out.push(finding(rule, {
            ...base,
            level: s.scope !== 'user' ? 'MEDIUM' : 'HIGH',
            reason: tx(
              `既定の権限モードが bypassPermissions で、ほぼすべての権限確認が省略されます。${note.ja}`,
              `The default permission mode is bypassPermissions, which skips almost every permission prompt.${note.en ? ' ' + note.en : ''}`,
            ),
            recommendation: tx(
              '既定モードは default（Manual）にし、bypassPermissions はコンテナや VM など隔離環境でのみ一時的に使ってください。',
              'Use default (Manual) as the default mode, and use bypassPermissions only temporarily in isolated environments such as containers or VMs.',
            ),
          }));
        } else if (s.value === 'auto') {
          out.push(finding(rule, {
            ...base,
            level: 'LOW',
            reason: tx(
              `既定の権限モードが auto で、人による確認の代わりに分類器が実行可否を判断します。${note.ja}`,
              `The default permission mode is auto, so a classifier decides instead of a human.${note.en ? ' ' + note.en : ''}`,
            ),
            recommendation: tx(
              '分類器の判断に任せたくない操作は ask または deny ルールに入れてください。',
              'Put operations you do not want left to the classifier in ask or deny rules.',
            ),
          }));
        } else if (s.value === 'acceptEdits') {
          out.push(finding(rule, {
            ...base,
            level: 'LOW',
            reason: tx(
              '既定の権限モードが acceptEdits で、作業ディレクトリ内のファイル編集と一部のファイル操作コマンドが確認なしで実行されます。',
              'The default permission mode is acceptEdits, so file edits and some filesystem commands in the working directory run without confirmation.',
            ),
            recommendation: tx('編集を確認したい場合は既定モードを default にしてください。', 'Set the default mode to default if you want to review edits.'),
          }));
        }
      }

      if (s.key === 'skipDangerousModePermissionPrompt' && s.value === 'true') {
        out.push(finding(rule, {
          ...base,
          level: 'MEDIUM',
          reason: tx('bypassPermissions モードに入る前の確認ダイアログが表示されません。', 'The confirmation dialog before entering bypassPermissions mode is not shown.'),
          recommendation: tx(
            'skipDangerousModePermissionPrompt を削除し、危険なモードへの切り替え時に確認が出るようにしてください。',
            'Remove skipDangerousModePermissionPrompt so that switching to a dangerous mode asks for confirmation.',
          ),
        }));
      }

      if (s.key === 'sandbox.filesystem.disabled' && s.value === 'true') {
        out.push(finding(rule, {
          ...base,
          level: 'LOW',
          reason: tx(
            'サンドボックスのファイルシステム隔離が無効になっています（ネットワーク隔離のみ有効）。',
            'Filesystem isolation of the sandbox is disabled (only network isolation is active).',
          ),
          recommendation: tx(
            'ファイルシステム隔離が必要ない理由がなければ、この設定を削除してください。',
            'Remove this setting unless you have a reason not to isolate the filesystem.',
          ),
        }));
      }
    }
    return out;
  },
};
