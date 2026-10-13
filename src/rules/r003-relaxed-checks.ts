import type { Finding } from '../types.js';
import { finding, type SecurityRule } from './types.js';

const rule = { id: 'R003', title: '権限チェックを大幅に緩和する設定' };

// project / local の設定ファイルからは bypassPermissions と auto が効かない（Claude Code v2.1.257 以降）
const PROJECT_MODE_NOTE = 'なお Claude Code v2.1.257 以降、この値はプロジェクト・ローカル設定からは適用されませんが、それ以前のバージョンでは有効です。';

export const r003: SecurityRule = {
  ...rule,
  description: '権限確認を省略するモードや、その確認ダイアログを省略する設定を検出します。',
  check(ctx) {
    const out: Finding[] = [];
    for (const s of ctx.settings) {
      if (s.agent !== 'claude-code') continue;
      const base = { agent: s.agent, file: s.source.file, pointer: s.source.pointer, evidence: `${s.key}: ${s.value}` };
      const projectScoped = s.scope !== 'user';

      if (s.key === 'permissions.defaultMode') {
        if (s.value === 'bypassPermissions') {
          out.push(finding(rule, {
            ...base,
            level: projectScoped ? 'MEDIUM' : 'HIGH',
            reason: `既定の権限モードが bypassPermissions で、ほぼすべての権限確認が省略されます。${projectScoped ? PROJECT_MODE_NOTE : ''}`,
            recommendation: '既定モードは default（Manual）にし、bypassPermissions はコンテナや VM など隔離環境でのみ一時的に使ってください。',
          }));
        } else if (s.value === 'auto') {
          out.push(finding(rule, {
            ...base,
            level: 'LOW',
            reason: `既定の権限モードが auto で、人による確認の代わりに分類器が実行可否を判断します。${projectScoped ? PROJECT_MODE_NOTE : ''}`,
            recommendation: '分類器の判断に任せたくない操作は ask または deny ルールに入れてください。',
          }));
        } else if (s.value === 'acceptEdits') {
          out.push(finding(rule, {
            ...base,
            level: 'LOW',
            reason: '既定の権限モードが acceptEdits で、作業ディレクトリ内のファイル編集と一部のファイル操作コマンドが確認なしで実行されます。',
            recommendation: '編集を確認したい場合は既定モードを default にしてください。',
          }));
        }
      }

      if (s.key === 'skipDangerousModePermissionPrompt' && s.value === 'true') {
        out.push(finding(rule, {
          ...base,
          level: 'MEDIUM',
          reason: 'bypassPermissions モードに入る前の確認ダイアログが表示されません。',
          recommendation: 'skipDangerousModePermissionPrompt を削除し、危険なモードへの切り替え時に確認が出るようにしてください。',
        }));
      }

      if (s.key === 'sandbox.filesystem.disabled' && s.value === 'true') {
        out.push(finding(rule, {
          ...base,
          level: 'LOW',
          reason: 'サンドボックスのファイルシステム隔離が無効になっています（ネットワーク隔離のみ有効）。',
          recommendation: 'ファイルシステム隔離が必要ない理由がなければ、この設定を削除してください。',
        }));
      }
    }
    return out;
  },
};
