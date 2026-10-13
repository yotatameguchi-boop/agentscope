import { ENV_CATALOG } from '../env/catalog.js';
import { tx } from '../i18n.js';
import type { Finding } from '../types.js';
import { finding, type SecurityRule } from './types.js';

const rule = { id: 'R007', title: tx('安全機能や通信先を変える環境変数', 'Environment variables that change safety checks or endpoints') };

/**
 * 環境変数による安全機能の無効化や、API 通信先の変更を検出する。
 * 判定内容は env/catalog.ts の各変数の risk に定義する。
 */
export const r007: SecurityRule = {
  ...rule,
  description: tx(
    'TLS 検証の無効化、削除の安全チェックの無効化、Node.js へのコード読み込み、API 通信先の変更など、環境変数による設定を検出します。',
    'Detects environment variables that turn off TLS verification or removal safety checks, load code into Node.js, or change the API endpoint.',
  ),
  check(ctx) {
    const out: Finding[] = [];
    for (const s of ctx.settings) {
      if (!s.key.startsWith('env.') || typeof s.value !== 'string') continue;
      const name = s.key.slice('env.'.length);
      const risk = ENV_CATALOG[name]?.risk?.(s.value, { projectShared: s.scope === 'project' });
      if (!risk) continue;
      out.push(finding(rule, {
        level: risk.level,
        agent: s.agent,
        reason: risk.reason,
        file: s.source.file,
        pointer: s.source.pointer,
        evidence: `${name}=${s.value}`,
        recommendation: risk.recommendation,
      }));
    }
    return out;
  },
};
