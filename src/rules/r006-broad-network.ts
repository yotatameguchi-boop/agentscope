import { tx } from '../i18n.js';
import type { Finding } from '../types.js';
import { redactIfSecret } from '../util/secrets.js';
import { finding, type SecurityRule } from './types.js';

const rule = { id: 'R006', title: tx('任意の通信先へのアクセスを許可する設定', 'Network access to any destination is allowed') };

const REC = tx(
  '「WebFetch(domain:docs.example.com)」のように、必要なドメインだけを許可してください。',
  'Allow only the domains you need, such as "WebFetch(domain:docs.example.com)".',
);

/**
 * 通信先を限定しない許可は、読み取ったファイルの内容を URL に含めて外部へ送れる経路になる。
 * - Claude Code: WebFetch（指定なし）、WebFetch(domain:*)、sandbox.network.allowedDomains の "*"
 * - Cursor CLI: WebFetch(*)
 */
export const r006: SecurityRule = {
  ...rule,
  description: tx(
    'Web 取得やサンドボックスの通信先を限定しない設定を検出します。データの持ち出し経路になりうるためです。',
    'Detects settings that do not restrict web fetch or sandbox network destinations, since they can become an exfiltration path.',
  ),
  check(ctx) {
    const out: Finding[] = [];
    for (const r of ctx.rules) {
      if (r.effect !== 'allow' || r.category !== 'network' || r.tool !== 'WebFetch') continue;
      const spec = r.specifier?.trim();
      const any =
        spec === undefined || spec === '' || spec === '*' || (r.agent === 'claude-code' && /^domain:\s*\*$/.test(spec));
      if (!any) continue;
      out.push(finding(rule, {
        level: 'MEDIUM',
        agent: r.agent,
        reason: tx(
          'Web 取得が通信先の限定なしで承認なしに実行できます。読み取った内容を外部へ送る経路になりえます',
          'Web fetches to any destination run without approval, which can be used to send data out',
        ),
        file: r.source.file,
        pointer: r.source.pointer,
        evidence: redactIfSecret(r.raw),
        recommendation: REC,
      }));
    }
    for (const s of ctx.settings) {
      if (s.agent !== 'claude-code' || s.key !== 'sandbox.network.allowedDomains' || s.value !== '*') continue;
      out.push(finding(rule, {
        level: 'MEDIUM',
        agent: s.agent,
        reason: tx(
          'サンドボックス内のコマンドがすべてのドメインと通信できます',
          'Sandboxed commands can reach every domain',
        ),
        file: s.source.file,
        pointer: s.source.pointer,
        evidence: `${s.key}: *`,
        recommendation: tx('sandbox.network.allowedDomains には必要なドメインだけを列挙してください。', 'List only the domains you need in sandbox.network.allowedDomains.'),
      }));
    }
    return out;
  },
};
