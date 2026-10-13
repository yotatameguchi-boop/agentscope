import type { Finding } from '../types.js';
import { finding, type SecurityRule } from './types.js';

const rule = { id: 'R004', title: '設定ファイルに認証情報らしき文字列が直接書かれている' };

export const r004: SecurityRule = {
  ...rule,
  description: 'APIキーやトークンなどが設定ファイルに平文で書かれていないかを、既知の形式とキー名から推定します。値は表示しません。',
  check(ctx) {
    const out: Finding[] = [];
    for (const h of ctx.secretHits) {
      const file = ctx.files.find((f) => f.displayPath === h.file);
      const shared = file?.scope === 'project';
      const strong = h.kind === 'value-pattern' || h.kind === 'url-credential';
      out.push(finding(rule, {
        level: strong ? 'HIGH' : 'MEDIUM',
        agent: h.agent,
        reason:
          (h.kind === 'key-name'
            ? `${h.label}に、参照（\${VAR} など）ではない値が直接書かれており、認証情報の可能性があります（値は表示しません）。`
            : `${h.label}と思われる値が直接書かれています（値は表示しません）。`) +
          (shared ? 'このファイルはリポジトリで共有される場所にあるため、コミットされると漏えいにつながります。' : ''),
        file: h.file,
        pointer: h.pointer,
        evidence: `${h.pointer}: [REDACTED]`,
        recommendation:
          '値を環境変数やシークレットマネージャーに移し、設定では ${VAR} などの参照だけを書いてください。すでに共有・コミットした場合は、そのキーを失効させて再発行してください。',
      }));
    }
    return out;
  },
};
