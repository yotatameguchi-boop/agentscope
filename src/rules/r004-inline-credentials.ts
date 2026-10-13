import { tx } from '../i18n.js';
import type { Finding } from '../types.js';
import { finding, type SecurityRule } from './types.js';

const rule = {
  id: 'R004',
  title: tx('設定ファイルに認証情報らしき文字列が直接書かれている', 'Credential-like strings are written directly in a config file'),
};

export const r004: SecurityRule = {
  ...rule,
  description: tx(
    'APIキーやトークンなどが設定ファイルに平文で書かれていないかを、既知の形式とキー名から推定します。値は表示しません。',
    'Estimates from known formats and key names whether API keys or tokens are written in plain text. Values are never shown.',
  ),
  check(ctx) {
    const out: Finding[] = [];
    for (const h of ctx.secretHits) {
      const file = ctx.files.find((f) => f.displayPath === h.file);
      const shared = file?.scope === 'project';
      const strong = h.kind === 'value-pattern' || h.kind === 'url-credential';
      const main =
        h.kind === 'key-name'
          ? tx(
              `${h.label.ja}に、参照（\${VAR} など）ではない値が直接書かれており、認証情報の可能性があります（値は表示しません）。`,
              `${h.label.en} holds a literal value rather than a reference such as \${VAR}; it may be a credential (value not shown).`,
            )
          : tx(
              `${h.label.ja}と思われる値が直接書かれています（値は表示しません）。`,
              `What appears to be ${h.label.en} is written directly (value not shown).`,
            );
      const sharedNote = shared
        ? tx(
            'このファイルはリポジトリで共有される場所にあるため、コミットされると漏えいにつながります。',
            ' This file is in a location shared through the repository, so committing it would leak the value.',
          )
        : tx('', '');
      out.push(finding(rule, {
        level: strong ? 'HIGH' : 'MEDIUM',
        agent: h.agent,
        reason: tx(main.ja + sharedNote.ja, main.en + sharedNote.en),
        file: h.file,
        pointer: h.pointer,
        evidence: `${h.pointer}: [REDACTED]`,
        recommendation: tx(
          '値を環境変数やシークレットマネージャーに移し、設定では ${VAR} などの参照だけを書いてください。すでに共有・コミットした場合は、そのキーを失効させて再発行してください。',
          'Move the value to an environment variable or a secret manager and reference it (for example ${VAR}) in the config. If it was already shared or committed, revoke and reissue the key.',
        ),
      }));
    }
    return out;
  },
};
