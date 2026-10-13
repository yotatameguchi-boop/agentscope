import { isText } from '../i18n.js';
import { isReferenceOrPlaceholder, SECRET_KEY_RE, VALUE_PATTERNS } from './secrets.js';

/**
 * 出力保護。秘密情報の「検出」（secrets.ts、R004 の材料）とは分け、出力する直前に必ず通す最後の防御として使う。
 *
 * 文字列の中から秘密情報らしい部分だけを [REDACTED] に置き換える。文字列全体は消さないので、
 * どの設定・どの位置の話かは読める。パーサーや検査ルールが個別に伏せ忘れても、ここで止める。
 */

const MASK = '[REDACTED]';

const GLOBAL_PATTERNS = VALUE_PATTERNS.map((p) => new RegExp(p.re.source, p.re.flags.includes('g') ? p.re.flags : `${p.re.flags}g`));

export function maskSecrets(input: string): string {
  let s = input;
  // 1. 既知の形式（sk-ant-、ghp_、AKIA など）
  for (const re of GLOBAL_PATTERNS) s = s.replace(re, MASK);
  // 2. URL のユーザー情報（scheme://user:pass@）
  s = s.replace(/([a-z][a-z0-9+.-]*:\/\/)([^\s/@'"]*:[^\s/@'"]*)@/gi, `$1${MASK}@`);
  // 3. URL のクエリやフラグ・代入の形の秘密情報（?token=..., API_KEY=..., password: ..., --token ...）
  s = s.replace(/([?&;\s'"(,]|^)((?:export\s+)?([A-Za-z_][\w.-]*)\s*[=:]\s*)(['"]?)([^\s'";&|)?#]+)\4/g, (m, pre, assign, key, q, value) =>
    SECRET_KEY_RE.test(key) && !isReferenceOrPlaceholder(value) ? `${pre}${assign}${q}${MASK}${q}` : m,
  );
  s = s.replace(/(^|\s)(--?([A-Za-z][\w-]*)\s+)(['"]?)([^\s'"-][^\s'"]*)\4/g, (m, pre, flag, key, q, value) =>
    SECRET_KEY_RE.test(key) && !isReferenceOrPlaceholder(value) ? `${pre}${flag}${q}${MASK}${q}` : m,
  );
  // 4. curl -u user:pass
  s = s.replace(/(^|\s)(-u|--user)(\s+)(['"]?)([^\s:'"]+):([^\s'"]+)\4/g, (m, pre, flag, sp, q, user, pass) =>
    /^\$\{?[A-Za-z_][\w:]*\}?$/.test(pass) ? m : `${pre}${flag}${sp}${q}${user}:${MASK}${q}`,
  );
  return s;
}

/** 値をたどり、すべての文字列（日英の文言を含む）に maskSecrets を適用した複製を返す */
export function protectOutput<T>(value: T): T {
  const visit = (v: unknown, depth: number): unknown => {
    if (typeof v === 'string') return maskSecrets(v);
    if (depth > 64) return v;
    if (Array.isArray(v)) return v.map((x) => visit(x, depth + 1));
    if (isText(v)) return { ja: maskSecrets(v.ja), en: maskSecrets(v.en) };
    if (typeof v === 'object' && v !== null) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, visit(x, depth + 1)]));
    return v;
  };
  return visit(value, 0) as T;
}
