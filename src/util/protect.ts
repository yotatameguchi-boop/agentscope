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
  // 4. ランダム性の高い長い文字列（形式に特徴のないトークン）。大文字・小文字・数字をすべて含み、
  //    1文字あたりのエントロピーが高いものだけを対象にする（16進のハッシュや UUID、パスは対象外）
  s = s.replace(/[A-Za-z0-9+_=-]{24,}/g, (m) => (looksRandom(m) ? MASK : m));
  // 5. curl -u user:pass
  s = s.replace(/(^|\s)(-u|--user)(\s+)(['"]?)([^\s:'"]+):([^\s'"]+)\4/g, (m, pre, flag, sp, q, user, pass) =>
    /^\$\{?[A-Za-z_][\w:]*\}?$/.test(pass) ? m : `${pre}${flag}${sp}${q}${user}:${MASK}${q}`,
  );
  return s;
}

/** 1文字あたりのシャノンエントロピー（ビット） */
function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function looksRandom(token: string): boolean {
  // 大文字・小文字・数字をすべて含むこと（16進のハッシュ、UUID、小文字だけの名前を除く）
  if (!/[a-z]/.test(token) || !/[A-Z]/.test(token) || !/[0-9]/.test(token)) return false;
  // 単語や数字を - / _ でつないだ名前（Miejscu-pracy-koparka-3741、Release_2024_Final）は除く。
  // 各区切りが「先頭だけ大文字の単語」「全部大文字」「数字だけ」のどれかなら人が付けた名前とみなす
  if (token.split(/[-_]/).every((seg) => /^(?:[A-Z]?[a-z]*|[A-Z]+|[0-9]+)$/.test(seg))) return false;
  // キャメルケースの名前（MyVeryLongServerName2024）は、単語・数字の区切りが少なく1つ1つが長い。
  // ランダムな文字列は大文字・小文字・数字が頻繁に入れ替わり、区切りが短くなる
  const words = token.replace(/[-_+=]/g, '').match(/[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+/g) ?? [];
  if (words.length > 0 && token.length / words.length >= 4) return false;
  return entropy(token) >= 4.0;
}

/** 保管庫にある値（検出時に秘密情報と判定した値）を伏せる。長いものから順に置き換える */
function maskKnown(s: string, known: readonly string[]): string {
  let out = s;
  for (const v of known) {
    if (out.includes(v)) out = out.split(v).join(MASK);
    const encoded = encodeURIComponent(v);
    if (encoded !== v && out.includes(encoded)) out = out.split(encoded).join(MASK);
  }
  return out;
}

/**
 * 値をたどり、すべての文字列（日英の文言を含む）に出力保護を適用した複製を返す。
 * vault には、スキャン中に秘密情報と判定した値を渡す（形式に特徴のない値もこれで伏せられる）
 */
export function protectOutput<T>(value: T, vault: Iterable<string> = []): T {
  const known = [...new Set(vault)].sort((a, b) => b.length - a.length);
  const mask = (str: string) => maskSecrets(maskKnown(str, known));
  const visit = (v: unknown, depth: number): unknown => {
    if (typeof v === 'string') return mask(v);
    if (depth > 64) return v;
    if (Array.isArray(v)) return v.map((x) => visit(x, depth + 1));
    if (isText(v)) return { ja: mask(v.ja), en: mask(v.en) };
    if (typeof v === 'object' && v !== null) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, visit(x, depth + 1)]));
    return v;
  };
  return visit(value, 0) as T;
}
