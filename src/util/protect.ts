import { isText } from '../i18n.js';
import { isReferenceOrPlaceholder, isUrlPasswordPlaceholder, safeDecode, SECRET_KEY_RE, VALUE_PATTERNS } from './secrets.js';

/**
 * 出力保護。秘密情報の「検出」（secrets.ts、R004 の材料）とは分け、出力する直前に必ず通す最後の防御として使う。
 *
 * 文字列の中から秘密情報らしい部分だけを [REDACTED] に置き換える。文字列全体は消さないので、
 * どの設定・どの位置の話かは読める。パーサーや検査ルールが個別に伏せ忘れても、ここで止める。
 */

const MASK = '[REDACTED]';

const GLOBAL_PATTERNS = VALUE_PATTERNS.map((p) => new RegExp(p.re.source, p.re.flags.includes('g') ? p.re.flags : `${p.re.flags}g`));

/** ゼロ幅スペース・単語結合子・BOM など、表示されない文字 */
const INVISIBLE_CHAR = /[\u200b-\u200d\u2060\ufeff\u00ad]/;
const INVISIBLE_ALL = /[\u200b-\u200d\u2060\ufeff\u00ad]/g;

/**
 * 見えない文字を値の途中に挟むと判定から外れるため、取り除いた形でも判定する。
 * 取り除いた形で伏せる箇所があればその結果を返し（見えない文字は出力から消える）、なければ元の文字列のまま判定する
 */
function withVisibleCheck(input: string, mask: (s: string) => string): string {
  if (!INVISIBLE_CHAR.test(input)) return mask(input);
  const visible = input.replace(INVISIBLE_ALL, '');
  const masked = mask(visible);
  return masked === visible ? mask(input) : masked;
}

export function maskSecrets(input: string): string {
  return withVisibleCheck(input, maskVisible);
}

function maskVisible(input: string): string {
  let s = input;
  // 1. 既知の形式（sk-ant-、ghp_、AKIA など）
  for (const re of GLOBAL_PATTERNS) s = s.replace(re, MASK);
  // 2. URL のユーザー情報（scheme://user:pass@）
  //    ユーザー名に : を含めないことで区切り位置を一意にし、@ のない長い URL でも線形時間で終える
  //    スキームは英数字の直後からは始まらない（各位置から照合し直して二乗の時間になるのを防ぐ）
  //    パスワードに / は含めない（http://localhost:3000/@react-refresh をユーザー情報と誤認しないため）。
  //    長さに上限を設け、@ のない入力で各位置から最後まで読み直さないようにする
  s = s.replace(/(?<![a-z0-9+.-])([a-z][a-z0-9+.-]*:\/\/)([^\s/@'":]{0,256}):([^\s/@'"]{0,256})@/gi, (m, scheme, user, pass) =>
    isUrlPasswordPlaceholder(safeDecode(pass)) ? m : `${scheme}${MASK}@`,
  );
  // 3. URL のクエリやフラグ・代入の形の秘密情報（?token=..., API_KEY=..., password: ..., --token ...）
  //    キー名の前は「--」（--api-key=値）、後ろは引用符（"api_key": "値"）でもよい
  //    値が ${...} の参照なら、入れ子（${A:-${B}}、${{ secrets.X }}）も含めて1つの値として扱う
  s = s.replace(/((?:^|[?&;\s'"(,]|(?<!\$)\{|--))((?:export\s+)?([A-Za-z_][\w.]*(?:-[\w.]+)*)['"]?\s*[=:]\s*)(['"]?)(\$\{(?:[^{}\n]|\{[^{}\n]*\})*\}|[^\s'";&|)?#,]+)\4/g, (m, pre, assign, key, q, value, offset: number, whole: string) =>
    SECRET_KEY_RE.test(key) && !isReferenceOrPlaceholder(value) && !isBadgeToken(whole, offset) ? `${pre}${assign}${q}${MASK}${q}` : m,
  );
  s = s.replace(/(^|\s)(--?([A-Za-z][\w-]*)\s+)(['"]?)([^\s'"-][^\s'"]*)\4/g, (m, pre, flag, key, q, value) =>
    SECRET_KEY_RE.test(key) && !isReferenceOrPlaceholder(value) ? `${pre}${flag}${q}${MASK}${q}` : m,
  );
  // 4. ランダム性の高い長い文字列（形式に特徴のないトークン）。大文字・小文字・数字をすべて含み、
  //    1文字あたりのエントロピーが高いものだけを対象にする（16進のハッシュや UUID、パスは対象外）
  //    公開鍵・証明書のブロックの中は対象にしない
  s = outsidePublicBlocks(s, (part) =>
    // = は base64 の末尾の詰め物としてだけ含める（KEY=値 をキー名ごと1つのトークンにしないため）
    part.replace(/[A-Za-z0-9+/_-]{16,}={0,2}/g, (token: string, offset: number, whole: string) => {
      if (isPublicToken(token, whole.slice(Math.max(0, offset - CONTEXT_LOOKBACK), offset), urlPrefixBefore(whole, offset))) return token;
      // URL の中や、単語が大半を占めるパス（/private/var/folders/…/T/agentscope-test-Ab3dE5/…）は、/ の区切りごとに判定する。
      // 単語をほとんど含まない / 入りの値（AWS のシークレットキーや base64）は、全体を1つの値として判定する
      if (token.includes('/') && (looksLikePath(token) || inUrlBefore(whole, offset))) {
        return token.split('/').map((seg) => (looksRandom(seg) ? MASK : seg)).join('/');
      }
      return looksRandom(token) ? MASK : token;
    }),
  );
  // 5. curl -u user:pass
  s = s.replace(/(^|\s)(-u|--user)(\s+)(['"]?)([^\s:'"]+):([^\s'"`]+)\4/g, (m, pre, flag, sp, q, user, pass) =>
    /^\$\{?[A-Za-z_][\w:]*\}?$/.test(pass) || /^(?:pass(?:word)?|secret|x+|\*+|<[^>]*>?)$/i.test(pass) ? m : `${pre}${flag}${sp}${q}${user}:${MASK}${q}`,
  );
  return s;
}

/** codecov などのバッジ画像の URL に付く token（公開する前提の値） */
function isBadgeToken(whole: string, offset: number): boolean {
  const before = whole.slice(Math.max(0, offset - 200), offset + 1);
  return /https?:\/\/(?:codecov\.io|app\.codecov\.io)\/\S*\/(?:graph\/)?badge\.svg$/i.test(before.replace(/\?$/, ''));
}

/** トークンの直前の文脈として見る長さ */
const CONTEXT_LOOKBACK = 64;

/** 公開鍵・証明書のブロック。中身は公開情報なので、ランダム性による伏せ字の対象にしない */
const PUBLIC_BLOCK = /-----BEGIN (?:CERTIFICATE|TRUSTED CERTIFICATE|CERTIFICATE REQUEST|X509 CRL|PUBLIC KEY|RSA PUBLIC KEY|PGP PUBLIC KEY BLOCK|PGP SIGNATURE|SSH2 PUBLIC KEY)-----[\s\S]*?-----END [A-Z0-9 ]+-----/g;

function outsidePublicBlocks(s: string, f: (part: string) => string): string {
  if (!s.includes('-----BEGIN ')) return f(s);
  let out = '';
  let last = 0;
  for (const m of s.matchAll(PUBLIC_BLOCK)) {
    out += f(s.slice(last, m.index)) + m[0];
    last = m.index! + m[0].length;
  }
  return out + f(s.slice(last));
}

/**
 * 秘密ではないと分かるトークン。値そのものの形（接頭辞）と、直前の文脈（キー名・ハッシュの種類）で判定する。
 * ここで残しても、形式に特徴のある秘密情報（sk_live_ など）は 1 の段階で、キー名のある値は 3 の段階で伏せている
 */
function isPublicToken(token: string, before: string, urlPrefix: string): boolean {
  // ハッシュ・ダイジェスト（sha512-…、h1:…、SHA256:…、sha256:…）。接頭辞がトークンに含まれる場合もある
  if (/(?:sha(?:1|224|256|384|512)[-:]|h1:|md5[-:])$/i.test(before) || /^(?:sha(?:1|224|256|384|512)|md5)-/i.test(token)) return true;
  // SSH の公開鍵（ssh-ed25519 AAAA…）
  if (/(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d+|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)\s+$/.test(before) && token.startsWith('AAAA')) return true;
  // data URI の中身（data:image/svg+xml;base64,…、sourceMappingURL=data:application/json;base64,…）
  if (/;base64,$/.test(before)) return true;
  // 公開コンテンツの URL のパス・クエリ（YouTube の動画・再生リスト、GitHub、npm、Wikipedia、バッジ）
  if (PUBLIC_CONTENT_URL.test(urlPrefix)) return true;
  // Ethereum のアドレス（公開情報）
  if (/^0x[0-9a-fA-F]{40}$/.test(token)) return true;
  // HTTP の ETag（W/"…"）
  if (/W\/"$/.test(before)) return true;
  // 公開情報を入れるキーの値（JWK の n / e / x / y / kid、integrity、checksum、fingerprint、公開鍵、証明書など）
  // 1 文字のキー（JWK の n / e / x / y）は、引用符で囲まれた JSON のキーのときだけ
  if (/"(?:n|e|x|y|kid|x5t(?:#S256)?|x5c)"\s*:\s*"?\[?\s*"?$/.test(before)) return true;
  if (/(?:^|[\s{,"'])(?:integrity|checksum|digest|hash|sha\d*|etag|fingerprint|thumbprint|public_?key|publicKey|pubkey|cert(?:ificate)?|nonce|commit|revision|build_?id)["']?\s*[:=]\s*["']?\[?\s*["']?$/i.test(before)) return true;
  // 公開してよいキー・オブジェクト ID の接頭辞（Stripe の pk_live_ / cus_ / price_、Vercel の prj_ など）
  if (/^(?:pk_(?:live|test)_|(?:cus|price|prod|pi|sub|si|in|ii|il|ch|pm|seti|evt|acct|txn|re|po|ba|card|src|plan|pyr|py|tr|or|sku|cs_test|cs_live|prj|team|dpl)_)/.test(token)) return true;
  // 公式ドキュメントの例の値（AKIAIOSFODNN7EXAMPLE、wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY）
  if (/EXAMPLE(?:KEY)?$/.test(token)) return true;
  return false;
}

/** 公開コンテンツのサイトの URL の途中にいるか（空白を含まない直前の文脈で判定） */
const PUBLIC_CONTENT_URL = /^https?:\/\/(?:www\.|m\.)?(?:youtube\.com|youtu\.be|github\.com|gitlab\.com|raw\.githubusercontent\.com|npmjs\.com|www\.npmjs\.com|[a-z]{2,3}\.wikipedia\.org|upload\.wikimedia\.org|img\.shields\.io|badgen\.net|badge\.fury\.io|codecov\.io|coveralls\.io|pkg\.go\.dev|crates\.io|pypi\.org)\//i;

/** URL をさかのぼって調べる最大の長さ。トークンごとに先頭まで戻ると、長い入力で二乗の時間になる */
const URL_LOOKBACK = 4096;

/** offset の直前の、空白を含まない部分（最大 URL_LOOKBACK 文字） */
function urlPrefixBefore(whole: string, offset: number): string {
  const limit = Math.max(0, offset - URL_LOOKBACK);
  let start = offset;
  while (start > limit && !/[\s<>"'`()[\]]/.test(whole[start - 1]!)) start--;
  return whole.slice(start, offset);
}

/** offset の直前（空白まで、最大 URL_LOOKBACK 文字）に "://" があれば、URL の中とみなす */
function inUrlBefore(whole: string, offset: number): boolean {
  return urlPrefixBefore(whole, offset).includes('://');
}

/** / で区切った断片を、さらに - _ . で分けたとき、単語（2 文字以上の英小文字、先頭だけ大文字の単語）が文字数の 4 割以上を占めるか */
export function looksLikePath(token: string): boolean {
  const pieces = token.split(/[/\-_.]/).filter(Boolean);
  const total = pieces.reduce((n, p) => n + p.length, 0);
  if (total === 0) return false;
  const wordy = pieces.filter((p) => /^[A-Z]?[a-z]{2,}$/.test(p)).reduce((n, p) => n + p.length, 0);
  return wordy / total >= 0.4;
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
  const core = token.replace(/^[/=_-]+|[/=_-]+$/g, '');
  if (core.length < 16) return false;
  // 大文字・小文字・数字をすべて含むこと（16進のハッシュ、UUID、小文字だけの名前を除く）
  if (!/[a-z]/.test(core) || !/[A-Z]/.test(core) || !/[0-9]/.test(core)) return false;
  // 単語や数字を - / _ でつないだ名前（Miejscu-pracy-koparka-3741、Release_2024_Final、Users/Someone/Projects）は除く。
  // 各区切りが「先頭だけ大文字の単語」「全部大文字」「数字だけ」のどれかなら人が付けた名前とみなす
  if (core.split(/[-_/]/).every((seg) => /^(?:[A-Z]?[a-z]*|[A-Z]+|[0-9]+)$/.test(seg))) return false;
  // キャメルケースの名前（MyVeryLongServerName2024）は、単語・数字の区切りが少なく1つ1つが長い。
  // ランダムな文字列は大文字・小文字・数字が頻繁に入れ替わり、区切りが短くなる
  const words = core.replace(/[-_+=/]/g, '').match(/[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+/g) ?? [];
  if (words.length > 0 && core.length / words.length >= 4) return false;
  // 発音できる単語（3 文字以上で母音を含む）と数字の並びが大半を占める名前（XChaCha20-Poly1305、fromBase58checkSync、readUInt32LE）。
  // ランダムな文字列は大文字・小文字が細かく入れ替わり、3 文字以上の単語がほとんどできない
  //   数字は 4 桁以下の並び（バージョン番号など）だけ、単語は a〜f だけでできたもの（16 進の一部）を除いて数える
  const pronounceable = words
    .filter((w) => /^[0-9]{1,5}$/.test(w) || (w.length >= 3 && /[aeiouyAEIOUY]/.test(w) && !/^[a-fA-F]+$/.test(w)))
    .reduce((n, w) => n + w.length, 0);
  if (pronounceable / core.replace(/[-_+=/]/g, '').length >= 0.75) return false;
  // 短い文字列ほど、ランダムでもエントロピーの上限（log2 長さ）が低いため、長さに応じて閾値を下げる
  return entropy(core) >= Math.min(4.0, Math.log2(core.length) - 0.8);
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
  const mask = (str: string) => withVisibleCheck(str, (v) => maskVisible(maskKnown(v, known)));
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
