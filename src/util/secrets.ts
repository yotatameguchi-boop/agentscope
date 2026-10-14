import { tx, type Text } from '../i18n.js';
import type { AgentId, SecretHit } from '../types.js';
import { isPlainObject } from './jsonc.js';
import { joinPointer } from './pointer.js';
import { rememberSecret } from './vault.js';

/**
 * 設定ファイル内に直接書かれた認証情報らしき文字列を探す（R004 の材料）。
 * 検出結果には値そのもの・値の一部・長さを一切含めない。
 */

interface ValuePattern {
  label: Text;
  re: RegExp;
}

// 既知の形式。誤検知を抑えるため、プレフィックスと十分な長さの両方を要求する。
// 先頭は \b ではなく英数字以外を条件にする（mcp__xoxb-... のように _ の直後でも検出するため）
export const VALUE_PATTERNS: ValuePattern[] = [
  { label: tx('Anthropic APIキー', 'an Anthropic API key'), re: /(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,}/ },
  { label: tx('OpenAI APIキー', 'an OpenAI API key'), re: /(?<![A-Za-z0-9])sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/ },
  { label: tx('GitHub トークン', 'a GitHub token'), re: /(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})/ },
  { label: tx('GitLab トークン', 'a GitLab token'), re: /(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}/ },
  { label: tx('Slack アプリトークン', 'a Slack app token'), re: /(?<![A-Za-z0-9])xapp-\d-[A-Za-z0-9]{8,}-\d{8,}-[A-Za-z0-9]{32,}/ },
  { label: tx('Discord ボットトークン', 'a Discord bot token'), re: /(?<![A-Za-z0-9_.-])[A-Za-z0-9]{24,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}(?![A-Za-z0-9_-])/ },
  { label: tx('Slack トークン', 'a Slack token'), re: /(?<![A-Za-z0-9])xox[abposr]-[A-Za-z0-9-]{10,}/ },
  // AWS 公式ドキュメントの例（AKIAIOSFODNN7EXAMPLE）は除く
  { label: tx('AWS アクセスキーID', 'an AWS access key ID'), re: /(?<![A-Za-z0-9])(?:AKIA|ASIA)(?![0-9A-Z]{9}EXAMPLE\b)[0-9A-Z]{16}\b/ },
  { label: tx('Stripe Webhook シークレット', 'a Stripe webhook secret'), re: /(?<![A-Za-z0-9])whsec_[A-Za-z0-9]{24,}/ },
  { label: tx('Google APIキー', 'a Google API key'), re: /(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}/ },
  { label: tx('Stripe シークレットキー', 'a Stripe secret key'), re: /(?<![A-Za-z0-9])[sr]k_live_[0-9A-Za-z]{20,}/ },
  { label: tx('npm トークン', 'an npm token'), re: /(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}/ },
  { label: tx('Hugging Face トークン', 'a Hugging Face token'), re: /(?<![A-Za-z0-9])hf_[A-Za-z0-9]{30,}/ },
  // 鍵の本体まで含めて1つの値として扱う（改行が実際の改行でも、JSON の \n でもよい）
  { label: tx('秘密鍵', 'a private key'), re: /-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)?/ },
  { label: tx('JWT', 'a JWT'), re: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { label: tx('Bearer トークン', 'a Bearer token'), re: /(?<![A-Za-z0-9])Bearer\s+(?!\$|<|YOUR|your|xxx|XXX|\*\*\*|TOKEN\b|token\b)[A-Za-z0-9._~+/-]{8,}=*/ },
  { label: tx('Shopify トークン', 'a Shopify token'), re: /(?<![A-Za-z0-9])shp(?:at|ss|ca|pa)_[0-9a-fA-F]{32}(?![A-Za-z0-9])/ },
  { label: tx('Pulumi トークン', 'a Pulumi token'), re: /(?<![A-Za-z0-9])pul-[0-9a-f]{40}(?![A-Za-z0-9])/ },
  { label: tx('DigitalOcean トークン', 'a DigitalOcean token'), re: /(?<![A-Za-z0-9])do[opr]_v1_[0-9a-f]{64}(?![A-Za-z0-9])/ },
  { label: tx('Grafana トークン', 'a Grafana token'), re: /(?<![A-Za-z0-9])gl(?:sa|c)_[A-Za-z0-9+/=_-]{32,}/ },
  { label: tx('age の秘密鍵', 'an age secret key'), re: /AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}/ },
  { label: tx('Notion トークン', 'a Notion token'), re: /(?<![A-Za-z0-9])(?:ntn_[A-Za-z0-9]{40,}|secret_[A-Za-z0-9]{43})(?![A-Za-z0-9])/ },
  { label: tx('Linear APIキー', 'a Linear API key'), re: /(?<![A-Za-z0-9])lin_(?:api|oauth)_[A-Za-z0-9]{40}(?![A-Za-z0-9])/ },
  { label: tx('Atlassian APIトークン', 'an Atlassian API token'), re: /(?<![A-Za-z0-9])ATATT3[A-Za-z0-9_=-]{100,}/ },
  { label: tx('Doppler トークン', 'a Doppler token'), re: /(?<![A-Za-z0-9])dp\.(?:st|ct|sa|scim|audit)\.[A-Za-z0-9._-]{40,}/ },
  { label: tx('Terraform Cloud トークン', 'a Terraform Cloud token'), re: /(?<![A-Za-z0-9])[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,}/ },
  { label: tx('Twilio APIキー', 'a Twilio API key'), re: /(?<![A-Za-z0-9])SK[0-9a-f]{32}(?![A-Za-z0-9])/ },
  { label: tx('Mailgun APIキー', 'a Mailgun API key'), re: /(?<![A-Za-z0-9])key-[0-9a-f]{32}(?![A-Za-z0-9])/ },
  { label: tx('Basic 認証の資格情報', 'Basic auth credentials'), re: /(?<![A-Za-z0-9])Basic\s+[A-Za-z0-9+/]{12,}={0,2}/ },
  { label: tx('Azure の接続文字列', 'an Azure connection string'), re: /(?<![A-Za-z0-9])(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/]{20,}/ },
  { label: tx('SendGrid APIキー', 'a SendGrid API key'), re: /(?<![A-Za-z0-9])SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/ },
  { label: tx('Discord / Telegram ボットトークン', 'a bot token'), re: /(?<![A-Za-z0-9])\d{8,10}:AA[A-Za-z0-9_-]{30,}/ },
];

// キー名から秘密情報を推定する
const SECRET_KEY_RE_RAW =
  /(?:^|[_\-.])(?:api[_-]?key|apikey|secret|token|password|passwd|pwd|credential|credentials|private[_-]?key|access[_-]?key|auth|authorization|session[_-]?key|client[_-]?secret)(?:$|[_\-.])/i;

/**
 * 秘密情報の「名前」や「置き場所」を指すキー（secret-id、AUTH_URL、PASSWORD_FILE、apiKeyHelper など）。
 * 値は秘密情報そのものではないので、キー名による判定から外す
 */
const NOT_SECRET_SUFFIX_RE = /(?:^|[_\-.])(?:id|ids|name|names|arn|file|path|dir|url|uri|endpoint|host|type|ttl|length|expiry|expires|expiration|hint|header|prefix|env|var|helper|command|cmd|mode|scope|scopes|provider|method|enabled|required|count|version)$/i;

/** camelCase のキー名（githubToken など）も区切りとして扱う */
export const SECRET_KEY_RE = {
  test: (key: string) => {
    const k = key.replace(/([a-z0-9])([A-Z])/g, '$1_$2');
    return SECRET_KEY_RE_RAW.test(k) && !NOT_SECRET_SUFFIX_RE.test(k);
  },
};

// 秘密情報を直接書いていないとみなせる値（環境変数参照やプレースホルダー）
/**
 * シェル形式の変数参照を分解する。$VAR / ${VAR} は参照だけ、${VAR:-値} / ${VAR-値} / ${VAR:=値} / ${VAR=値} は
 * 「変数がなければこの値を使う」というリテラルの既定値を持つ。既定値は直接書かれた値として検査する必要がある。
 */
export function parseVarRef(value: string): { name: string; fallback?: string } | undefined {
  const v = value.trim();
  const bare = /^\$([A-Za-z_][A-Za-z0-9_]*)$/.exec(v);
  if (bare) return { name: bare[1]! };
  // ${VAR:?メッセージ} / ${VAR?メッセージ} は「未設定ならエラー」で、既定値は持たない
  const braced = /^\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-=?])(.*))?\}$/s.exec(v);
  if (!braced) return undefined;
  if (braced[2] === undefined || braced[2].endsWith('?')) return { name: braced[1]! };
  return { name: braced[1]!, fallback: braced[3]! };
}

export function isReferenceOrPlaceholder(value: string): boolean {
  const v = value.trim();
  const ref = parseVarRef(v);
  // ${TOKEN:-abc...} は参照ではなく、既定値 abc... が直接書かれている
  if (ref) return ref.fallback === undefined || isReferenceOrPlaceholder(ref.fallback);
  if (v.length < 8) return true; // 短すぎる値（"true", "1" など）は対象外
  if (/^\$\{(?:env|input):[^}]+\}$/.test(v)) return true; // Cursor/VS Code の ${env:VAR}, ${input:id}
  if (/^\$\{\{[^{}]*\}\}$/.test(v)) return true; // GitHub Actions の ${{ secrets.X }}
  if (/^Bearer\s+\$\{?[A-Za-z_][\w:]*\}?$/i.test(v)) return true;
  if (/^<[^>]*>?$/.test(v) || /^\{\{.*\}\}$/.test(v)) return true; // <YOUR_TOKEN>、{{ テンプレート }}
  // 「あなたのパスワード」「ここにトークン」のように、日本語・中国語だけで書かれた値は説明用の仮の値
  if (/^[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}ー・（）()「」\s]+$/u.test(v)) return true;
  // コード中の参照・呼び出し（process.env.GITHUB_TOKEN、config.apiKey、request.headers.get(...)、matchToToken(match)）
  if (/^(?:process|import\.meta|os|env|config|settings|secrets|context|request|req|res|ctx|this|self|window|globalThis|Deno|Bun|vars|inputs|github|steps|needs|matrix|props|options|opts|args)\.[\w$.[\]'"]+\(?$/.test(v)) return true;
  if (/^[A-Za-z_$][\w$.]*\(/.test(v)) return true;
  // 定数名（SERVICE_KEY、BLOB_TOKEN）、型（InjectionToken<T>、string>1）、メンバー参照（data.nextToken）
  if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(v) && /[A-Z]{2}/.test(v)) return true;
  if (/^[A-Za-z_$][\w$]*\s*[<>]/.test(v)) return true;
  if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(v) && !/[0-9]{3}/.test(v)) return true;
  // 説明用の値（someuser / somepassword / sometoken）
  if (/^some[_-]?(?:pass(?:word)?|secret|token|key|value|user)/i.test(v)) return true;
  // 接頭辞の後ろを x や * で埋めた仮の値（sk-xxxxxxxx、ghp_************、sk-ant-...）
  if (/^(?:[A-Za-z0-9]{1,10}[-_.]){1,3}(?:x{4,}|X{4,}|\*{4,}|0{8,}|\.{3,}|<[^>]*>)$/.test(v)) return true;
  // よく使われる仮の値（.env.example や README に書かれるもの）
  if (/^(?:x+|\*+|\.+|your.*|.*(?:[_-]|goes)here|change[_-]?me(?:[_-].*)?|replace[_-]?me|to[_-]?be[_-]?(?:modified|changed|replaced)|placeholder|dummy.*|example.*|sample.*|redacted|todo|tbd|secret|password|passw0rd|token|test|testing)$/i.test(v)) return true;
  if (/^(?:op|vault|keychain|aws-sm|gcp-sm):\/\//i.test(v)) return true; // シークレットマネージャー参照
  return false;
}

function matchValuePattern(value: string): { label: Text; part: string } | undefined {
  for (const p of VALUE_PATTERNS) {
    const m = p.re.exec(value);
    if (m) return { label: p.label, part: m[0] };
  }
  return undefined;
}

/**
 * URL のパスワード部分によく書かれる仮の値（postgres://user:password@host など）。
 * 長さでは判定しない（admin:pw123@ のような短い本物のパスワードを見逃さないため）
 */
export function isUrlPasswordPlaceholder(pw: string): boolean {
  return /^(?:\$\{?[A-Za-z_][\w:]*\}?|\$\{\{[^{}]*\}\}|password|passwd|pass|postgres|mysql|root|admin|changeme|secret|example|some[_-]?pass(?:word)?|your[_-]?pass(?:word)?|x+|\*+|<[^>]*>|\[[^\]]*\]|\.\.\.)$/i.test(pw);
}

/** 壊れた % エンコードでも例外を投げずにデコードする（失敗したら元の文字列を返す） */
export function safeDecode(v: string): string {
  try {
    return decodeURIComponent(v);
  } catch {
    return v;
  }
}

/** URL にユーザー情報（user:pass@）やトークン系クエリが含まれるか。含まれていればその値を返す */
function urlCredential(value: string): string | undefined {
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return undefined;
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return undefined;
  }
  if (u.password && !isUrlPasswordPlaceholder(safeDecode(u.password))) return safeDecode(u.password);
  for (const [k, v] of u.searchParams) {
    if (SECRET_KEY_RE.test(k) && !isReferenceOrPlaceholder(v)) return v;
  }
  return undefined;
}

function hasUrlCredential(value: string): boolean {
  return urlCredential(value) !== undefined;
}

/**
 * 文字列の中に埋め込まれた資格情報を探す。
 * 例: `API_KEY=abc...`、`password: abc...`、`--token abc...`、`curl -u user:pass`
 */
function findInlineSecret(value: string): { label: Text; part: string } | undefined {
  for (const m of value.matchAll(/(?:^|[\s;&|'"(?,]|(?<!\$)\{|--)(?:export\s+)?([A-Za-z_][\w.]*(?:-[\w.]+)*)['"]?\s*[=:]\s*(['"]?)(\$\{(?:[^{}\n]|\{[^{}\n]*\})*\}|[^\s'";&|)?,]+)\2/g)) {
    if (SECRET_KEY_RE.test(m[1]!) && !isReferenceOrPlaceholder(m[3]!)) return { label: tx(`「${m[1]}」の値`, `the value of ${m[1]}`), part: secretPart(m[3]!) };
  }
  for (const m of value.matchAll(/(?:^|\s)--?([A-Za-z][\w-]*)\s+(['"]?)([^\s'"-][^\s'"]*)\2/g)) {
    if (SECRET_KEY_RE.test(m[1]!) && !isReferenceOrPlaceholder(m[3]!)) return { label: tx(`引数 ${m[1]} の値`, `the value of argument ${m[1]}`), part: secretPart(m[3]!) };
  }
  const user = /(?:^|\s)(?:-u|--user)\s+(['"]?)[^\s:'"]+:([^\s'"]+)\1/.exec(value);
  if (user && !/^\$\{?[A-Za-z_][\w:]*\}?$/.test(user[2]!)) return { label: tx('ユーザー名とパスワード', 'a username and password'), part: user[2]! };
  return undefined;
}

/** ${VAR:-既定値} なら既定値の部分が秘密情報 */
function secretPart(value: string): string {
  return parseVarRef(value)?.fallback ?? value;
}

/** 秘密情報らしいフラグ名か（--api-key, --token, --password など） */
function isSecretFlag(v: unknown): boolean {
  if (typeof v !== 'string') return false;
  const m = /^--?([A-Za-z][\w-]*)$/.exec(v);
  return m !== null && SECRET_KEY_RE.test(m[1]!);
}

/** キー名・サーバー名などの「名前」に秘密情報が入っていないか（名前は表示するため） */
export function looksLikeSecretName(name: string): boolean {
  return matchValuePattern(name) !== undefined || hasUrlCredential(name) || findInlineSecret(name) !== undefined;
}

/** 名前を表示する前に、秘密情報らしければ伏せる */
export function redactName(name: string): string {
  return looksLikeSecretName(name) ? '[REDACTED]' : name;
}

/** 1つの文字列値を検査する。keyName はその値のキー名（配列要素なら直前のキー名） */
export function classifySecret(keyName: string | undefined, value: string): Omit<SecretHit, 'agent' | 'file' | 'pointer'> | undefined {
  const found = detectSecret(keyName, value);
  if (!found) return undefined;
  // 判定した値そのものを保管庫に覚える（出力保護が、同じ値が別の場所に現れたときにも伏せられるように）
  rememberSecret(found.part);
  return { kind: found.kind, label: found.label };
}

function detectSecret(keyName: string | undefined, value: string): { kind: SecretHit['kind']; label: Text; part: string } | undefined {
  const pattern = matchValuePattern(value);
  if (pattern) return { kind: 'value-pattern', ...pattern };
  const url = urlCredential(value);
  if (url !== undefined) return { kind: 'url-credential', label: tx('URL 内の認証情報', 'credentials embedded in a URL'), part: url };
  // --api-key=xxxx のような引数
  const flag = /^--?([A-Za-z][\w-]*)=(.+)$/.exec(value);
  if (flag && SECRET_KEY_RE.test(flag[1]!) && !isReferenceOrPlaceholder(flag[2]!)) {
    return { kind: 'key-name', label: tx(`引数 ${flag[1]}`, `Argument ${flag[1]}`), part: secretPart(flag[2]!) };
  }
  if (keyName && SECRET_KEY_RE.test(keyName) && !isReferenceOrPlaceholder(value)) {
    const shown = redactName(keyName);
    return { kind: 'key-name', label: tx(`「${shown}」`, `Key "${shown}"`), part: secretPart(value) };
  }
  const inline = findInlineSecret(value);
  if (inline) return { kind: 'key-name', ...inline };
  return undefined;
}

/** 値を再帰的にたどり、秘密情報らしき文字列の位置を集める */
export function scanForSecrets(value: unknown, agent: AgentId, file: string, pointer = ''): SecretHit[] {
  const hits: SecretHit[] = [];
  const visit = (v: unknown, ptr: string, keyName: string | undefined, depth: number) => {
    if (depth > 256) return;
    if (typeof v === 'string') {
      const hit = classifySecret(keyName, v);
      if (hit) hits.push({ agent, file, pointer: ptr, ...hit });
    } else if (Array.isArray(v)) {
      v.forEach((item, i) => {
        const p = joinPointer(ptr, i);
        // ["--token", "abc..."] のように、フラグの次の要素に値を置く形
        if (typeof item === 'string' && i > 0 && isSecretFlag(v[i - 1]) && !isReferenceOrPlaceholder(item) && !classifySecret(keyName, item)) {
          const flag = String(v[i - 1]).replace(/^--?/, '');
          rememberSecret(secretPart(item));
          hits.push({ agent, file, pointer: p, kind: 'key-name', label: tx(`引数 ${flag} の値`, `the value of argument ${flag}`) });
          return;
        }
        visit(item, p, keyName, depth + 1);
      });
    } else if (isPlainObject(v)) {
      for (const [k, child] of Object.entries(v)) visit(child, joinPointer(ptr, k), k, depth + 1);
    }
  };
  visit(value, pointer, undefined, 0);
  return hits;
}

/** 表示用：秘密情報を含みうる文字列を伏せる（ルール文字列などを画面に出す前の安全策） */
export function redactIfSecret(value: string): string {
  return classifySecret(undefined, value) ? '[REDACTED]' : value;
}
