import { tx, type Text } from '../i18n.js';
import type { AgentId, SecretHit } from '../types.js';
import { isPlainObject } from './jsonc.js';
import { joinPointer } from './pointer.js';

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
const VALUE_PATTERNS: ValuePattern[] = [
  { label: tx('Anthropic APIキー', 'an Anthropic API key'), re: /(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,}/ },
  { label: tx('OpenAI APIキー', 'an OpenAI API key'), re: /(?<![A-Za-z0-9])sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/ },
  { label: tx('GitHub トークン', 'a GitHub token'), re: /(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})/ },
  { label: tx('GitLab トークン', 'a GitLab token'), re: /(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}/ },
  { label: tx('Slack トークン', 'a Slack token'), re: /(?<![A-Za-z0-9])xox[abposr]-[A-Za-z0-9-]{10,}/ },
  { label: tx('AWS アクセスキーID', 'an AWS access key ID'), re: /(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { label: tx('Google APIキー', 'a Google API key'), re: /(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}/ },
  { label: tx('Stripe シークレットキー', 'a Stripe secret key'), re: /(?<![A-Za-z0-9])[sr]k_live_[0-9A-Za-z]{20,}/ },
  { label: tx('npm トークン', 'an npm token'), re: /(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}/ },
  { label: tx('Hugging Face トークン', 'a Hugging Face token'), re: /(?<![A-Za-z0-9])hf_[A-Za-z0-9]{30,}/ },
  { label: tx('秘密鍵', 'a private key'), re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { label: tx('JWT', 'a JWT'), re: /(?<![A-Za-z0-9])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { label: tx('Bearer トークン', 'a Bearer token'), re: /(?<![A-Za-z0-9])Bearer\s+[A-Za-z0-9._~+/-]{20,}=*/ },
  { label: tx('Basic 認証の資格情報', 'Basic auth credentials'), re: /(?<![A-Za-z0-9])Basic\s+[A-Za-z0-9+/]{12,}={0,2}/ },
  { label: tx('Azure の接続文字列', 'an Azure connection string'), re: /(?<![A-Za-z0-9])(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/]{20,}/ },
  { label: tx('SendGrid APIキー', 'a SendGrid API key'), re: /(?<![A-Za-z0-9])SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/ },
  { label: tx('Discord / Telegram ボットトークン', 'a bot token'), re: /(?<![A-Za-z0-9])\d{8,10}:AA[A-Za-z0-9_-]{30,}/ },
];

// キー名から秘密情報を推定する
const SECRET_KEY_RE_RAW =
  /(?:^|[_\-.])(?:api[_-]?key|apikey|secret|token|password|passwd|pwd|credential|credentials|private[_-]?key|access[_-]?key|auth|authorization|session[_-]?key|client[_-]?secret)(?:$|[_\-.])/i;

/** camelCase のキー名（githubToken など）も区切りとして扱う */
const SECRET_KEY_RE = { test: (key: string) => SECRET_KEY_RE_RAW.test(key.replace(/([a-z0-9])([A-Z])/g, '$1_$2')) };

// 秘密情報を直接書いていないとみなせる値（環境変数参照やプレースホルダー）
function isReferenceOrPlaceholder(value: string): boolean {
  const v = value.trim();
  if (v.length < 8) return true; // 短すぎる値（"true", "1" など）は対象外
  if (/^\$\{?[A-Za-z_][A-Za-z0-9_]*(?::-[^}]*)?\}?$/.test(v)) return true; // $VAR, ${VAR}, ${VAR:-x}
  if (/^\$\{(?:env|input):[^}]+\}$/.test(v)) return true; // Cursor/VS Code の ${env:VAR}, ${input:id}
  if (/^Bearer\s+\$\{?[A-Za-z_][\w:]*\}?$/i.test(v)) return true;
  if (/^<[^>]+>$/.test(v)) return true; // <YOUR_TOKEN>
  if (/^(?:x+|\*+|\.+|your[_-].*|changeme|placeholder|dummy|example|redacted|todo)$/i.test(v)) return true;
  if (/^(?:op|vault|keychain|aws-sm|gcp-sm):\/\//i.test(v)) return true; // シークレットマネージャー参照
  return false;
}

function matchValuePattern(value: string): Text | undefined {
  for (const p of VALUE_PATTERNS) if (p.re.test(value)) return p.label;
  return undefined;
}

/** URL にユーザー情報（user:pass@）やトークン系クエリが含まれるか */
function hasUrlCredential(value: string): boolean {
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return false;
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return false;
  }
  if (u.password && !/^\$\{?[A-Za-z_][\w:]*\}?$/.test(decodeURIComponent(u.password))) return true;
  for (const [k, v] of u.searchParams) {
    if (SECRET_KEY_RE.test(k) && !isReferenceOrPlaceholder(v)) return true;
  }
  return false;
}

/**
 * 文字列の中に埋め込まれた資格情報を探す。
 * 例: `API_KEY=abc...`、`password: abc...`、`--token abc...`、`curl -u user:pass`
 */
function findInlineSecret(value: string): Text | undefined {
  for (const m of value.matchAll(/(?:^|[\s;&|'"(?,])(?:export\s+)?([A-Za-z_][\w.-]*)\s*[=:]\s*(['"]?)([^\s'";&|)?]+)\2/g)) {
    if (SECRET_KEY_RE.test(m[1]!) && !isReferenceOrPlaceholder(m[3]!)) return tx(`「${m[1]}」の値`, `the value of ${m[1]}`);
  }
  for (const m of value.matchAll(/(?:^|\s)--?([A-Za-z][\w-]*)\s+(['"]?)([^\s'"-][^\s'"]*)\2/g)) {
    if (SECRET_KEY_RE.test(m[1]!) && !isReferenceOrPlaceholder(m[3]!)) return tx(`引数 ${m[1]} の値`, `the value of argument ${m[1]}`);
  }
  const user = /(?:^|\s)(?:-u|--user)\s+(['"]?)[^\s:'"]+:([^\s'"]+)\1/.exec(value);
  if (user && !/^\$\{?[A-Za-z_][\w:]*\}?$/.test(user[2]!)) return tx('ユーザー名とパスワード', 'a username and password');
  return undefined;
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
  const label = matchValuePattern(value);
  if (label) return { kind: 'value-pattern', label };
  if (hasUrlCredential(value)) return { kind: 'url-credential', label: tx('URL 内の認証情報', 'credentials embedded in a URL') };
  // --api-key=xxxx のような引数
  const flag = /^--?([A-Za-z][\w-]*)=(.+)$/.exec(value);
  if (flag && SECRET_KEY_RE.test(flag[1]!) && !isReferenceOrPlaceholder(flag[2]!)) {
    return { kind: 'key-name', label: tx(`引数 ${flag[1]}`, `Argument ${flag[1]}`) };
  }
  if (keyName && SECRET_KEY_RE.test(keyName) && !isReferenceOrPlaceholder(value)) {
    const shown = redactName(keyName);
    return { kind: 'key-name', label: tx(`「${shown}」`, `Key "${shown}"`) };
  }
  const inline = findInlineSecret(value);
  if (inline) return { kind: 'key-name', label: inline };
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
