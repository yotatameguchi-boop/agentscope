import type { AgentId, SecretHit } from '../types.js';
import { isPlainObject, joinPointer } from './jsonc.js';

/**
 * 設定ファイル内に直接書かれた認証情報らしき文字列を探す（R004 の材料）。
 * 検出結果には値そのもの・値の一部・長さを一切含めない。
 */

interface ValuePattern {
  label: string;
  re: RegExp;
}

// 既知の形式。誤検知を抑えるため、プレフィックスと十分な長さの両方を要求する
const VALUE_PATTERNS: ValuePattern[] = [
  { label: 'Anthropic APIキー', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/ },
  { label: 'OpenAI APIキー', re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/ },
  { label: 'GitHub トークン', re: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})/ },
  { label: 'GitLab トークン', re: /\bglpat-[A-Za-z0-9_-]{20,}/ },
  { label: 'Slack トークン', re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/ },
  { label: 'AWS アクセスキーID', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { label: 'Google APIキー', re: /\bAIza[0-9A-Za-z_-]{35}/ },
  { label: 'Stripe シークレットキー', re: /\b[sr]k_live_[0-9A-Za-z]{20,}/ },
  { label: 'npm トークン', re: /\bnpm_[A-Za-z0-9]{36}/ },
  { label: 'Hugging Face トークン', re: /\bhf_[A-Za-z0-9]{30,}/ },
  { label: '秘密鍵', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { label: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { label: 'Bearer トークン', re: /\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*/ },
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

function matchValuePattern(value: string): string | undefined {
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

/** 1つの文字列値を検査する。keyName はその値のキー名（配列要素なら直前のキー名） */
export function classifySecret(keyName: string | undefined, value: string): Omit<SecretHit, 'agent' | 'file' | 'pointer'> | undefined {
  const label = matchValuePattern(value);
  if (label) return { kind: 'value-pattern', label };
  if (hasUrlCredential(value)) return { kind: 'url-credential', label: 'URL 内の認証情報' };
  // --api-key=xxxx のような引数
  const flag = /^--?([A-Za-z][\w-]*)=(.+)$/.exec(value);
  if (flag && SECRET_KEY_RE.test(flag[1]!) && !isReferenceOrPlaceholder(flag[2]!)) {
    return { kind: 'key-name', label: `引数 ${flag[1]}` };
  }
  if (keyName && SECRET_KEY_RE.test(keyName) && !isReferenceOrPlaceholder(value)) {
    return { kind: 'key-name', label: `「${keyName}」` };
  }
  return undefined;
}

/** 値を再帰的にたどり、秘密情報らしき文字列の位置を集める */
export function scanForSecrets(value: unknown, agent: AgentId, file: string, pointer = ''): SecretHit[] {
  const hits: SecretHit[] = [];
  const visit = (v: unknown, ptr: string, keyName: string | undefined, depth: number) => {
    if (depth > 64) return;
    if (typeof v === 'string') {
      const hit = classifySecret(keyName, v);
      if (hit) hits.push({ agent, file, pointer: ptr, ...hit });
    } else if (Array.isArray(v)) {
      v.forEach((item, i) => visit(item, joinPointer(ptr, i), keyName, depth + 1));
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
