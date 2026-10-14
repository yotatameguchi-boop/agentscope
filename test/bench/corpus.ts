/**
 * 出力保護（maskSecrets）の評価用データ。
 *
 * 本物の鍵をリポジトリに置かないよう、ダミーの値は固定シードの乱数で実行時に組み立てる。
 * - positives: 伏せるべき秘密情報（形式 × 置き場所）
 * - 伏せてはいけない無害な文字列は negatives.ts にある
 */

/** 固定シードの擬似乱数（mulberry32） */
export function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const HEX = '0123456789abcdef';
const B64 = ALNUM + '+/';
const URLSAFE = ALNUM + '-_';

export function gen(r: () => number, chars: string, n: number): string {
  let s = '';
  for (let i = 0; i < n; i++) s += chars[Math.floor(r() * chars.length)];
  return s;
}

export interface Secret {
  /** 形式の名前（集計の単位） */
  kind: string;
  /** 出力に残ってはいけない値 */
  value: string;
  /** 秘密情報としての書き方（値そのものと違う場合。例: 接続文字列全体） */
  text?: string;
}

/** 伏せるべき秘密情報の形式 */
export function secrets(seed = 1): Secret[] {
  const r = rng(seed);
  const s = (kind: string, value: string, text?: string): Secret => ({ kind, value, text });
  const pg = gen(r, ALNUM, 18);
  const mongo = gen(r, ALNUM, 16);
  const redis = gen(r, ALNUM, 20);
  const basicUser = 'svc';
  const basicPass = gen(r, ALNUM, 14);
  const pemBody = gen(r, B64, 64);
  return [
    s('anthropic', `sk-ant-api03-${gen(r, URLSAFE, 93)}AA`),
    s('openai-proj', `sk-proj-${gen(r, URLSAFE, 120)}`),
    s('openai-legacy', `sk-${gen(r, ALNUM, 48)}`),
    s('github-pat-classic', `ghp_${gen(r, ALNUM, 36)}`),
    s('github-oauth', `gho_${gen(r, ALNUM, 36)}`),
    s('github-fine-grained', `github_pat_${gen(r, ALNUM, 22)}_${gen(r, ALNUM, 59)}`),
    s('gitlab', `glpat-${gen(r, URLSAFE, 20)}`),
    s('slack-bot', `xoxb-${gen(r, '0123456789', 12)}-${gen(r, '0123456789', 13)}-${gen(r, ALNUM, 24)}`),
    s('slack-app', `xapp-1-${gen(r, ALNUM, 11)}-${gen(r, '0123456789', 13)}-${gen(r, HEX, 64)}`),
    s('aws-access-key-id', `AKIA${gen(r, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 16)}`),
    s('aws-secret-access-key', gen(r, B64, 40)),
    s('google-api-key', `AIza${gen(r, URLSAFE, 35)}`),
    s('stripe-live', `sk_live_${gen(r, ALNUM, 24)}`),
    s('stripe-restricted', `rk_live_${gen(r, ALNUM, 24)}`),
    s('sendgrid', `SG.${gen(r, URLSAFE, 22)}.${gen(r, URLSAFE, 43)}`),
    s('twilio', `SK${gen(r, HEX, 32)}`),
    s('mailgun', `key-${gen(r, HEX, 32)}`),
    s('npm', `npm_${gen(r, ALNUM, 36)}`),
    s('pypi', `pypi-AgEIcHlwaS5vcmc${gen(r, URLSAFE, 60)}`),
    s('huggingface', `hf_${gen(r, ALNUM, 34)}`),
    s('discord-bot', `${gen(r, ALNUM, 24)}.${gen(r, URLSAFE, 6)}.${gen(r, URLSAFE, 27)}`),
    s('telegram-bot', `${gen(r, '0123456789', 10)}:AA${gen(r, URLSAFE, 33)}`),
    s('jwt', `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIx${gen(r, URLSAFE, 20)}.${gen(r, URLSAFE, 43)}`),
    s('datadog-hex32', gen(r, HEX, 32)),
    s('generic-hex40', gen(r, HEX, 40)),
    s('generic-alnum16', gen(r, ALNUM, 16)),
    s('generic-alnum32', gen(r, ALNUM, 32)),
    s('generic-urlsafe43', gen(r, URLSAFE, 43)),
    s('generic-base64-44', gen(r, B64, 43) + '='),
    s('postgres-url', pg, `postgres://app:${pg}@db.internal:5432/app`),
    s('mongodb-srv', mongo, `mongodb+srv://admin:${mongo}@cluster0.mongodb.net/prod`),
    s('redis-url', redis, `redis://:${redis}@cache:6379/0`),
    s('basic-auth', basicPass, `Authorization: Basic ${Buffer.from(`${basicUser}:${basicPass}`).toString('base64')}`),
    s('bearer', gen(r, URLSAFE, 40)),
    s('private-key-pem', pemBody, `-----BEGIN PRIVATE KEY-----\n${pemBody}\n-----END PRIVATE KEY-----`),
    s('azure-conn', gen(r, B64, 86) + '==', undefined),
    s('short-alnum8', gen(r, ALNUM, 8)),
    // ---- 2 回目に追加した形式 ----
    s('anthropic-admin', `sk-ant-admin01-${gen(r, URLSAFE, 93)}AA`),
    s('openai-svcacct', `sk-svcacct-${gen(r, URLSAFE, 120)}`),
    s('notion', `ntn_${gen(r, ALNUM, 46)}`),
    s('notion-legacy', `secret_${gen(r, ALNUM, 43)}`),
    s('linear', `lin_api_${gen(r, ALNUM, 40)}`),
    s('shopify', `shpat_${gen(r, HEX, 32)}`),
    s('atlassian', `ATATT3xFfGF0${gen(r, URLSAFE, 180)}=${gen(r, HEX, 8).toUpperCase()}`),
    s('doppler', `dp.st.prd.${gen(r, ALNUM, 43)}`),
    s('pulumi', `pul-${gen(r, HEX, 40)}`),
    s('terraform-cloud', `${gen(r, ALNUM, 14)}.atlasv1.${gen(r, ALNUM, 67)}`),
    s('cloudflare-token', gen(r, URLSAFE, 40)),
    s('vercel', gen(r, ALNUM, 24)),
    s('digitalocean', `dop_v1_${gen(r, HEX, 64)}`),
    s('grafana', `glsa_${gen(r, ALNUM, 32)}_${gen(r, HEX, 8)}`),
    s('age-secret', `AGE-SECRET-KEY-1${gen(r, 'QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L', 58)}`),
    s('gcp-sa-private-key-json', pemBody, `"private_key": "-----BEGIN PRIVATE KEY-----\\n${pemBody}\\n-----END PRIVATE KEY-----\\n"`),
    s('openssh-private-key', pemBody, `-----BEGIN OPENSSH PRIVATE KEY-----\n${pemBody}\n-----END OPENSSH PRIVATE KEY-----`),
  ];
}

/** 秘密情報を置く場所。key は秘密情報らしいキー名を持つ文脈かどうか（文脈なしでも伏せるべきかを分けて集計する） */
export interface Placement {
  name: string;
  /** キー名やフラグ名など、秘密情報だと分かる手がかりがある置き場所か */
  hinted: boolean;
  render: (secret: Secret) => string;
}

export const PLACEMENTS: Placement[] = [
  { name: 'bare', hinted: false, render: (x) => x.text ?? x.value },
  { name: 'in-path', hinted: false, render: (x) => `/var/run/app/${x.value}/config.json` },
  { name: 'flag-space', hinted: true, render: (x) => `deploy --token ${x.value} --region us` },
  { name: 'flag-equals', hinted: true, render: (x) => `deploy --api-key=${x.value}` },
  { name: 'env-assign', hinted: true, render: (x) => `export SERVICE_TOKEN=${x.value}` },
  { name: 'env-assign-quoted', hinted: true, render: (x) => `SERVICE_SECRET="${x.value}" npm start` },
  { name: 'header', hinted: true, render: (x) => `curl -H "Authorization: Bearer ${x.value}" https://api.example.com` },
  { name: 'x-api-key-header', hinted: true, render: (x) => `curl -H 'x-api-key: ${x.value}' https://api.example.com` },
  { name: 'url-query', hinted: true, render: (x) => `https://api.example.com/v1/items?access_token=${x.value}&page=2` },
  { name: 'url-userinfo', hinted: true, render: (x) => `https://deploy:${x.value}@git.example.com/repo.git` },
  { name: 'json-snippet', hinted: true, render: (x) => `{"api_key": "${x.value}"}` },
  { name: 'yaml-snippet', hinted: true, render: (x) => `password: ${x.value}` },
  { name: 'japanese-sentence', hinted: false, render: (x) => `本番のトークンは${x.value}です` },
  { name: 'parenthesized', hinted: false, render: (x) => `Bash(echo ${x.value})` },
  { name: 'url-encoded-in-query', hinted: true, render: (x) => `https://h.example/?token=${encodeURIComponent(x.value)}` },
  { name: 'adjacent-punct', hinted: false, render: (x) => `[${x.value}],` },
  { name: 'newline-separated', hinted: false, render: (x) => `line1\n${x.value}\nline3` },
  // 見えない文字を値の途中に挟んだもの（ゼロ幅スペース・単語結合子・BOM）
  { name: 'zero-width-split', hinted: false, render: (x) => { const v = x.text ?? x.value; const i = Math.floor(v.length / 2); return v.slice(0, i) + '\u200b' + v.slice(i); } },
  { name: 'zero-width-many', hinted: true, render: (x) => `export SERVICE_TOKEN=${[...x.value].join('\u2060')}` },
];
