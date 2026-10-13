/**
 * 回帰テスト: 出力保護・検出の正規表現が、意地の悪い入力でも線形に近い時間で終わること（ReDoS の防止）。
 * 出力保護はすべての出力文字列にかかるため、1つの遅い入力で CLI 全体が止まる。
 */
import { describe, expect, it } from 'vitest';
import { maskSecrets } from '../src/util/protect.js';
import { classifySecret } from '../src/util/secrets.js';

const CASES: Record<string, string> = {
  'userinfo-without-at': 'https://' + 'a'.repeat(100_000) + ':' + 'b'.repeat(100_000),
  'long-base64': Array.from({ length: 500_000 }, (_, i) => 'Ab3+/xYz9'[i % 9]).join(''),
  'repeated-assign': 'a='.repeat(50_000),
  'repeated-flags': '--token '.repeat(30_000),
  'repeated-scheme': 'http://'.repeat(20_000) + 'x',
  'nested-braces': 'TOKEN=${' + '{'.repeat(50_000),
  'many-colon-at': 'x://' + ':@'.repeat(50_000),
  'bearer-spam': 'Bearer '.repeat(50_000),
  'unclosed-private-key': '-----BEGIN PRIVATE KEY-----' + 'a\n'.repeat(100_000),
  'jwt-like': ('eyJ' + 'a'.repeat(20) + '.').repeat(20_000),
  // 総当たりで見つかった、二乗の時間になっていた入力
  'jwt-prefix-run': 'eyJ-'.repeat(60_000),
  'double-dash-run': 'a--'.repeat(80_000),
  'age-key-run': 'AGE-SECRET-KEY-1@'.repeat(15_000),
  'long-token-no-space': 'Ab3dE5fG7hJ9kL1mN2pQ4rS6/'.repeat(10_000),
};

describe('出力保護の処理時間', () => {
  it.each(Object.entries(CASES))('%s', (_name, input) => {
    const t = performance.now();
    maskSecrets(input);
    classifySecret('token', input);
    expect(performance.now() - t).toBeLessThan(1500);
  });
});

/** 部品を繰り返した入力で、長さを 2 倍にしたときの時間の伸びが 2 乗に近くないこと */
describe('総当たり（部品 2 つの組み合わせ）', () => {
  const PARTS = ['a', 'A', '9', ':', '=', '-', '--', '/', '://', '@', '${', '{', '}', ' ', '"', '?', '&', 'eyJ', '.', '_', 'Bearer ', '--token ', 'token=', 'sk-ant-', 'ghp_', 'AGE-SECRET-KEY-1', '-----BEGIN ', 'https://x/'];
  it('二乗の時間になる組み合わせがない', () => {
    const slow: string[] = [];
    for (const a of PARTS) {
      for (const b of PARTS) {
        const unit = a + b;
        const n = Math.ceil(8000 / unit.length);
        const run = (k: number) => {
          const input = unit.repeat(k);
          const t = performance.now();
          maskSecrets(input);
          classifySecret('api_token', input);
          return performance.now() - t;
        };
        const t1 = run(n);
        const t2 = run(n * 4);
        // 線形なら約 4 倍、2 乗なら約 16 倍。ゆらぎを見込んで 10 倍かつ 100ms 超を問題とする
        if (t2 > 100 && t2 / Math.max(t1, 1) > 10) slow.push(`${JSON.stringify(unit)} ${t1.toFixed(0)}ms -> ${t2.toFixed(0)}ms`);
      }
    }
    expect(slow).toEqual([]);
  });
});
