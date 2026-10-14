/**
 * 回帰テスト: 出力保護の品質の下限。評価データ（test/bench/corpus.ts）で測る。
 * 改良の経過と、伏せない範囲の方針は docs/output-protection.md にある。
 */
import { describe, expect, it } from 'vitest';
import { evaluate } from './bench/evaluate.js';
import { PLACEMENTS } from './bench/corpus.js';

const r = evaluate();
const rate = ([m, t]: [number, number]) => m / t;

/** 手がかりがない場所では、形式に特徴のない値を伏せない方針（16進の値はハッシュと区別できない、短い値は一般の文字列と区別できない） */
const CONTEXT_DEPENDENT = new Set(['datadog-hex32', 'generic-hex40', 'short-alnum8', 'mongodb-srv', 'basic-auth', 'postgres-url', 'aws-secret-access-key']);

/** 接頭辞のないランダムな値。ランダム性による判定は確率的なため、100% ではなく下限で見る */
const RANDOM_WITHOUT_PREFIX = new Set(['generic-alnum32', 'generic-urlsafe43', 'generic-base64-44', 'bearer', 'cloudflare-token', 'vercel']);

describe('出力保護の品質', () => {
  it('変更してはいけない無害な文字列を変更しない（適合率 100%）', () => {
    expect(r.precision.falsePositives.filter((f) => f.tier === 'keep')).toEqual([]);
    const [kept, total] = r.precision.byTier.get('keep')!;
    expect(kept).toBe(total);
  });

  it('全体の再現率は 97% 以上', () => {
    expect(r.recall.masked / r.recall.total).toBeGreaterThanOrEqual(0.97);
  });

  it('形式に特徴のある秘密情報は、どこに置いても伏せる', () => {
    const misses = [...r.recall.byKind]
      .filter(([kind, v]) => !CONTEXT_DEPENDENT.has(kind) && !RANDOM_WITHOUT_PREFIX.has(kind) && rate(v) < 1)
      .map(([k]) => k);
    expect(misses).toEqual([]);
  });

  it('接頭辞のないランダムな値も 97% 以上伏せる', () => {
    for (const kind of RANDOM_WITHOUT_PREFIX) expect(rate(r.recall.byKind.get(kind)!), kind).toBeGreaterThanOrEqual(0.97);
  });

  it('ランダムな文字列を「人が付けた名前」と見なす割合は 1.5% 未満', async () => {
    const { looksRandom } = await import('../src/util/protect.js');
    const { gen, rng } = await import('./bench/corpus.js');
    const rand = rng(123);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let missed = 0;
    const N = 5000;
    for (let i = 0; i < N; i++) {
      const t = gen(rand, chars, 16 + Math.floor(rand() * 48));
      // 大文字・小文字・数字をすべて含むものだけを対象にする（含まないものは方針として伏せない）
      if (!/[a-z]/.test(t) || !/[A-Z]/.test(t) || !/[0-9]/.test(t)) continue;
      if (!looksRandom(t)) missed++;
    }
    expect(missed / N).toBeLessThan(0.015);
  });

  it('キー名・フラグ名などの手がかりがある置き場所では、ほぼすべて伏せる', () => {
    for (const p of PLACEMENTS.filter((x) => x.hinted)) {
      // url-userinfo は、URL の規則上ありえない / を含む値をそのまま置いた場合だけ一部が残る
      expect(rate(r.recall.byPlacement.get(p.name)!), p.name).toBeGreaterThanOrEqual(p.name === 'url-userinfo' ? 0.98 : 1);
    }
  });
});
