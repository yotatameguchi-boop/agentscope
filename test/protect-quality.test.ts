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

describe('出力保護の品質', () => {
  it('無害な文字列を変更しない（適合率 100%）', () => {
    expect(r.precision.falsePositives).toEqual([]);
    expect(r.precision.kept).toBe(r.precision.total);
  });

  it('全体の再現率は 97% 以上', () => {
    expect(r.recall.masked / r.recall.total).toBeGreaterThanOrEqual(0.97);
  });

  it('形式に特徴のある秘密情報は、どこに置いても伏せる', () => {
    const misses = [...r.recall.byKind].filter(([kind, v]) => !CONTEXT_DEPENDENT.has(kind) && rate(v) < 1).map(([k]) => k);
    expect(misses).toEqual([]);
  });

  it('キー名・フラグ名などの手がかりがある置き場所では、ほぼすべて伏せる', () => {
    for (const p of PLACEMENTS.filter((x) => x.hinted)) {
      // url-userinfo は、URL の規則上ありえない / を含む値をそのまま置いた場合だけ一部が残る
      expect(rate(r.recall.byPlacement.get(p.name)!), p.name).toBeGreaterThanOrEqual(p.name === 'url-userinfo' ? 0.98 : 1);
    }
  });
});
