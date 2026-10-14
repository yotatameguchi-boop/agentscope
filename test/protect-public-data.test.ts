/**
 * 回帰テスト: 公開データ（このリポジトリの node_modules）での誤検知。
 * 変更されてよいのは、伏せても許容できるもの（リンクを知っていれば開ける文書の ID、ドキュメント中のランダムな出力例）だけ。
 */
import path from 'node:path';
import { existsSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { maskSecrets } from '../src/util/protect.js';
import { collectPublicStrings } from './bench/real-corpus.js';

const NODE_MODULES = path.join(import.meta.dirname, '..', 'node_modules');

/** 伏せても許容できる変更（変更後の文字列で判定する） */
const TOLERABLE = [
  /docs\.google\.com\/(?:document|spreadsheets)\/d\/\[REDACTED\]/, // 共有リンクの ID
  /nanoid\(\) \/\/=> "\[REDACTED\]"/, // ランダムな ID の出力例
];

describe.skipIf(!existsSync(NODE_MODULES))('公開データでの誤検知', () => {
  it('node_modules の文字列で、許容できるもの以外を変更しない', () => {
    const strings = collectPublicStrings(NODE_MODULES);
    expect(strings.length).toBeGreaterThan(5000);
    const unexpected = strings
      .map((x) => ({ file: path.relative(NODE_MODULES, x.file), before: x.s, after: maskSecrets(x.s) }))
      .filter((x) => x.after !== x.before && !TOLERABLE.some((re) => re.test(x.after)))
      .map((x) => `${x.file}: ${x.before.slice(0, 160)}`);
    expect(unexpected).toEqual([]);
  });
});
