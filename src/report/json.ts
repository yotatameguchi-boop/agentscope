import type { LocalizedScanResult } from '../types.js';

/** 機械処理向けの JSON。秘密情報の値はパース段階で取り除かれているため、ここでは整形のみ行う */
export function renderJson(result: LocalizedScanResult): string {
  return JSON.stringify(result, null, 2) + '\n';
}
