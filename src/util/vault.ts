import { AsyncLocalStorage } from 'node:async_hooks';

/**
 * スキャン1回分の「秘密情報と判定した値」の保管庫。
 *
 * 検出（classifySecret など）で秘密情報と判定した値そのものを、スキャンの間だけメモリに保持する。
 * 出力保護（protect.ts）は、形式に特徴のない値でも、ここにある値と同じ文字列が出力のどこかに現れたら伏せる。
 * 保管庫の中身は結果に含めず、ログにも出さない。スキャンごとに独立しており、並行して動くスキャン同士で混ざらない。
 */

const storage = new AsyncLocalStorage<Set<string>>();

/** 保管庫を用意して fn を実行する。fn には保管庫（読み取り専用）が渡る */
export function withSecretVault<T>(fn: (vault: ReadonlySet<string>) => Promise<T>): Promise<T> {
  const vault = new Set<string>();
  return storage.run(vault, () => fn(vault));
}

/** 秘密情報と判定した値を覚える。短すぎる値は一般的な文字列と区別できないため覚えない */
export function rememberSecret(value: string | undefined): void {
  const v = value?.trim();
  if (!v || v.length < 8) return;
  storage.getStore()?.add(v);
}
