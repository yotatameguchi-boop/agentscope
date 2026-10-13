/**
 * 表示文言の多言語化。
 *
 * パーサーや検査ルールは文言を日英の組（Text）で持ち、言語の選択は出力の直前（localize）で行う。
 * こうすることで、検査ロジックが言語に依存せず、JSON 出力も選んだ言語でそろう。
 */

export type Lang = 'ja' | 'en';
export const LANGS: readonly Lang[] = ['ja', 'en'];

export interface Text {
  readonly ja: string;
  readonly en: string;
}

export function tx(ja: string, en: string): Text {
  return { ja, en };
}

export function isText(v: unknown): v is Text {
  return typeof v === 'object' && v !== null && !Array.isArray(v) && Object.keys(v).length === 2 && typeof (v as Text).ja === 'string' && typeof (v as Text).en === 'string';
}

/** Text を string に置き換えた型 */
export type Localized<T> = T extends Text
  ? string
  : T extends readonly (infer U)[]
    ? Localized<U>[]
    : T extends object
      ? { [K in keyof T]: Localized<T[K]> }
      : T;

/** オブジェクトをたどり、Text をすべて指定言語の文字列に置き換える */
export function localize<T>(value: T, lang: Lang): Localized<T> {
  const visit = (v: unknown): unknown => {
    if (isText(v)) return v[lang];
    if (Array.isArray(v)) return v.map(visit);
    if (typeof v === 'object' && v !== null) {
      return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, visit(x)]));
    }
    return v;
  };
  return visit(value) as Localized<T>;
}

/**
 * 環境変数から表示言語を決める。AGENTSCOPE_LANG を最優先し、次に LC_ALL / LC_MESSAGES / LANG を見る。
 * 日本語のロケールなら ja、それ以外は en。
 */
export function detectLang(env: NodeJS.ProcessEnv = process.env): Lang {
  const explicit = env.AGENTSCOPE_LANG?.toLowerCase();
  if (explicit === 'ja' || explicit === 'en') return explicit;
  const locale = env.LC_ALL || env.LC_MESSAGES || env.LANG || '';
  if (/^ja\b|^ja[_-]/i.test(locale)) return 'ja';
  if (!locale && Intl.DateTimeFormat().resolvedOptions().locale.startsWith('ja')) return 'ja';
  return 'en';
}
