import { parse, printParseErrorCode, type ParseError } from 'jsonc-parser';
import { tx, type Text } from '../i18n.js';

export type JsoncResult = { ok: true; value: unknown } | { ok: false; reason: Text };

/** JSON / JSONC（コメント・末尾カンマ）を解析する。エラー位置は行番号で返し、内容は返さない */
export function parseJsonc(text: string): JsoncResult {
  const errors: ParseError[] = [];
  const value = parse(text, errors, { allowTrailingComma: true, disallowComments: false });
  if (errors.length > 0) {
    const first = errors[0]!;
    const line = text.slice(0, first.offset).split('\n').length;
    const code = printParseErrorCode(first.error);
    return { ok: false, reason: tx(`JSONC として解析できません（${line}行目: ${code}）`, `Cannot parse as JSONC (line ${line}: ${code})`) };
  }
  return { ok: true, value };
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** JSON ポインタ風の表示用パスを組み立てる（例: mcpServers.github.env.TOKEN, permissions.allow[2]） */
export function joinPointer(base: string, key: string | number): string {
  if (typeof key === 'number') return `${base}[${key}]`;
  const safe = /^[A-Za-z_$][\w$-]*$/.test(key) ? key : JSON.stringify(key);
  return base ? `${base}.${safe}` : safe;
}
