import { createScanner, printParseErrorCode, SyntaxKind, visit, type ParseError } from 'jsonc-parser';
import { tx, type Text } from '../i18n.js';

export type JsoncResult = { ok: true; value: unknown } | { ok: false; reason: Text };

/** 設定ファイルとして許す入れ子の深さ。これを超えるものは解析しない（スタックあふれを防ぐ） */
export const MAX_DEPTH = 256;

/**
 * JSON / JSONC（コメント・末尾カンマ）を解析する。エラー位置は行番号で返し、内容は返さない。
 *
 * - オブジェクトはプロトタイプを持たない形で組み立てる。"__proto__" というキーがあっても
 *   プロトタイプが差し替わらず、書かれていないキー（例: permissions.allow）が見えてしまうことがない
 * - 先にトークン単位で入れ子の深さを数え、深すぎる入力は解析前に拒否する
 */
export function parseJsonc(text: string): JsoncResult {
  const depth = maxDepth(text);
  if (depth > MAX_DEPTH) {
    return { ok: false, reason: tx(`入れ子が深すぎるため解析しません（上限 ${MAX_DEPTH}）`, `Nesting is too deep to parse (limit ${MAX_DEPTH})`) };
  }

  const errors: ParseError[] = [];
  const stack: Array<Record<string, unknown> | unknown[]> = [];
  let root: unknown;
  let pendingKey = '';

  const put = (value: unknown) => {
    const top = stack[stack.length - 1];
    if (!top) root = value;
    else if (Array.isArray(top)) top.push(value);
    // 重複キーは後勝ち（JSON.parse と同じ）。defineProperty なので "__proto__" も通常のキーになる
    else Object.defineProperty(top, pendingKey, { value, enumerable: true, writable: true, configurable: true });
  };

  visit(
    text,
    {
      onObjectBegin: () => {
        const obj = Object.create(null) as Record<string, unknown>;
        put(obj);
        stack.push(obj);
      },
      onObjectProperty: (property) => {
        pendingKey = property;
      },
      onObjectEnd: () => {
        stack.pop();
      },
      onArrayBegin: () => {
        const arr: unknown[] = [];
        put(arr);
        stack.push(arr);
      },
      onArrayEnd: () => {
        stack.pop();
      },
      onLiteralValue: (value) => put(value),
      onError: (error, offset) => {
        errors.push({ error, offset, length: 0 });
      },
    },
    { allowTrailingComma: true, disallowComments: false },
  );

  if (errors.length > 0) {
    const first = errors[0]!;
    const line = text.slice(0, first.offset).split('\n').length;
    const code = printParseErrorCode(first.error);
    return { ok: false, reason: tx(`JSONC として解析できません（${line}行目: ${code}）`, `Cannot parse as JSONC (line ${line}: ${code})`) };
  }
  return { ok: true, value: root };
}

/** 文字列・コメントの中は数えずに、括弧の入れ子の最大深さを求める（再帰しない） */
function maxDepth(text: string): number {
  const scanner = createScanner(text, true);
  let depth = 0;
  let max = 0;
  for (let kind = scanner.scan(); kind !== SyntaxKind.EOF; kind = scanner.scan()) {
    if (kind === SyntaxKind.OpenBraceToken || kind === SyntaxKind.OpenBracketToken) {
      depth++;
      if (depth > max) max = depth;
      if (max > MAX_DEPTH) return max;
    } else if (kind === SyntaxKind.CloseBraceToken || kind === SyntaxKind.CloseBracketToken) {
      depth--;
    }
  }
  return max;
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
