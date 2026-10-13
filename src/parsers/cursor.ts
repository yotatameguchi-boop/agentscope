import type { McpTransport, ParsedConfig, PermissionRule, RuleEffect } from '../types.js';
import { isPlainObject, joinPointer } from '../util/jsonc.js';
import { redactIfSecret, scanForSecrets } from '../util/secrets.js';
import { emptyParsed, parseMcpServers, stringArray, unparsed, type ParseContext } from './common.js';

/**
 * Cursor の設定パーサー。
 * 仕様: https://cursor.com/docs/reference/permissions , https://cursor.com/docs/context/mcp
 *
 * Cursor の permissions.json は「承認なしで実行してよいもの」の許可リストだけを持ち、
 * Claude Code のような deny / ask ルールはない。autoRun の指示文は分類器へのヒントで、強制力はない。
 */

export function inferCursorTransport(def: Record<string, unknown>): McpTransport {
  const t = typeof def.type === 'string' ? def.type.toLowerCase() : undefined;
  if (t === 'stdio' || t === 'sse') return t;
  if (t === 'http' || t === 'streamable-http' || t === 'streamablehttp') return 'http';
  if (t !== undefined) return 'unknown';
  if (typeof def.command === 'string') return 'stdio';
  // url だけのときは Cursor が Streamable HTTP / SSE を自動判別するため、設定からは確定できない
  return 'unknown';
}

export function parseCursorMcpJson(ctx: ParseContext, json: unknown): ParsedConfig {
  const out = emptyParsed();
  if (!isPlainObject(json)) {
    out.unparsed.push(unparsed(ctx, '', 'トップレベルがオブジェクトではないため解析できません'));
    return out;
  }
  out.secretHits.push(...scanForSecrets(json, 'cursor', ctx.file));
  if (json.mcpServers === undefined) out.unparsed.push(unparsed(ctx, 'mcpServers', 'mcpServers が見つかりません'));
  const servers = parseMcpServers(ctx, json.mcpServers, 'mcpServers', out, inferCursorTransport);
  for (const s of servers) {
    s.approvalNote = 'Cursor ではサーバーの有効・無効を IDE の設定画面で管理するため、設定ファイルからは不明';
  }
  out.mcpServers.push(...servers);
  for (const key of Object.keys(json)) {
    if (key !== 'mcpServers') out.unparsed.push(unparsed(ctx, joinPointer('', key), 'AgentScope が知らないキーです'));
  }
  return out;
}

const PERMISSIONS_NOTE = 'permissions.json の許可リストは IDE 側の許可リストを置き換えます';

export function parseCursorPermissions(ctx: ParseContext, json: unknown): ParsedConfig {
  const out = emptyParsed();
  if (!isPlainObject(json)) {
    out.unparsed.push(unparsed(ctx, '', 'トップレベルがオブジェクトではないため解析できません'));
    return out;
  }
  out.secretHits.push(...scanForSecrets(json, 'cursor', ctx.file));

  const ignored = 'Cursor は文字列以外の要素を無視します';
  for (const item of stringArray(ctx, json.mcpAllowlist, 'mcpAllowlist', out, ignored)) {
    const idx = item.value.indexOf(':');
    if (idx === -1) {
      out.unparsed.push(unparsed(ctx, item.pointer, '「サーバー:ツール」の形式ではないため Cursor に無視されます'));
      continue;
    }
    out.rules.push(rule(ctx, {
      effect: 'allow',
      category: 'mcp',
      tool: 'mcp',
      specifier: item.value,
      raw: item.value,
      nativeKind: 'cursor.mcpAllowlist',
      source: { file: ctx.file, pointer: item.pointer },
      note: PERMISSIONS_NOTE,
    }));
  }

  for (const item of stringArray(ctx, json.terminalAllowlist, 'terminalAllowlist', out, ignored)) {
    out.rules.push(rule(ctx, {
      effect: 'allow',
      category: 'command',
      tool: 'terminal',
      specifier: item.value,
      raw: item.value,
      nativeKind: 'cursor.terminalAllowlist',
      source: { file: ctx.file, pointer: item.pointer },
      note: `前方一致で判定されます。${PERMISSIONS_NOTE}`,
    }));
  }

  if (json.autoRun !== undefined) {
    if (!isPlainObject(json.autoRun)) {
      out.unparsed.push(unparsed(ctx, 'autoRun', 'オブジェクトではないため解析できません'));
    } else {
      const pairs: Array<[string, RuleEffect]> = [
        ['allow_instructions', 'guidance-allow'],
        ['block_instructions', 'guidance-block'],
      ];
      for (const [key, effect] of pairs) {
        for (const item of stringArray(ctx, json.autoRun[key], `autoRun.${key}`, out, ignored)) {
          out.rules.push(rule(ctx, {
            effect,
            category: 'other',
            tool: 'auto-review',
            specifier: item.value,
            raw: item.value,
            nativeKind: `cursor.autoRun.${key}`,
            source: { file: ctx.file, pointer: item.pointer },
            note: 'Auto-review 分類器への自然言語のヒントです。強制力はなく、内容の効果は判定していません',
          }));
        }
      }
      for (const key of Object.keys(json.autoRun)) {
        if (key !== 'allow_instructions' && key !== 'block_instructions') {
          out.unparsed.push(unparsed(ctx, joinPointer('autoRun', key), 'AgentScope が知らないキーです'));
        }
      }
    }
  }

  for (const key of Object.keys(json)) {
    if (!['mcpAllowlist', 'terminalAllowlist', 'autoRun'].includes(key)) {
      out.unparsed.push(unparsed(ctx, joinPointer('', key), 'AgentScope が知らないキーです'));
    }
  }
  return out;
}

function rule(ctx: ParseContext, r: Omit<PermissionRule, 'agent' | 'scope'>): PermissionRule {
  // 秘密情報を含む文字列は伏せて保持する
  const specifier = r.specifier === undefined ? undefined : redactIfSecret(r.specifier);
  return { agent: 'cursor', scope: ctx.scope, ...r, specifier, raw: redactIfSecret(r.raw) };
}
