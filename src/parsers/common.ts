import path from 'node:path';
import type { AgentId, ConfigScope, McpServer, McpTransport, ParsedConfig, UnparsedItem } from '../types.js';
import { isPlainObject, joinPointer } from '../util/jsonc.js';

export interface ParseContext {
  agent: AgentId;
  scope: ConfigScope;
  /** 表示用パス */
  file: string;
  /** 解析対象ディレクトリの絶対パス（~/.claude.json の projects 参照に使う） */
  root: string;
}

export function emptyParsed(): ParsedConfig {
  return { rules: [], settings: [], mcpServers: [], unparsed: [], secretHits: [] };
}

export function unparsed(ctx: ParseContext, pointer: string, reason: string): UnparsedItem {
  return { agent: ctx.agent, file: ctx.file, pointer: pointer || '(ルート)', reason };
}

/** 起動コマンドから実行ファイル名だけを取り出す。引数やパスは秘密情報を含みうるため捨てる */
export function commandNameOf(command: string): string | undefined {
  const first = command.trim().split(/\s+/)[0];
  if (!first) return undefined;
  const base = path.basename(first.replace(/\\/g, '/'));
  return base.replace(/\.(?:exe|cmd|bat|ps1)$/i, '') || undefined;
}

/** URL からホスト名だけを取り出す。変数展開を含むなど解析できないときは undefined */
export function hostOf(url: string): string | undefined {
  try {
    const u = new URL(url);
    return u.hostname || undefined;
  } catch {
    return undefined;
  }
}

/** 文字列配列を取り出し、文字列でない要素は未解析として記録する */
export function stringArray(
  ctx: ParseContext,
  value: unknown,
  pointer: string,
  out: ParsedConfig,
  nonStringReason = '文字列ではない要素のため解析できません',
): Array<{ value: string; pointer: string }> {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    out.unparsed.push(unparsed(ctx, pointer, '配列ではないため解析できません'));
    return [];
  }
  const items: Array<{ value: string; pointer: string }> = [];
  value.forEach((v, i) => {
    const ptr = joinPointer(pointer, i);
    if (typeof v === 'string') items.push({ value: v, pointer: ptr });
    else out.unparsed.push(unparsed(ctx, ptr, nonStringReason));
  });
  return items;
}

/**
 * MCP サーバー定義（Claude Code の .mcp.json / Cursor の mcp.json は概ね同じ形）を共通形式に変換する。
 * 値は保持せず、名前・種類・ホスト名だけを取り出す。
 */
export function parseMcpServers(
  ctx: ParseContext,
  servers: unknown,
  pointer: string,
  out: ParsedConfig,
  inferTransport: (def: Record<string, unknown>) => McpTransport,
): McpServer[] {
  if (servers === undefined) return [];
  if (!isPlainObject(servers)) {
    out.unparsed.push(unparsed(ctx, pointer, 'オブジェクトではないため MCP サーバー定義として解析できません'));
    return [];
  }
  const result: McpServer[] = [];
  for (const [name, def] of Object.entries(servers)) {
    const ptr = joinPointer(pointer, name);
    if (!isPlainObject(def)) {
      out.unparsed.push(unparsed(ctx, ptr, 'オブジェクトではないため MCP サーバー定義として解析できません'));
      continue;
    }
    const server: McpServer = {
      agent: ctx.agent,
      scope: ctx.scope,
      name,
      transport: inferTransport(def),
      envNames: isPlainObject(def.env) ? Object.keys(def.env).sort() : [],
      headerNames: isPlainObject(def.headers) ? Object.keys(def.headers).sort() : [],
      approval: 'unknown',
      source: { file: ctx.file, pointer: ptr },
      toolPermissions: 'unknown',
    };
    if (typeof def.command === 'string') server.commandName = commandNameOf(def.command);
    if (typeof def.url === 'string') {
      server.urlHost = hostOf(def.url);
      if (!server.urlHost) out.unparsed.push(unparsed(ctx, joinPointer(ptr, 'url'), '接続先URLを解析できません（変数展開を含む可能性があります）'));
    }
    if (def.env !== undefined && !isPlainObject(def.env)) out.unparsed.push(unparsed(ctx, joinPointer(ptr, 'env'), 'オブジェクトではないため解析できません'));
    if (def.headers !== undefined && !isPlainObject(def.headers)) out.unparsed.push(unparsed(ctx, joinPointer(ptr, 'headers'), 'オブジェクトではないため解析できません'));
    if (typeof def.envFile === 'string') out.unparsed.push(unparsed(ctx, joinPointer(ptr, 'envFile'), '外部の環境変数ファイルは読み取りません（中身は未検証）'));
    if (def.headersHelper !== undefined) out.unparsed.push(unparsed(ctx, joinPointer(ptr, 'headersHelper'), 'ヘッダー生成コマンドは実行・解析しません'));
    if (!server.commandName && !server.urlHost && def.url === undefined) {
      out.unparsed.push(unparsed(ctx, ptr, '起動コマンドも接続先URLも見つからないため、接続方式を判断できません'));
    }
    result.push(server);
  }
  return result;
}
