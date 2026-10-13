import type { McpTransport, ParsedConfig, PermissionRule, RuleEffect } from '../types.js';
import { isPlainObject } from '../util/jsonc.js';
import { joinPointer } from '../util/pointer.js';
import { redactIfSecret, scanForSecrets } from '../util/secrets.js';
import { tx } from '../i18n.js';
import { emptyParsed, MSG, parseMcpServers, stringArray, unparsed, type ParseContext } from './common.js';

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
    out.unparsed.push(unparsed(ctx, '', MSG.rootNotObject));
    return out;
  }
  out.secretHits.push(...scanForSecrets(json, 'cursor', ctx.file));
  if (json.mcpServers === undefined) out.unparsed.push(unparsed(ctx, 'mcpServers', MSG.noMcpServers));
  const servers = parseMcpServers(ctx, json.mcpServers, 'mcpServers', out, inferCursorTransport);
  for (const s of servers) {
    s.approvalNote = tx(
      'Cursor ではサーバーの有効・無効を IDE の設定画面で管理するため、設定ファイルからは不明',
      'Cursor manages enabling servers in the IDE settings, so this is unknown from config files',
    );
  }
  out.mcpServers.push(...servers);
  for (const key of Object.keys(json)) {
    if (key !== 'mcpServers') out.unparsed.push(unparsed(ctx, joinPointer('', key), MSG.unknownKey));
  }
  return out;
}

const PERMISSIONS_NOTE = tx('permissions.json の許可リストは IDE 側の許可リストを置き換えます', 'Allowlists in permissions.json replace the IDE allowlist');

export function parseCursorPermissions(ctx: ParseContext, json: unknown): ParsedConfig {
  const out = emptyParsed();
  if (!isPlainObject(json)) {
    out.unparsed.push(unparsed(ctx, '', MSG.rootNotObject));
    return out;
  }
  out.secretHits.push(...scanForSecrets(json, 'cursor', ctx.file));

  const ignored = tx('Cursor は文字列以外の要素を無視します', 'Cursor ignores non-string entries');
  for (const item of stringArray(ctx, json.mcpAllowlist, 'mcpAllowlist', out, ignored)) {
    const idx = item.value.indexOf(':');
    if (idx === -1) {
      out.unparsed.push(unparsed(ctx, item.pointer, tx('「サーバー:ツール」の形式ではないため Cursor に無視されます', 'Not in "server:tool" form, so Cursor ignores it')));
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
      note: tx(`前方一致で判定されます。${PERMISSIONS_NOTE.ja}`, `Matched by prefix. ${PERMISSIONS_NOTE.en}`),
    }));
  }

  if (json.autoRun !== undefined) {
    if (!isPlainObject(json.autoRun)) {
      out.unparsed.push(unparsed(ctx, 'autoRun', MSG.notObject));
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
            note: tx(
              'Auto-review 分類器への自然言語のヒントです。強制力はなく、内容の効果は判定していません',
              'A natural-language hint for the Auto-review classifier. It is not enforced, and its effect is not assessed',
            ),
          }));
        }
      }
      for (const key of Object.keys(json.autoRun)) {
        if (key !== 'allow_instructions' && key !== 'block_instructions') {
          out.unparsed.push(unparsed(ctx, joinPointer('autoRun', key), MSG.unknownKey));
        }
      }
    }
  }

  for (const key of Object.keys(json)) {
    if (!['mcpAllowlist', 'terminalAllowlist', 'autoRun'].includes(key)) {
      out.unparsed.push(unparsed(ctx, joinPointer('', key), MSG.unknownKey));
    }
  }
  return out;
}

function rule(ctx: ParseContext, r: Omit<PermissionRule, 'agent' | 'scope' | 'status'>): PermissionRule {
  // 秘密情報を含む文字列は伏せて保持する
  const specifier = r.specifier === undefined ? undefined : redactIfSecret(r.specifier);
  return { agent: 'cursor', scope: ctx.scope, ...r, specifier, raw: redactIfSecret(r.raw), status: 'active' };
}

// ---- Cursor CLI（.cursor/cli.json, ~/.cursor/cli-config.json） -----------------

const CLI_TOOLS: Record<string, PermissionRule['category']> = {
  Shell: 'command',
  Read: 'file-read',
  Write: 'file-write',
  WebFetch: 'network',
  Mcp: 'mcp',
};

/**
 * Cursor CLI の権限設定。permissions.allow / deny に Shell(cmd) / Read(glob) / Write(glob) / WebFetch(domain) / Mcp(server:tool) を書く。
 * deny は allow より優先される。cli-config.json には CLI の他の設定も入るため、permissions 以外のキーは読み飛ばす。
 * 仕様: https://cursor.com/docs/cli/reference/permissions
 */
export function parseCursorCli(ctx: ParseContext, json: unknown): ParsedConfig {
  const out = emptyParsed();
  if (!isPlainObject(json)) {
    out.unparsed.push(unparsed(ctx, '', MSG.rootNotObject));
    return out;
  }
  if (json.permissions === undefined) return out;
  out.secretHits.push(...scanForSecrets(json.permissions, 'cursor', ctx.file, 'permissions'));
  if (!isPlainObject(json.permissions)) {
    out.unparsed.push(unparsed(ctx, 'permissions', MSG.notObject));
    return out;
  }
  for (const effect of ['allow', 'deny'] as const) {
    for (const item of stringArray(ctx, json.permissions[effect], `permissions.${effect}`, out)) {
      const m = /^\s*([A-Za-z]+)\s*\((.*)\)\s*$/s.exec(item.value);
      const category = m ? CLI_TOOLS[m[1]!] : undefined;
      if (!m || !category) {
        out.unparsed.push(unparsed(ctx, item.pointer, tx('Cursor CLI の権限トークンとして解釈できません', 'Cannot be interpreted as a Cursor CLI permission token')));
        continue;
      }
      out.rules.push(rule(ctx, {
        effect,
        category,
        tool: m[1]!,
        specifier: m[2]!.trim(),
        raw: item.value,
        nativeKind: `cursor.cli.permissions.${effect}`,
        source: { file: ctx.file, pointer: item.pointer },
        note: m[1] === 'Shell' ? tx('コマンドの先頭部分（commandBase）で判定されます', 'Matched by command base') : undefined,
      }));
    }
  }
  for (const key of Object.keys(json.permissions)) {
    if (key !== 'allow' && key !== 'deny') out.unparsed.push(unparsed(ctx, joinPointer('permissions', key), MSG.unknownKey));
  }
  return out;
}
