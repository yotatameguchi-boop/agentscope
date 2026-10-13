import path from 'node:path';
import { tx, type Text } from '../i18n.js';
import { categorizeClaudeTool, ignoredReason, parseClaudeMcpJson, parseClaudeSettings, splitClaudeRule } from '../parsers/claude.js';
import { emptyParsed, type ParseContext } from '../parsers/common.js';
import type { AgentId, LaunchCommand, ParsedConfig, PermissionRule, PermissionSetting, RuleEffect } from '../types.js';
import { parseJsonc } from '../util/jsonc.js';
import { safeReadFile } from '../util/safeRead.js';
import { classifySecret, redactIfSecret } from '../util/secrets.js';

/**
 * 起動コマンド（claude / agent の引数）から、権限に関わるオプションを読み取る。コマンドは実行しない。
 * 仕様: https://code.claude.com/docs/en/cli-reference , https://cursor.com/docs/cli/reference/parameters
 */

export interface LaunchSource {
  /** 表示用のファイル名（--launch で渡されたものは "--launch"） */
  file: string;
  /** ファイル内の位置（scripts.dev、line 12 など） */
  pointer: string;
}

export interface LaunchParsed extends ParsedConfig {
  launch: LaunchCommand;
}

const CLAUDE_EXES = new Set(['claude']);
const CURSOR_EXES = new Set(['agent', 'cursor-agent']);
const CLAUDE_PACKAGES = /^@anthropic-ai\/claude-code(?:@.*)?$/;

/** 起動コマンドの前に置かれうるラッパー（引数のコマンドをそのまま実行する） */
const WRAPPERS = new Set(['exec', 'command', 'builtin', 'nohup', 'time', 'noglob', 'caffeinate']);

/** 1つのコマンド（語の列）がエージェントの起動かどうか。起動なら実行ファイルの位置を返す */
export function findInvocation(words: string[]): { agent: AgentId; exe: string; index: number; env: Array<[string, string]> } | undefined {
  const env: Array<[string, string]> = [];
  let i = 0;
  while (i < words.length) {
    const w = words[i]!;
    const assign = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s.exec(w);
    if (assign) {
      env.push([assign[1]!, assign[2]!]);
      i++;
      continue;
    }
    const base = exeName(w);
    if (WRAPPERS.has(base)) {
      i++;
      continue;
    }
    if (base === 'env') {
      i++;
      while (i < words.length && words[i]!.startsWith('-')) i++;
      continue;
    }
    if (base === 'timeout') {
      i += 2; // timeout <時間> <コマンド>
      continue;
    }
    if (base === 'npx' || base === 'bunx' || base === 'pnpx' || ((base === 'pnpm' || base === 'yarn') && words[i + 1] === 'dlx')) {
      let j = i + 1 + (base === 'pnpm' || base === 'yarn' ? 1 : 0);
      while (j < words.length && words[j]!.startsWith('-')) j++;
      if (CLAUDE_PACKAGES.test(words[j] ?? '')) return { agent: 'claude-code', exe: 'claude', index: j, env };
      return undefined;
    }
    if (CLAUDE_EXES.has(base)) return { agent: 'claude-code', exe: base, index: i, env };
    if (CURSOR_EXES.has(base)) return { agent: 'cursor', exe: base, index: i, env };
    return undefined;
  }
  return undefined;
}

function exeName(w: string): string {
  return path.basename(w.replace(/\\/g, '/')).replace(/\.(?:exe|cmd)$/i, '');
}

// ---- Claude Code のフラグ ------------------------------------------------------

/** 複数の値を取るフラグ（次のフラグが来るまで値が続く） */
const CLAUDE_VARIADIC = new Set(['--allowedTools', '--allowed-tools', '--disallowedTools', '--disallowed-tools', '--add-dir', '--mcp-config', '--channels']);

/** 値を1つ取るフラグ（権限と無関係なものも、値を位置引数と取り違えないために列挙する） */
const CLAUDE_VALUE = new Set([
  '--permission-mode', '--settings', '--setting-sources', '--tools', '--permission-prompt-tool', '--permission-prompts', '--plugin-dir',
  '--plugin-url', '--agents', '--agent', '--model', '--fallback-model', '--effort', '--append-system-prompt', '--append-system-prompt-file',
  '--system-prompt', '--system-prompt-file', '--append-subagent-system-prompt', '--append-subagent-system-prompt-file', '--system-prompt-snapshot',
  '--output-format', '--input-format', '--max-turns', '--max-budget-usd', '--json-schema', '--session-id', '--name', '-n', '--debug-file',
  '--betas', '--teammate-mode', '--from-pr', '--cloud', '--remote', '--environment', '--ref', '--autocompact', '--advisor', '--exec',
  '--remote-control-session-name-prefix', '--dangerously-load-development-channels',
]);

const NOT_ANALYZED: Record<string, Text> = {
  '--plugin-dir': tx('このオプションで読み込むプラグインは解析しません', 'Plugins loaded by this option are not analyzed'),
  '--plugin-url': tx('このオプションで読み込むプラグインは解析しません', 'Plugins loaded by this option are not analyzed'),
  '--agents': tx('このオプションで定義するサブエージェントは解析しません', 'Subagents defined by this option are not analyzed'),
  '--channels': tx('チャンネルの設定は解析しません', 'Channel settings are not analyzed'),
  '--dangerously-load-development-channels': tx('許可リスト外のチャンネルを読み込みます（内容は解析しません）', 'Loads channels outside the allowlist (contents not analyzed)'),
  '--permission-prompt-tool': tx('承認を代行する MCP ツールの判断内容は解析しません', 'Decisions made by the permission prompt tool are not analyzed'),
};

/**
 * 権限ルールらしい語か（"Bash(git log *)"、"Read"、"mcp__github__x" など）。プロンプト文を取り込まないための判定。
 * Claude Code のツール名は大文字で始まる（MCP ツールは mcp__ で始まる）
 */
function looksLikeRule(w: string): boolean {
  return /^(?:\*|[A-Z][A-Za-z]*\*?|mcp__[\w*-]+)(?:\(.*\))?$/s.test(w.trim());
}

/** カンマ区切りのルール列を、括弧の中のカンマでは区切らずに分ける */
function splitRuleList(value: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = '';
  for (const ch of value) {
    if (ch === '(') depth++;
    if (ch === ')') depth = Math.max(0, depth - 1);
    if ((ch === ',' || ch === ' ') && depth === 0) {
      if (cur.trim()) out.push(cur.trim());
      cur = '';
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

interface FlagArg {
  flag: string;
  values: string[];
  /** words 内の位置（ポインタ表示用） */
  index: number;
}

/** フラグと値を取り出す。--flag=value と --flag value の両方を扱う */
function readFlags(args: string[], variadic: Set<string>, single: Set<string>): FlagArg[] {
  const out: FlagArg[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (!a.startsWith('-') || a === '-' || a === '--') continue;
    const eq = a.indexOf('=');
    const flag = eq > 0 && a.startsWith('--') ? a.slice(0, eq) : a;
    const inline = eq > 0 && a.startsWith('--') ? a.slice(eq + 1) : undefined;
    const values: string[] = inline !== undefined ? [inline] : [];
    if (inline === undefined && single.has(flag) && i + 1 < args.length) {
      values.push(args[++i]!);
    } else if (inline === undefined && variadic.has(flag)) {
      while (i + 1 < args.length && !args[i + 1]!.startsWith('-')) {
        const next = args[i + 1]!;
        // --allowedTools の後ろのプロンプト文などは値に含めない
        if (/Tools$|tools$/.test(flag) && !splitRuleList(next).every(looksLikeRule)) break;
        values.push(next);
        i++;
      }
    }
    out.push({ flag, values, index: i });
  }
  return out;
}

export interface LaunchOptions {
  root: string;
  source: LaunchSource;
  launchId: string;
}

/** 起動コマンド1つを解析する。--settings / --mcp-config のファイルは対象ディレクトリ内のものだけ読む */
export async function parseLaunch(words: string[], opts: LaunchOptions): Promise<LaunchParsed | undefined> {
  const inv = findInvocation(words);
  if (!inv) return undefined;
  const args = words.slice(inv.index + 1);
  const out: LaunchParsed = {
    ...emptyParsed(),
    launch: { agent: inv.agent, executable: inv.exe, source: { ...opts.source }, launchId: opts.launchId, options: [] },
  };
  const { file } = opts.source;
  const at = (suffix: string) => `${opts.source.pointer} ${suffix}`.trim();
  const ctx: ParseContext = { agent: inv.agent, scope: 'cli', file, root: opts.root };

  // 秘密情報: 環境変数の代入と、各引数
  for (const [k, v] of inv.env) {
    const hit = classifySecret(k, v);
    if (hit) out.secretHits.push({ agent: inv.agent, file, pointer: at(k), ...hit });
  }
  args.forEach((a, i) => {
    if (a.trim().startsWith('{')) return; // インライン JSON は parseEmbedded で項目ごとに検査する
    const prev = args[i - 1];
    const keyName = prev?.startsWith('-') ? prev.replace(/^-+/, '') : undefined;
    const hit = classifySecret(keyName, a);
    if (hit) out.secretHits.push({ agent: inv.agent, file, pointer: at(`args[${i}]`), ...hit });
  });

  if (inv.agent === 'claude-code') await parseClaudeFlags(args, opts, ctx, out, at);
  else parseCursorFlags(args, ctx, out, at);
  return out;
}

async function parseClaudeFlags(args: string[], opts: LaunchOptions, ctx: ParseContext, out: LaunchParsed, at: (s: string) => string) {
  const setting = (key: string, value: string | Text, pointer: string) => {
    const s: PermissionSetting = { agent: 'claude-code', scope: 'cli', key, value, source: { file: ctx.file, pointer }, status: 'active', launchId: opts.launchId };
    out.settings.push(s);
  };
  const option = (flag: string, value?: string) => out.launch.options.push(value === undefined ? { flag } : { flag, value: redactIfSecret(value) });

  for (const { flag, values } of readFlags(args, CLAUDE_VARIADIC, CLAUDE_VALUE)) {
    const v = values[0];
    switch (flag) {
      case '--permission-mode':
        if (v !== undefined) {
          const mode = v === 'manual' ? 'default' : v;
          setting('permissions.defaultMode', mode, at(flag));
          option(flag, mode);
        }
        break;
      case '--dangerously-skip-permissions':
        setting('permissions.defaultMode', 'bypassPermissions', at(flag));
        option(flag);
        break;
      case '--allow-dangerously-skip-permissions':
        setting('allowDangerouslySkipPermissions', 'true', at(flag));
        option(flag);
        break;
      case '--allowedTools':
      case '--allowed-tools':
      case '--disallowedTools':
      case '--disallowed-tools': {
        const effect: RuleEffect = /^--allowed/.test(flag) ? 'allow' : 'deny';
        const raws = values.flatMap(splitRuleList);
        raws.forEach((raw, i) => pushRule(out, ctx, opts.launchId, raw, effect, at(`${flag}[${i}]`), flag));
        option(flag, tx(`${raws.length} 件`, `${raws.length} rule(s)`).en);
        break;
      }
      case '--add-dir':
        values.forEach((d, i) => setting('permissions.additionalDirectories', d, at(`${flag}[${i}]`)));
        option(flag, values.map((d) => redactIfSecret(d)).join(' '));
        break;
      case '--tools':
        if (v !== undefined) setting('tools', v === '' ? tx('(なし)', '(none)') : v, at(flag));
        option(flag, v);
        break;
      case '--setting-sources':
        if (v !== undefined) {
          setting('settingSources', v, at(flag));
          option(flag, v);
        }
        break;
      case '--strict-mcp-config':
      case '--bare':
      case '--safe-mode':
      case '--restricted':
        setting(flag.slice(2), 'true', at(flag));
        option(flag);
        break;
      case '--settings':
        if (v !== undefined) await parseEmbedded(v, 'settings', opts, ctx, out, at(flag));
        option(flag, v?.trim().startsWith('{') ? '(inline JSON)' : undefined);
        break;
      case '--mcp-config':
        for (const [i, item] of values.entries()) await parseEmbedded(item, 'mcp', opts, ctx, out, at(`${flag}[${i}]`));
        option(flag, `${values.length}`);
        break;
      default:
        if (flag in NOT_ANALYZED) {
          out.unparsed.push({ agent: 'claude-code', file: ctx.file, pointer: at(flag), reason: NOT_ANALYZED[flag]! });
          option(flag);
        } else if (flag === '-p' || flag === '--print') {
          option(flag);
        }
    }
  }
}

function pushRule(out: LaunchParsed, ctx: ParseContext, launchId: string, raw: string, effect: RuleEffect, pointer: string, flag: string) {
  const split = splitClaudeRule(raw);
  if (!split) {
    out.unparsed.push({ agent: 'claude-code', file: ctx.file, pointer, reason: tx('権限ルールの書式として解釈できません', 'Cannot be interpreted as a permission rule') });
    return;
  }
  const rule: PermissionRule = {
    agent: 'claude-code',
    scope: 'cli',
    effect,
    category: categorizeClaudeTool(split.tool),
    tool: split.tool,
    specifier: split.specifier === undefined ? undefined : redactIfSecret(split.specifier),
    raw: redactIfSecret(raw),
    nativeKind: `claude.cli.${flag.replace(/^--/, '')}`,
    source: { file: ctx.file, pointer },
    status: 'active',
    launchId,
  };
  // 括弧付きの mcp__ ルールは設定ファイルでは無視されるが、--disallowedTools では使える
  const ignored = split.tool.startsWith('mcp__') && split.specifier !== undefined ? undefined : ignoredReason(split.tool, split.specifier, effect);
  if (ignored) {
    rule.status = 'ignored';
    rule.statusNote = ignored;
  }
  out.rules.push(rule);
}

/** --settings / --mcp-config の値（インライン JSON またはファイル）を解析する */
async function parseEmbedded(value: string, kind: 'settings' | 'mcp', opts: LaunchOptions, ctx: ParseContext, out: LaunchParsed, pointer: string) {
  let text: string;
  if (value.trim().startsWith('{')) {
    text = value;
  } else {
    const p = path.resolve(opts.root, value);
    const read = await safeReadFile(p, { confineTo: opts.root });
    if (!read.ok) {
      out.unparsed.push({
        agent: 'claude-code',
        file: ctx.file,
        pointer,
        reason: read.missing
          ? tx('指定されたファイルが対象ディレクトリ内に見つからないため解析していません', 'The referenced file was not found in the target directory, so it was not analyzed')
          : read.reason,
      });
      return;
    }
    text = read.text;
  }
  const json = parseJsonc(text);
  if (!json.ok) {
    out.unparsed.push({ agent: 'claude-code', file: ctx.file, pointer, reason: json.reason });
    return;
  }
  const parsed = kind === 'settings' ? parseClaudeSettings(ctx, json.value) : parseClaudeMcpJson(ctx, json.value);
  // ポインタを「起動コマンドの位置 › JSON 内の位置」にそろえる
  const rebase = (p: string) => `${pointer} › ${p}`;
  for (const r of parsed.rules) out.rules.push({ ...r, source: { ...r.source, pointer: rebase(r.source.pointer) }, launchId: opts.launchId });
  for (const s of parsed.settings) out.settings.push({ ...s, source: { ...s.source, pointer: rebase(s.source.pointer) }, launchId: opts.launchId });
  for (const m of parsed.mcpServers) {
    out.mcpServers.push({ ...m, source: { ...m.source, pointer: rebase(m.source.pointer) }, approval: 'not-required', approvalNote: tx('起動オプションで指定されたサーバー', 'Specified by a launch option') });
  }
  for (const u of parsed.unparsed) out.unparsed.push({ ...u, pointer: rebase(u.pointer) });
  for (const h of parsed.secretHits) out.secretHits.push({ ...h, pointer: rebase(h.pointer) });
}

// ---- Cursor（agent / cursor-agent）のフラグ ------------------------------------

const CURSOR_VALUE = new Set(['--sandbox', '--workspace', '--model', '--output-format', '--api-key', '--resume', '-H', '--header']);

function parseCursorFlags(args: string[], ctx: ParseContext, out: LaunchParsed, at: (s: string) => string) {
  const setting = (key: string, value: string, pointer: string) =>
    out.settings.push({ agent: 'cursor', scope: 'cli', key, value, source: { file: ctx.file, pointer }, status: 'active', launchId: out.launch.launchId });
  const option = (flag: string, value?: string) => out.launch.options.push(value === undefined ? { flag } : { flag, value });

  for (const { flag, values } of readFlags(args, new Set(), CURSOR_VALUE)) {
    const v = values[0];
    switch (flag) {
      case '-f':
      case '--force':
      case '--yolo':
        setting('force', 'true', at(flag));
        option(flag);
        break;
      case '--approve-mcps':
        setting('approveMcps', 'true', at(flag));
        option(flag);
        break;
      case '--trust':
        setting('trust', 'true', at(flag));
        option(flag);
        break;
      case '--sandbox':
        if (v !== undefined) {
          setting('sandbox', v, at(flag));
          option(flag, v);
        }
        break;
      case '--api-key':
        // 値は表示しない。参照（$VAR）でない値は、引数の検査（classifySecret）で R004 として検出される
        option(flag, '[REDACTED]');
        break;
      case '-p':
      case '--print':
        option(flag);
        break;
    }
  }
}
