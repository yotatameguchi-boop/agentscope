import path from 'node:path';
import type { McpServer, McpTransport, ParsedConfig, PermissionRule, RuleCategory, RuleEffect } from '../types.js';
import { isPlainObject, joinPointer } from '../util/jsonc.js';
import { redactIfSecret, scanForSecrets } from '../util/secrets.js';
import { tx, type Text } from '../i18n.js';
import { emptyParsed, MSG, parseMcpServers, stringArray, unparsed, type ParseContext } from './common.js';

/**
 * Claude Code の設定パーサー。
 * 仕様: https://code.claude.com/docs/en/settings , https://code.claude.com/docs/en/permissions
 */

/** .mcp.json のサーバー承認に関わる設定。複数ファイルにまたがるため後でまとめて解決する */
export interface ClaudeMcpApprovalHints {
  enableAll?: { value: boolean; file: string };
  enabled: Array<{ name: string; file: string }>;
  disabled: Array<{ name: string; file: string }>;
}

export interface ClaudeParsed extends ParsedConfig {
  approvalHints: ClaudeMcpApprovalHints;
}

function emptyClaude(): ClaudeParsed {
  return { ...emptyParsed(), approvalHints: { enabled: [], disabled: [] } };
}

// ---- 権限ルール文字列 -------------------------------------------------------

const FILE_READ_TOOLS = new Set(['Read', 'Grep', 'Glob', 'LS']);
const FILE_WRITE_TOOLS = new Set(['Edit', 'Write', 'MultiEdit', 'NotebookEdit']);
const COMMAND_TOOLS = new Set(['Bash', 'PowerShell']);
const NETWORK_TOOLS = new Set(['WebFetch', 'WebSearch']);
const OTHER_TOOLS = new Set(['Agent', 'Task', 'Skill', 'TodoWrite', 'AskUserQuestion', 'NotebookRead', 'ExitPlanMode', 'SlashCommand', 'BashOutput', 'KillShell']);

export function categorizeClaudeTool(tool: string): RuleCategory {
  if (tool.startsWith('mcp__')) return 'mcp';
  if (COMMAND_TOOLS.has(tool)) return 'command';
  if (FILE_READ_TOOLS.has(tool)) return 'file-read';
  if (FILE_WRITE_TOOLS.has(tool)) return 'file-write';
  if (NETWORK_TOOLS.has(tool)) return 'network';
  if (OTHER_TOOLS.has(tool)) return 'other';
  return 'unknown';
}

/** "Bash(npm run *)" → { tool: "Bash", specifier: "npm run *" }。形式が崩れていれば undefined */
export function splitClaudeRule(raw: string): { tool: string; specifier?: string } | undefined {
  const s = raw.trim();
  if (!s) return undefined;
  const open = s.indexOf('(');
  if (open === -1) return /[()]/.test(s) ? undefined : { tool: s };
  if (!s.endsWith(')') || open === 0) return undefined;
  return { tool: s.slice(0, open).trim(), specifier: s.slice(open + 1, -1) };
}

function parseRuleList(ctx: ParseContext, list: unknown, pointer: string, effect: RuleEffect, out: ParsedConfig) {
  for (const item of stringArray(ctx, list, pointer, out)) {
    const split = splitClaudeRule(item.value);
    if (!split) {
      out.unparsed.push(unparsed(ctx, item.pointer, tx('権限ルールの書式として解釈できません', 'Cannot be interpreted as a permission rule')));
      continue;
    }
    const rule: PermissionRule = {
      agent: 'claude-code',
      scope: ctx.scope,
      effect,
      category: categorizeClaudeTool(split.tool),
      tool: split.tool,
      // 秘密情報を含むルール（例: Bash(curl -H "Authorization: Bearer ...")）は伏せて保持する
      specifier: split.specifier === undefined ? undefined : redactIfSecret(split.specifier),
      raw: redactIfSecret(item.value),
      nativeKind: `claude.permissions.${effect}`,
      source: { file: ctx.file, pointer: item.pointer },
    };
    if (rule.category === 'unknown') rule.note = tx('AgentScope が知らないツール名です。権限の範囲は判断していません', 'Tool name not known to AgentScope; its scope was not assessed');
    if (split.tool.startsWith('mcp__') && split.specifier !== undefined) {
      rule.note = tx('Claude Code は括弧付きの mcp__ ルールを設定ファイルから読み込まず、無視します', 'Claude Code skips mcp__ rules with parentheses when loading settings files');
    }
    if ((split.tool === 'Write' || split.tool === 'MultiEdit' || split.tool === 'NotebookEdit' || split.tool === 'Glob') && split.specifier) {
      rule.note = tx(
        `パス指定付きの ${split.tool} ルールはファイル権限の判定に使われません（Edit / Read を使います）`,
        `${split.tool} rules with a path are not used for file permission checks (Edit / Read are used instead)`,
      );
    }
    out.rules.push(rule);
  }
}

// ---- settings.json ------------------------------------------------------------

/** 権限分析には関係しない既知のキー。未解析としても表示しない */
const IGNORED_SETTINGS_KEYS = new Set([
  '$schema', 'model', 'availableModels', 'theme', 'cleanupPeriodDays', 'includeCoAuthoredBy', 'attribution', 'outputStyle',
  'language', 'forceLoginMethod', 'forceLoginOrgUUID', 'spinnerTipsEnabled', 'spinnerVerbs', 'spinnerTipsOverride',
  'alwaysThinkingEnabled', 'autoUpdatesChannel', 'companyAnnouncements', 'respectGitignore', 'effortLevel',
  'autoMemoryEnabled', 'verbose', 'preferredNotifChannel', 'feedbackSurveyRate', 'showTurnDuration', 'terminalProgressBarEnabled',
  'promptSuggestionEnabled', 'prefersReducedMotion', 'editorMode', 'viewMode', 'fastMode', 'plansDirectory', 'autoCompactEnabled',
]);

/** 実行やネットワークに関わるが、v0.1 では中身を解析しないキー */
const UNANALYZED_SECURITY_KEYS: Record<string, Text> = {
  hooks: tx('フック（自動実行されるコマンド）は v0.1 では解析しません', 'Hooks (automatically executed commands) are not analyzed in v0.1'),
  statusLine: tx('ステータスライン用のコマンドは v0.1 では解析しません', 'The status line command is not analyzed in v0.1'),
  fileSuggestion: tx('ファイル候補用のコマンドは v0.1 では解析しません', 'The file suggestion command is not analyzed in v0.1'),
  enabledPlugins: tx('プラグインが追加する権限・MCP サーバーは v0.1 では解析しません', 'Permissions and MCP servers added by plugins are not analyzed in v0.1'),
  extraKnownMarketplaces: tx('プラグインのマーケットプレイス設定は v0.1 では解析しません', 'Plugin marketplace settings are not analyzed in v0.1'),
  awsAuthRefresh: tx('認証更新コマンドは v0.1 では解析しません', 'The auth refresh command is not analyzed in v0.1'),
  awsCredentialExport: tx('認証情報出力コマンドは v0.1 では解析しません', 'The credential export command is not analyzed in v0.1'),
  otelHeadersHelper: tx('ヘッダー生成コマンドは v0.1 では解析しません', 'The header helper command is not analyzed in v0.1'),
  allowedHttpHookUrls: tx('フックの通信先設定は v0.1 では解析しません', 'Hook URL settings are not analyzed in v0.1'),
  mcpServers: tx(
    'settings.json 内の mcpServers は Claude Code の MCP 設定の場所ではないため解析しません（.mcp.json または ~/.claude.json を使います）',
    'mcpServers in settings.json is not where Claude Code reads MCP config, so it is not analyzed (.mcp.json or ~/.claude.json is used)',
  ),
};

const KNOWN_PERMISSION_KEYS = new Set([
  'allow', 'deny', 'ask', 'defaultMode', 'disableBypassPermissionsMode', 'disableAutoMode', 'additionalDirectories',
  'blockReadsOutsideWorkingDirectories',
]);

function pushSetting(ctx: ParseContext, out: ParsedConfig, key: string, value: string | Text, pointer: string) {
  const shown = typeof value === 'string' ? redactIfSecret(value) : value;
  out.settings.push({ agent: 'claude-code', scope: ctx.scope, key, value: shown, source: { file: ctx.file, pointer } });
}

function describeScalar(v: unknown): string | Text {
  if (typeof v === 'string') return v;
  if (typeof v === 'boolean' || typeof v === 'number') return String(v);
  if (v === null) return 'null';
  return Array.isArray(v) ? tx(`配列（${v.length}件）`, `array (${v.length} items)`) : tx('オブジェクト', 'object');
}

export function parseClaudeSettings(ctx: ParseContext, json: unknown): ClaudeParsed {
  const out = emptyClaude();
  if (!isPlainObject(json)) {
    out.unparsed.push(unparsed(ctx, '', MSG.rootNotObject));
    return out;
  }
  out.secretHits.push(...scanForSecrets(json, 'claude-code', ctx.file));

  for (const [key, value] of Object.entries(json)) {
    const ptr = joinPointer('', key);
    switch (key) {
      case 'permissions':
        parsePermissionsBlock(ctx, value, out);
        break;
      case 'enableAllProjectMcpServers':
        if (typeof value === 'boolean') {
          pushSetting(ctx, out, key, String(value), ptr);
          out.approvalHints.enableAll = { value, file: ctx.file };
        } else out.unparsed.push(unparsed(ctx, ptr, MSG.notBoolean));
        break;
      case 'enabledMcpjsonServers':
      case 'disabledMcpjsonServers': {
        const names = stringArray(ctx, value, ptr, out);
        for (const n of names) (key === 'enabledMcpjsonServers' ? out.approvalHints.enabled : out.approvalHints.disabled).push({ name: n.value, file: ctx.file });
        pushSetting(ctx, out, key, names.map((n) => n.value).join(', ') || tx('(なし)', '(none)'), ptr);
        break;
      }
      case 'allowedMcpServers':
      case 'deniedMcpServers':
        pushSetting(ctx, out, key, describeScalar(value), ptr);
        out.unparsed.push(unparsed(ctx, ptr, tx('MCP サーバーの許可・拒否リストの中身は v0.1 では照合しません', 'MCP server allow/deny lists are not matched in v0.1')));
        break;
      case 'skipDangerousModePermissionPrompt':
      case 'skipAutoPermissionPrompt':
      case 'disableAutoMode':
      case 'allowManagedPermissionRulesOnly':
      case 'disableAllHooks':
        pushSetting(ctx, out, key, describeScalar(value), ptr);
        break;
      case 'apiKeyHelper':
        // コマンド文字列は表示しない（引数に秘密情報が含まれうる）
        pushSetting(ctx, out, key, tx('設定あり（コマンドは表示しません）', 'set (command not shown)'), ptr);
        break;
      case 'env':
        if (isPlainObject(value)) {
          const names = Object.keys(value).sort().join(', ');
          pushSetting(ctx, out, 'env', tx(`${names || '(なし)'}（値は表示しません）`, `${names || '(none)'} (values not shown)`), ptr);
        }
        else out.unparsed.push(unparsed(ctx, ptr, MSG.notObject));
        break;
      case 'sandbox':
        parseSandbox(ctx, value, out);
        break;
      default:
        if (IGNORED_SETTINGS_KEYS.has(key)) break;
        if (key in UNANALYZED_SECURITY_KEYS) out.unparsed.push(unparsed(ctx, ptr, UNANALYZED_SECURITY_KEYS[key]!));
        else out.unparsed.push(unparsed(ctx, ptr, tx('AgentScope が知らない設定キーです（v0.1 では解析しません）', 'Setting key not known to AgentScope (not analyzed in v0.1)')));
    }
  }
  return out;
}

function parsePermissionsBlock(ctx: ParseContext, value: unknown, out: ClaudeParsed) {
  if (!isPlainObject(value)) {
    out.unparsed.push(unparsed(ctx, 'permissions', MSG.notObject));
    return;
  }
  parseRuleList(ctx, value.allow, 'permissions.allow', 'allow', out);
  parseRuleList(ctx, value.ask, 'permissions.ask', 'ask', out);
  parseRuleList(ctx, value.deny, 'permissions.deny', 'deny', out);

  for (const key of ['defaultMode', 'disableBypassPermissionsMode', 'disableAutoMode', 'blockReadsOutsideWorkingDirectories'] as const) {
    if (value[key] !== undefined) pushSetting(ctx, out, `permissions.${key}`, describeScalar(value[key]), `permissions.${key}`);
  }
  for (const d of stringArray(ctx, value.additionalDirectories, 'permissions.additionalDirectories', out)) {
    pushSetting(ctx, out, 'permissions.additionalDirectories', d.value, d.pointer);
  }
  for (const key of Object.keys(value)) {
    if (!KNOWN_PERMISSION_KEYS.has(key)) out.unparsed.push(unparsed(ctx, joinPointer('permissions', key), tx('AgentScope が知らない permissions のキーです', 'permissions key not known to AgentScope')));
  }
}

function parseSandbox(ctx: ParseContext, value: unknown, out: ParsedConfig) {
  if (!isPlainObject(value)) {
    out.unparsed.push(unparsed(ctx, 'sandbox', MSG.notObject));
    return;
  }
  const known = ['enabled', 'autoAllowBashIfSandboxed', 'allowUnsandboxedCommands', 'failIfUnavailable', 'excludedCommands'];
  for (const key of known) {
    if (value[key] === undefined) continue;
    const v = value[key];
    const shown: string | Text = Array.isArray(v) && v.every((x) => typeof x === 'string') ? v.join(', ') : describeScalar(v);
    pushSetting(ctx, out, `sandbox.${key}`, shown, `sandbox.${key}`);
  }
  if (isPlainObject(value.filesystem) && value.filesystem.disabled !== undefined) {
    pushSetting(ctx, out, 'sandbox.filesystem.disabled', describeScalar(value.filesystem.disabled), 'sandbox.filesystem.disabled');
  }
  for (const key of Object.keys(value)) {
    if (!known.includes(key)) {
      out.unparsed.push(unparsed(ctx, joinPointer('sandbox', key), tx('サンドボックスの詳細設定は v0.1 では解析しません', 'Detailed sandbox settings are not analyzed in v0.1')));
    }
  }
}

// ---- .mcp.json / ~/.claude.json ----------------------------------------------

export function inferClaudeTransport(def: Record<string, unknown>): McpTransport {
  const t = typeof def.type === 'string' ? def.type.toLowerCase() : undefined;
  if (t === 'stdio' || t === 'http' || t === 'sse') return t;
  if (t !== undefined) return 'unknown';
  if (typeof def.command === 'string') return 'stdio';
  return 'unknown';
}

export function parseClaudeMcpJson(ctx: ParseContext, json: unknown): ClaudeParsed {
  const out = emptyClaude();
  if (!isPlainObject(json)) {
    out.unparsed.push(unparsed(ctx, '', MSG.rootNotObject));
    return out;
  }
  out.secretHits.push(...scanForSecrets(json, 'claude-code', ctx.file));
  if (json.mcpServers === undefined) out.unparsed.push(unparsed(ctx, 'mcpServers', MSG.noMcpServers));
  out.mcpServers.push(...parseMcpServers(ctx, json.mcpServers, 'mcpServers', out, inferClaudeTransport));
  for (const key of Object.keys(json)) {
    if (key !== 'mcpServers') out.unparsed.push(unparsed(ctx, joinPointer('', key), MSG.unknownKey));
  }
  return out;
}

/**
 * ~/.claude.json は会話履歴や認証状態などを含む内部状態ファイル。
 * MCP に関わる部分（トップレベルの mcpServers と、対象ディレクトリの projects エントリ）だけを見て、
 * それ以外のキーは列挙もしない。
 */
export function parseClaudeGlobalState(ctx: ParseContext, json: unknown, rootCandidates: string[]): ClaudeParsed {
  const out = emptyClaude();
  if (!isPlainObject(json)) {
    out.unparsed.push(unparsed(ctx, '', MSG.rootNotObject));
    return out;
  }
  if (json.mcpServers !== undefined) {
    out.secretHits.push(...scanForSecrets(json.mcpServers, 'claude-code', ctx.file, 'mcpServers'));
    const servers = parseMcpServers({ ...ctx, scope: 'user' }, json.mcpServers, 'mcpServers', out, inferClaudeTransport);
    out.mcpServers.push(...markSelfAdded(servers, tx('ユーザー自身が追加したサーバー（user スコープ）', 'Added by the user (user scope)')));
  }

  if (isPlainObject(json.projects)) {
    const key = rootCandidates.find((k) => isPlainObject((json.projects as Record<string, unknown>)[k]));
    if (key !== undefined) {
      const proj = (json.projects as Record<string, unknown>)[key] as Record<string, unknown>;
      const base = joinPointer('projects', key);
      const localCtx: ParseContext = { ...ctx, scope: 'project-local' };
      if (proj.mcpServers !== undefined) {
        out.secretHits.push(...scanForSecrets(proj.mcpServers, 'claude-code', ctx.file, joinPointer(base, 'mcpServers')));
        const servers = parseMcpServers(localCtx, proj.mcpServers, joinPointer(base, 'mcpServers'), out, inferClaudeTransport);
        out.mcpServers.push(...markSelfAdded(servers, tx('ユーザー自身が追加したサーバー（local スコープ）', 'Added by the user (local scope)')));
      }
      for (const k of ['enabledMcpjsonServers', 'disabledMcpjsonServers'] as const) {
        const ptr = joinPointer(base, k);
        for (const n of stringArray(localCtx, proj[k], ptr, out)) {
          (k === 'enabledMcpjsonServers' ? out.approvalHints.enabled : out.approvalHints.disabled).push({ name: n.value, file: ctx.file });
        }
      }
    }
  }
  return out;
}

function markSelfAdded(servers: McpServer[], note: Text): McpServer[] {
  return servers.map((s) => ({ ...s, approval: 'not-required', approvalNote: note }));
}

/** ~/.claude.json の projects のキーになりうる表記（OS によって区切り文字が異なる） */
export function projectKeyCandidates(root: string, realRoot: string): string[] {
  const set = new Set<string>();
  for (const r of [root, realRoot]) {
    set.add(r);
    set.add(r.split(path.sep).join('/'));
  }
  return [...set];
}

/** .mcp.json 由来のサーバーに、設定ファイル群から分かる承認状態を付ける */
export function resolveClaudeMcpApproval(servers: McpServer[], hints: ClaudeMcpApprovalHints[]): void {
  const enabled = hints.flatMap((h) => h.enabled);
  const disabled = hints.flatMap((h) => h.disabled);
  const enableAll = hints.map((h) => h.enableAll).filter((x) => x !== undefined);
  for (const s of servers) {
    if (s.agent !== 'claude-code' || s.approval === 'not-required') continue;
    const dis = disabled.find((d) => d.name === s.name);
    const en = enabled.find((d) => d.name === s.name);
    const all = enableAll.find((e) => e.value);
    if (dis) {
      s.approval = 'rejected';
      s.approvalNote = tx(`${dis.file} の disabledMcpjsonServers で拒否`, `rejected by disabledMcpjsonServers in ${dis.file}`);
    } else if (all) {
      s.approval = 'approved';
      s.approvalNote = tx(`${all.file} の enableAllProjectMcpServers により自動承認`, `auto-approved by enableAllProjectMcpServers in ${all.file}`);
    } else if (en) {
      s.approval = 'approved';
      s.approvalNote = tx(`${en.file} の enabledMcpjsonServers で承認`, `approved by enabledMcpjsonServers in ${en.file}`);
    } else {
      s.approval = 'unknown';
      s.approvalNote = tx('初回起動時の承認ダイアログで判断されます（設定ファイルからは不明）', 'Decided in the approval dialog on first launch (unknown from settings files)');
    }
  }
}
