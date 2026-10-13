import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { localize, tx, type Lang, type Text } from './i18n.js';
import { discoverCandidates, toDisplayPath, type Candidate } from './discovery/discover.js';
import {
  parseClaudeGlobalState,
  parseClaudeMcpJson,
  parseClaudeSettings,
  projectKeyCandidates,
  resolveClaudeMcpApproval,
  type ClaudeMcpApprovalHints,
} from './parsers/claude.js';
import type { ParseContext } from './parsers/common.js';
import { parseCursorCli, parseCursorMcpJson, parseCursorPermissions } from './parsers/cursor.js';
import { collectFileEnv } from './env/sources.js';
import { envToSetting, knownEnv } from './env/record.js';
import { collectLaunchTexts } from './launch/sources.js';
import { parseLaunch } from './launch/parse.js';
import { splitCommands } from './launch/tokenize.js';
import { applyPrecedence, effectiveEnableAll } from './precedence.js';
import { runRules } from './rules/index.js';
import type { AgentId, ConfigFile, LaunchCommand, LocalizedScanResult, ParsedConfig, RiskLevel, ScanResult } from './types.js';
import { parseJsonc } from './util/jsonc.js';
import { safeReadFile } from './util/safeRead.js';
import { VERSION } from './version.js';

export interface ScanOptions {
  /** 解析対象ディレクトリ（既定: カレントディレクトリ） */
  root?: string;
  /** 対象エージェント（既定: すべて） */
  agents?: AgentId[];
  /** ユーザー単位の設定も解析する */
  includeGlobal?: boolean;
  /** ホームディレクトリ（テスト用に差し替え可能） */
  home?: string;
  /** Claude Code の管理設定ディレクトリ（テスト用に差し替え可能。既定は OS ごとの場所） */
  managedDir?: string;
  /** 起動コマンド（例: "claude --permission-mode bypassPermissions"）。実行はせず、文字列として解析する */
  launch?: string[];
  /** package.json の scripts などから起動コマンドを探す（既定: true）。includeGlobal 時はシェルの設定ファイルも見る */
  launchFiles?: boolean;
  /**
   * 実行中の環境変数も分析する。true なら process.env を、オブジェクトならそれを使う（テスト用）。
   * 権限・安全性に関わる変数（env/catalog.ts）だけを見て、秘密情報の値は保持しない
   */
  env?: boolean | NodeJS.ProcessEnv;
}

export const DISCLAIMER = tx(
  'この結果は設定ファイル・起動コマンド・環境変数に書かれた内容の静的解析です。実際に行使できる権限は、エージェントのバージョン、組織の管理設定、' +
    '実際に使われた起動オプションや環境変数（ここで見つからなかったものを含む）、IDE 側の設定、MCP サーバーの実装によって変わります。' +
    '検出がないことは安全を保証しません。',
  'This is a static analysis of what is written in configuration files, launch commands, and environment variables. The permissions that can actually be exercised depend on ' +
    'the agent version, organization-managed settings, the launch options and environment variables actually used (including ones not found here), ' +
    'IDE settings, and MCP server implementations. ' +
    'Having no findings does not mean the setup is safe.',
);

/** 利用者に見せるエラー。文言は表示時に言語を選ぶ */
export class AgentScopeError extends Error {
  constructor(readonly text: Text) {
    super(text.en);
    this.name = 'AgentScopeError';
  }
}

export async function scan(opts: ScanOptions = {}): Promise<ScanResult> {
  const root = path.resolve(opts.root ?? process.cwd());
  const home = path.resolve(opts.home ?? os.homedir());
  const agents = opts.agents ?? ['claude-code', 'cursor'];
  const includeGlobal = opts.includeGlobal ?? false;

  const st = await fs.stat(root).catch(() => undefined);
  if (!st) throw new AgentScopeError(tx(`対象ディレクトリが見つかりません: ${root}`, `Target directory not found: ${root}`));
  if (!st.isDirectory()) throw new AgentScopeError(tx(`ディレクトリではありません: ${root}`, `Not a directory: ${root}`));
  const realRoot = await fs.realpath(root);

  const files: ConfigFile[] = [];
  const parsed: ParsedConfig[] = [];
  const approvalHints: ClaudeMcpApprovalHints[] = [];

  const managedDir = opts.managedDir ?? defaultManagedDir();
  const candidates = await discoverCandidates({ root, home, agents, includeGlobal, managedDir });
  for (const c of candidates) {
    const displayPath = toDisplayPath(c.path, root, home);
    const read = await safeReadFile(c.path, { confineTo: c.confineTo });
    if (!read.ok && read.missing) continue; // 存在しないファイルはエラーにせずスキップ

    const file: ConfigFile = {
      agent: c.agent,
      kind: c.kind,
      scope: c.scope,
      path: c.path,
      displayPath,
      status: 'parsed',
      symlinkTarget: read.symlinkTarget ? toDisplayPath(read.symlinkTarget, root, home) : undefined,
    };
    files.push(file);

    if (!read.ok) {
      file.status = 'skipped';
      file.reason = read.reason;
      continue;
    }
    if (c.kind === 'unsupported') {
      file.status = 'unsupported';
      file.reason = c.unsupportedReason;
      continue;
    }
    const json = parseJsonc(read.text);
    if (!json.ok) {
      file.status = 'parse-error';
      file.reason = json.reason;
      continue;
    }

    const ctx: ParseContext = { agent: c.agent, scope: c.scope, file: displayPath, root };
    let result: ParsedConfig;
    try {
      result = parseByKind(c, ctx, json.value, projectKeyCandidates(root, realRoot));
    } catch {
      // 想定外の入力でパーサーが失敗しても、他のファイルの分析は続ける。例外の内容は設定値を含みうるため出さない
      file.status = 'parse-error';
      file.reason = tx('解析中に予期しないエラーが発生したため、このファイルは分析していません', 'An unexpected error occurred while parsing, so this file was not analyzed');
      continue;
    }
    parsed.push(result);
    if ('approvalHints' in result) approvalHints.push(result.approvalHints as ClaudeMcpApprovalHints);
  }

  const rules = parsed.flatMap((p) => p.rules);
  const settings = parsed.flatMap((p) => p.settings);
  const mcpServers = parsed.flatMap((p) => p.mcpServers);
  // ファイルごとに、設定項目の位置順（配列番号は数値として）に並べる
  const fileOrder = new Map(files.map((f, i) => [f.displayPath, i]));
  const unparsed = parsed
    .flatMap((p) => p.unparsed)
    .sort((a, b) => (fileOrder.get(a.file) ?? 0) - (fileOrder.get(b.file) ?? 0) || a.pointer.localeCompare(b.pointer, 'en', { numeric: true }));
  const secretHits = parsed.flatMap((p) => p.secretHits);

  // 起動コマンド（起動時のオプション）
  const launches: LaunchCommand[] = [];
  const texts = await collectLaunchTexts({
    root,
    home,
    explicit: opts.launch ?? [],
    projectFiles: opts.launchFiles ?? true,
    shellFiles: (opts.launchFiles ?? true) && includeGlobal,
  });
  for (const t of texts) {
    for (const [k, words] of splitCommands(t.text).entries()) {
      const lp = await parseLaunch(words, { root, source: { file: t.file, pointer: t.pointer }, launchId: `${t.file}#${t.pointer}#${k}` });
      if (!lp || !agents.includes(lp.launch.agent)) continue;
      launches.push(lp.launch);
      rules.push(...lp.rules);
      settings.push(...lp.settings);
      mcpServers.push(...lp.mcpServers);
      unparsed.push(...lp.unparsed);
      secretHits.push(...lp.secretHits);
    }
  }

  // 環境変数（ファイルに書かれたもの・実行中の環境）
  const envInputs = await collectFileEnv({ root, home, projectFiles: opts.launchFiles ?? true, shellFiles: (opts.launchFiles ?? true) && includeGlobal });
  if (opts.env) {
    for (const [name, value] of knownEnv(opts.env === true ? process.env : opts.env)) {
      envInputs.push({ name, value, scope: 'shell', origin: 'process', source: { file: '(environment)', pointer: name }, writtenInFile: false });
    }
  }
  for (const e of envInputs) {
    const { setting, secret } = envToSetting(e);
    if (setting && agents.includes(setting.agent)) settings.push(setting);
    if (secret && agents.includes(secret.agent)) secretHits.push(secret);
  }

  applyPrecedence(rules, settings);
  resolveClaudeMcpApproval(mcpServers, approvalHints, effectiveEnableAll(settings) ?? null);

  const findings = runRules({ agents, files, rules, settings, mcpServers, secretHits, home });
  const counts: Record<RiskLevel, number> = { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) counts[f.level]++;

  return {
    tool: { name: 'agentscope', version: VERSION },
    target: root,
    agents,
    includeGlobal,
    files,
    rules,
    settings,
    mcpServers,
    launches,
    findings,
    unparsed,
    summary: { files: files.length, rules: rules.length, mcpServers: mcpServers.length, launches: launches.length, findings: counts },
    disclaimer: DISCLAIMER,
  };
}

/** Claude Code の管理設定ファイルの置き場所 https://code.claude.com/docs/en/managed-settings */
export function defaultManagedDir(platform: NodeJS.Platform = process.platform): string {
  if (platform === 'darwin') return '/Library/Application Support/ClaudeCode';
  if (platform === 'win32') return 'C:\\Program Files\\ClaudeCode';
  return '/etc/claude-code';
}

/** 文言を1つの言語に確定させる。lang は JSON 出力にも含める */
export function localizeResult(result: ScanResult, lang: Lang): LocalizedScanResult {
  const { tool, ...rest } = localize(result, lang);
  return { tool, lang, ...rest };
}

function parseByKind(c: Candidate, ctx: ParseContext, json: unknown, projectKeys: string[]): ParsedConfig {
  switch (c.kind) {
    case 'claude-settings':
      return parseClaudeSettings(ctx, json);
    case 'claude-mcp':
      return parseClaudeMcpJson(ctx, json);
    case 'claude-global-state':
      return parseClaudeGlobalState(ctx, json, projectKeys);
    case 'cursor-mcp':
      return parseCursorMcpJson(ctx, json);
    case 'cursor-permissions':
      return parseCursorPermissions(ctx, json);
    case 'cursor-cli':
      return parseCursorCli(ctx, json);
    case 'unsupported':
      throw new Error('unreachable');
  }
}
