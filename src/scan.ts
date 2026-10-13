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
import { applyPrecedence, effectiveEnableAll, selectManagedSource, type ManagedSourceInfo } from './precedence.js';
import { parsePlist } from './util/plist.js';
import { protectOutput } from './util/protect.js';
import { withSecretVault } from './util/vault.js';
import { runRules } from './rules/index.js';
import type { AgentId, ConfigFile, LaunchCommand, LocalizedScanResult, ParsedConfig, RiskLevel, ScanResult } from './types.js';
import { isPlainObject, parseJsonc } from './util/jsonc.js';
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
  /** macOS の構成プロファイルの候補（テスト用に差し替え可能。既定は macOS の managed preferences の場所） */
  mdmPaths?: string[];
  /** OS（テスト用に差し替え可能） */
  platform?: NodeJS.Platform;
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

const UNEXPECTED_FILE = tx('解析中に予期しないエラーが発生したため、このファイルは分析していません', 'An unexpected error occurred while parsing, so this file was not analyzed');
const UNEXPECTED = tx('解析中に予期しないエラーが発生したため、この項目は分析していません', 'An unexpected error occurred while parsing, so this item was not analyzed');

/** 利用者に見せるエラー。文言は表示時に言語を選ぶ */
export class AgentScopeError extends Error {
  constructor(readonly text: Text) {
    super(text.en);
    this.name = 'AgentScopeError';
  }
}

export function scan(opts: ScanOptions = {}): Promise<ScanResult> {
  // 秘密情報と判定した値は、このスキャンの間だけ保管庫に置き、出力保護に使う
  return withSecretVault((vault) => scanInner(opts, vault));
}

async function scanInner(opts: ScanOptions, vault: ReadonlySet<string>): Promise<ScanResult> {
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
  const mdmPaths = opts.mdmPaths ?? defaultMdmPaths();
  const candidates = await discoverCandidates({ root, home, agents, includeGlobal, managedDir, mdmPaths });
  /** 管理設定の配布元ごとの情報（どれが使われるかの判定に使う） */
  const managedSources: ManagedSourceInfo[] = [];
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
      managedSource: c.managedSource,
    };
    files.push(file);

    if (!read.ok) {
      file.status = 'skipped';
      file.reason = read.reason;
      if (c.managedSource) {
        file.managedIssue = managedReadIssue(read.code);
        // 読めなかった管理設定も「存在する文書」として扱われ、下位の配布元より優先される
        managedSources.push({ source: c.managedSource, file: displayPath, hasPolicyKey: true });
      }
      continue;
    }
    if (c.kind === 'unsupported') {
      file.status = 'unsupported';
      file.reason = c.unsupportedReason;
      continue;
    }

    // 内容を JSON の値にする（plist は自前で変換する）
    let value: unknown;
    if (c.kind === 'claude-plist') {
      const pl = parsePlist(read.bytes);
      if (!pl.ok) {
        file.status = 'parse-error';
        file.reason = tx(`plist として解析できません（${pl.reason}）`, `Cannot parse as a plist (${pl.reason})`);
        file.managedIssue = REFUSES_START_PLIST;
        managedSources.push({ source: 'mdm', file: displayPath, hasPolicyKey: true });
        continue;
      }
      value = pl.value;
    } else {
      // 管理設定のファイルは空なら {} として扱われる
      const text = c.managedSource === 'file' && read.text.trim() === '' ? '{}' : read.text;
      const json = parseJsonc(text);
      if (!json.ok) {
        file.status = 'parse-error';
        file.reason = json.reason;
        if (c.managedSource === 'file') {
          file.managedIssue = REFUSES_START_JSON;
          managedSources.push({ source: 'file', file: displayPath, hasPolicyKey: true });
        }
        continue;
      }
      value = json.value;
      // 管理設定のファイルは厳密な JSON でなければならない（コメントや末尾カンマがあると起動を拒否される）
      if (c.managedSource === 'file' && !isStrictJsonObject(text)) file.managedIssue = REFUSES_START_JSON;
    }
    if (c.managedSource) {
      if (!isPlainObject(value)) {
        if (c.managedSource !== 'remote') file.managedIssue = c.managedSource === 'mdm' ? REFUSES_START_PLIST : REFUSES_START_JSON;
      }
      managedSources.push({
        source: c.managedSource,
        file: displayPath,
        hasPolicyKey: isPlainObject(value) && Object.keys(value).some((k) => !MANAGED_CONTROL_KEYS.has(k)),
        behavior: isPlainObject(value) && typeof value.managedSourcesBehavior === 'string' ? value.managedSourcesBehavior : undefined,
      });
    }

    const ctx: ParseContext = { agent: c.agent, scope: c.scope, file: displayPath, root };
    let result: ParsedConfig;
    try {
      result = parseByKind(c, ctx, value, projectKeyCandidates(root, realRoot));
    } catch {
      // 想定外の入力でパーサーが失敗しても、他のファイルの分析は続ける。例外の内容は設定値を含みうるため出さない
      file.status = 'parse-error';
      file.reason = UNEXPECTED_FILE;
      continue;
    }
    if (c.mergeOrder !== undefined) for (const st of result.settings) st.mergeOrder = c.mergeOrder;
    if (c.managedSource) {
      for (const st of result.settings) st.managedSource = c.managedSource;
      for (const r of result.rules) r.managedSource = c.managedSource;
    }
    parsed.push(result);
    if ('approvalHints' in result) approvalHints.push(result.approvalHints as ClaudeMcpApprovalHints);
  }
  const managedSelection = selectManagedSource(managedSources);
  for (const f of files) if (f.managedSource) f.managedSelected = managedSelection.applies(f.managedSource);

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
      let lp: Awaited<ReturnType<typeof parseLaunch>>;
      try {
        lp = await parseLaunch(words, { root, source: { file: t.file, pointer: t.pointer }, launchId: `${t.file}#${t.pointer}#${k}` });
      } catch {
        // 1つの起動コマンドの解析に失敗しても、他の分析は続ける。例外の内容は設定値を含みうるため出さない
        unparsed.push({ agent: 'claude-code', file: t.file, pointer: t.pointer, reason: UNEXPECTED });
        continue;
      }
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
    let converted: ReturnType<typeof envToSetting>;
    try {
      converted = envToSetting(e);
    } catch {
      unparsed.push({ agent: 'claude-code', file: e.source.file, pointer: e.source.pointer, reason: UNEXPECTED });
      continue;
    }
    const { setting, secret } = converted;
    if (setting && agents.includes(setting.agent)) settings.push(setting);
    if (secret && agents.includes(secret.agent)) secretHits.push(secret);
  }

  applyPrecedence(rules, settings, managedSelection);
  resolveClaudeMcpApproval(mcpServers, approvalHints, effectiveEnableAll(settings) ?? null);

  const findings = runRules({ agents, files, rules, settings, mcpServers, secretHits, home, includeGlobal, platform: opts.platform ?? process.platform });
  const counts: Record<RiskLevel, number> = { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) counts[f.level]++;

  // 出力保護: どの経路から来た文字列でも、既知形式の秘密情報や、検出時に秘密情報と判定した値が残っていれば伏せる
  return protectOutput({
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
  }, vault);
}

/** Claude Code の管理設定ファイルの置き場所 https://code.claude.com/docs/en/managed-settings */
export function defaultManagedDir(platform: NodeJS.Platform = process.platform): string {
  if (platform === 'darwin') return '/Library/Application Support/ClaudeCode';
  if (platform === 'win32') return 'C:\\Program Files\\ClaudeCode';
  return '/etc/claude-code';
}

/**
 * macOS の構成プロファイル（managed preferences の com.anthropic.claudecode ドメイン）。
 * コンピュータ全体と、ユーザー単位の2か所に置かれうる。
 */
export function defaultMdmPaths(platform: NodeJS.Platform = process.platform): string[] {
  if (platform !== 'darwin') return [];
  const out = ['/Library/Managed Preferences/com.anthropic.claudecode.plist'];
  try {
    out.push(`/Library/Managed Preferences/${os.userInfo().username}/com.anthropic.claudecode.plist`);
  } catch {
    // ユーザー名を取得できない環境ではコンピュータ全体の場所だけを見る
  }
  return out;
}

/** 管理設定の配布元を選ぶときに数えないキー（https://code.claude.com/docs/en/managed-settings） */
const MANAGED_CONTROL_KEYS = new Set(['wslInheritsWindowsSettings', 'managedSourcesBehavior']);

const REFUSES_START_JSON = {
  kind: 'refuses-start' as const,
  reason: tx(
    '管理設定のファイルが厳密な JSON のオブジェクトではありません（コメント・末尾カンマ・構文エラー・オブジェクト以外を含む）。この状態では Claude Code は起動を拒否します',
    'The managed settings file is not a strict JSON object (it has comments, trailing commas, a syntax error, or a non-object top level). Claude Code refuses to start in this state',
  ),
};
const REFUSES_START_PLIST = {
  kind: 'refuses-start' as const,
  reason: tx(
    '構成プロファイル（plist）が壊れているか、内容がオブジェクトではありません。この状態では Claude Code は起動を拒否します',
    'The configuration profile (plist) is malformed or its content is not an object. Claude Code refuses to start in this state',
  ),
};

/** 管理設定を読めなかったときの扱い。権限で拒否されたなら適用されず、それ以外の読み取り失敗なら起動を拒否する */
function managedReadIssue(code: string | undefined): ConfigFile['managedIssue'] {
  if (code === 'EACCES' || code === 'EPERM') {
    return {
      kind: 'not-applied',
      reason: tx(
        'この管理設定は OS の権限により読めません。Claude Code も同じユーザーで動くなら、この管理設定は適用されないまま起動します',
        'This managed settings file cannot be read due to OS permissions. If Claude Code runs as the same user, it starts without applying this policy',
      ),
    };
  }
  return {
    kind: 'refuses-start',
    reason: tx('この管理設定を読み取れません。この状態では Claude Code は起動時に終了します', 'This managed settings file cannot be read. In this state Claude Code exits at startup'),
  };
}

function isStrictJsonObject(text: string): boolean {
  try {
    return isPlainObject(JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text));
  } catch {
    return false;
  }
}

/** 文言を1つの言語に確定させる。lang は JSON 出力にも含める */
export function localizeResult(result: ScanResult, lang: Lang): LocalizedScanResult {
  const { tool, ...rest } = localize(result, lang);
  return { tool, lang, ...rest };
}

function parseByKind(c: Candidate, ctx: ParseContext, json: unknown, projectKeys: string[]): ParsedConfig {
  switch (c.kind) {
    case 'claude-settings':
    case 'claude-plist':
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
