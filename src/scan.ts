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
import { parseCursorMcpJson, parseCursorPermissions } from './parsers/cursor.js';
import { runRules } from './rules/index.js';
import type { AgentId, ConfigFile, LocalizedScanResult, ParsedConfig, RiskLevel, ScanResult } from './types.js';
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
}

export const DISCLAIMER = tx(
  'この結果は設定ファイルに書かれた内容の静的解析です。実際に行使できる権限は、エージェントのバージョン、組織の管理設定、' +
    '起動時のオプション、IDE 側の設定、MCP サーバーの実装によって変わります。検出がないことは安全を保証しません。',
  'This is a static analysis of what is written in configuration files. The permissions that can actually be exercised depend on ' +
    'the agent version, organization-managed settings, launch options, IDE settings, and MCP server implementations. ' +
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
  if (!st?.isDirectory()) throw new AgentScopeError(tx(`対象ディレクトリが見つかりません: ${root}`, `Target directory not found: ${root}`));
  const realRoot = await fs.realpath(root);

  const files: ConfigFile[] = [];
  const parsed: ParsedConfig[] = [];
  const approvalHints: ClaudeMcpApprovalHints[] = [];

  for (const c of discoverCandidates({ root, home, agents, includeGlobal })) {
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
    const result = parseByKind(c, ctx, json.value, projectKeyCandidates(root, realRoot));
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
  resolveClaudeMcpApproval(mcpServers, approvalHints);

  const findings = runRules({ agents, files, rules, settings, mcpServers, secretHits });
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
    findings,
    unparsed,
    summary: { files: files.length, rules: rules.length, mcpServers: mcpServers.length, findings: counts },
    disclaimer: DISCLAIMER,
  };
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
    case 'unsupported':
      throw new Error('unreachable');
  }
}
