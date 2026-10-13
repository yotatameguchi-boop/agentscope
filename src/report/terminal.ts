import pc from 'picocolors';
import type { Lang } from '../i18n.js';
import {
  AGENT_LABELS,
  type AgentId,
  type ConfigScope,
  type EffectStatus,
  type FileStatus,
  type LocalizedScanResult,
  type McpApproval,
  type RiskLevel,
  type RuleEffect,
} from '../types.js';

export interface TerminalOptions {
  color?: boolean;
}

interface Labels {
  scope: Record<ConfigScope, string>;
  status: Record<FileStatus, string>;
  effect: Record<RuleEffect, string>;
  approval: Record<McpApproval, string>;
  target: string;
  agents: string;
  includesGlobal: string;
  summary: (files: number, rules: number, servers: number) => string;
  findings: string;
  hFiles: string;
  noFiles: string;
  hintGlobal: string;
  symlink: string;
  hRules: string;
  noRules: string;
  hSettings: string;
  hMcp: string;
  noMcp: string;
  command: string;
  host: string;
  hostUnknown: string;
  env: string;
  headers: string;
  approvalLabel: string;
  toolPerms: string;
  defined: string;
  hFindings: string;
  noFindings: string;
  reason: string;
  location: string;
  evidence: string;
  fix: string;
  hRecs: string;
  hUnparsed: string;
  paren: (s: string) => string;
  hLaunch: string;
  noLaunch: string;
  launchSummary: (n: number) => string;
  ruleStatus: Record<Exclude<EffectStatus, 'active'>, string>;
  effect2: string;
  originally: (level: string) => string;
}

const LABELS: Record<Lang, Labels> = {
  ja: {
    scope: { project: 'プロジェクト共有', 'project-local': 'プロジェクト個人', user: 'ユーザー全体', managed: '組織の管理設定', cli: '起動オプション' },
    status: { parsed: '解析済み', 'parse-error': '解析エラー', skipped: 'スキップ', unsupported: '未対応' },
    effect: { allow: '許可', ask: '要承認', deny: '禁止', 'guidance-allow': '許可寄りヒント', 'guidance-block': '拒否寄りヒント' },
    approval: { approved: '承認済み', rejected: '拒否', 'not-required': '承認不要', unknown: '不明' },
    target: '対象ディレクトリ',
    agents: '対象エージェント',
    includesGlobal: '（ユーザー設定を含む）',
    summary: (f, r, s) => `設定ファイル: ${f}  権限ルール: ${r}  MCPサーバー: ${s}`,
    findings: '検出',
    hFiles: '検出された設定ファイル',
    noFiles: '対象の設定ファイルは見つかりませんでした。',
    hintGlobal: 'ユーザー単位の設定も確認するには --include-global を指定してください。',
    symlink: 'シンボリックリンク',
    hRules: '権限ルール',
    noRules: '権限ルールは見つかりませんでした。',
    hSettings: '権限に関わる設定',
    hMcp: 'MCP サーバー',
    noMcp: 'MCP サーバーの設定は見つかりませんでした。',
    command: 'コマンド',
    host: '接続先',
    hostUnknown: '接続先: 不明',
    env: '環境変数',
    headers: 'ヘッダー',
    approvalLabel: '承認状態',
    toolPerms: 'ツール権限: 不明（サーバーに接続しないため未検証）',
    defined: '定義',
    hFindings: '検出されたリスク',
    noFindings: '既知の検査ルールに該当する設定は見つかりませんでした（安全であることを保証するものではありません）。',
    reason: '理由',
    location: '場所',
    evidence: '該当',
    fix: '対応',
    hRecs: '推奨される対応',
    hUnparsed: '解析できなかった項目',
    paren: (s) => `（${s}）`,
    hLaunch: '起動コマンド（起動時のオプション）',
    noLaunch: '起動コマンドは見つかりませんでした。--launch で直接指定することもできます。',
    launchSummary: (n) => `起動コマンド: ${n}`,
    ruleStatus: { ignored: '無効', overridden: '打ち消し' },
    effect2: '有効性',
    originally: (l) => `（本来は ${l}）`,
  },
  en: {
    scope: { project: 'project, shared', 'project-local': 'project, personal', user: 'user-wide', managed: 'organization-managed', cli: 'launch option' },
    status: { parsed: 'parsed', 'parse-error': 'parse error', skipped: 'skipped', unsupported: 'unsupported' },
    effect: { allow: 'allow', ask: 'ask', deny: 'deny', 'guidance-allow': 'hint: allow', 'guidance-block': 'hint: block' },
    approval: { approved: 'approved', rejected: 'rejected', 'not-required': 'not required', unknown: 'unknown' },
    target: 'Target directory',
    agents: 'Agents',
    includesGlobal: ' (including user settings)',
    summary: (f, r, s) => `Config files: ${f}  Permission rules: ${r}  MCP servers: ${s}`,
    findings: 'Findings',
    hFiles: 'Configuration files',
    noFiles: 'No configuration files were found.',
    hintGlobal: 'Pass --include-global to also check user-level settings.',
    symlink: 'symbolic link',
    hRules: 'Permission rules',
    noRules: 'No permission rules were found.',
    hSettings: 'Permission-related settings',
    hMcp: 'MCP servers',
    noMcp: 'No MCP server configuration was found.',
    command: 'command',
    host: 'host',
    hostUnknown: 'host: unknown',
    env: 'Env vars',
    headers: 'Headers',
    approvalLabel: 'Approval',
    toolPerms: 'Tool permissions: unknown (not verified; AgentScope does not connect to servers)',
    defined: 'Defined in',
    hFindings: 'Security findings',
    noFindings: 'No settings matched the known checks (this does not guarantee the setup is safe).',
    reason: 'Reason',
    location: 'Location',
    evidence: 'Setting',
    fix: 'Fix',
    hRecs: 'Recommendations',
    hUnparsed: 'Items not analyzed',
    paren: (s) => ` (${s})`,
    hLaunch: 'Launch commands (launch options)',
    noLaunch: 'No launch commands were found. You can also pass one with --launch.',
    launchSummary: (n) => `Launch commands: ${n}`,
    ruleStatus: { ignored: 'not applied', overridden: 'neutralized' },
    effect2: 'Effect',
    originally: (l) => ` (originally ${l})`,
  },
};

export function renderTerminal(input: LocalizedScanResult, opts: TerminalOptions = {}): string {
  // 設定ファイル由来の文字列に制御文字や双方向制御文字が含まれていても、端末の表示を書き換えられないようにする
  const result = sanitizeDeep(input);
  const L = LABELS[result.lang];
  const c = pc.createColors(opts.color ?? false);
  const levelColor: Record<RiskLevel, (s: string) => string> = {
    HIGH: (s) => c.bold(c.red(s)),
    MEDIUM: (s) => c.yellow(s),
    LOW: (s) => c.cyan(s),
    INFO: (s) => c.dim(s),
  };
  const lines: string[] = [];
  const h = (title: string) => {
    lines.push('', c.bold(`■ ${title}`));
  };
  const agentLabel = (a: AgentId) => AGENT_LABELS[a];

  lines.push(c.bold(`AgentScope Security Report (v${result.tool.version})`));
  lines.push(`${L.target}: ${result.target}`);
  lines.push(`${L.agents}: ${result.agents.map(agentLabel).join(', ')}${result.includeGlobal ? L.includesGlobal : ''}`);
  const f = result.summary.findings;
  lines.push(
    `${L.summary(result.summary.files, result.summary.rules, result.summary.mcpServers)}  ${L.launchSummary(result.summary.launches)}  ` +
      `${L.findings}: ${levelColor.HIGH(`HIGH ${f.HIGH}`)} / ${levelColor.MEDIUM(`MEDIUM ${f.MEDIUM}`)} / ${levelColor.LOW(`LOW ${f.LOW}`)} / ${levelColor.INFO(`INFO ${f.INFO}`)}`,
  );

  // ---- 設定ファイル
  h(L.hFiles);
  if (result.files.length === 0) {
    lines.push(`  ${L.noFiles}`);
    if (!result.includeGlobal) lines.push(c.dim(`  ${L.hintGlobal}`));
  }
  for (const file of result.files) {
    const label = L.status[file.status];
    const status = file.status === 'parsed' ? c.green(label) : file.status === 'unsupported' ? c.dim(label) : c.yellow(label);
    lines.push(`  [${agentLabel(file.agent)}] ${file.displayPath}  (${L.scope[file.scope]})  ${status}`);
    if (file.symlinkTarget) lines.push(c.dim(`      ${L.symlink} → ${file.symlinkTarget}`));
    if (file.reason) lines.push(c.dim(`      ${file.reason}`));
  }

  // ---- 権限ルール
  h(L.hRules);
  if (result.rules.length === 0) lines.push(`  ${L.noRules}`);
  for (const agent of result.agents) {
    const rules = result.rules.filter((r) => r.agent === agent);
    if (rules.length === 0) continue;
    lines.push(`  ${c.bold(agentLabel(agent))}`);
    const width = Math.max(...rules.map((r) => displayWidth(L.effect[r.effect])));
    for (const r of rules) {
      const eff = pad(L.effect[r.effect], width);
      const effColored = r.effect === 'deny' ? c.green(eff) : r.effect === 'allow' ? c.yellow(eff) : eff;
      const tag = r.status === 'active' ? '' : ` ${c.yellow(`[${L.ruleStatus[r.status]}]`)}`;
      lines.push(`    ${effColored}  ${r.raw}${tag}  ${c.dim(`${r.source.file} ${r.source.pointer}`)}`);
      if (r.statusNote) lines.push(c.dim(`      * ${r.statusNote}`));
      if (r.note) lines.push(c.dim(`      * ${r.note}`));
    }
  }

  if (result.settings.length > 0) {
    h(L.hSettings);
    for (const s of result.settings) {
      const tag = s.status === 'active' ? '' : ` ${c.yellow(`[${L.ruleStatus[s.status]}]`)}`;
      lines.push(`  [${agentLabel(s.agent)}] ${s.key} = ${s.value}${tag}  ${c.dim(`${s.source.file} ${s.source.pointer}`)}`);
      if (s.statusNote) lines.push(c.dim(`      * ${s.statusNote}`));
    }
  }

  // ---- MCP
  h(L.hMcp);
  if (result.mcpServers.length === 0) lines.push(`  ${L.noMcp}`);
  for (const s of result.mcpServers) {
    const target = s.commandName ? `${L.command}: ${s.commandName}` : s.urlHost ? `${L.host}: ${s.urlHost}` : L.hostUnknown;
    lines.push(`  [${agentLabel(s.agent)}] ${c.bold(s.name)}  ${s.transport}  ${target}  (${L.scope[s.scope]})`);
    if (s.envNames.length) lines.push(`      ${L.env}: ${s.envNames.join(', ')}`);
    if (s.headerNames.length) lines.push(`      ${L.headers}: ${s.headerNames.join(', ')}`);
    lines.push(`      ${L.approvalLabel}: ${L.approval[s.approval]}${s.approvalNote ? c.dim(L.paren(s.approvalNote)) : ''}`);
    lines.push(`      ${L.toolPerms}`);
    lines.push(c.dim(`      ${L.defined}: ${s.source.file} ${s.source.pointer}`));
  }

  // ---- 起動コマンド
  h(L.hLaunch);
  if (result.launches.length === 0) lines.push(`  ${L.noLaunch}`);
  for (const l of result.launches) {
    const opts = l.options.map((o) => (o.value === undefined ? o.flag : `${o.flag} ${o.value}`)).join(' ');
    lines.push(`  [${agentLabel(l.agent)}] ${c.bold(l.executable)}${opts ? ` ${opts}` : ''}  ${c.dim(`${l.source.file} ${l.source.pointer}`)}`);
  }

  // ---- 検出結果
  h(L.hFindings);
  if (result.findings.length === 0) lines.push(`  ${L.noFindings}`);
  for (const x of result.findings) {
    const orig = x.originalLevel ? c.dim(L.originally(x.originalLevel)) : '';
    lines.push(`  ${levelColor[x.level](`[${x.level}]`)}${orig} ${x.ruleId} ${x.title}  ${c.dim(`(${agentLabel(x.agent)})`)}`);
    lines.push(`      ${L.reason}: ${x.reason}`);
    if (x.effectNote) lines.push(`      ${L.effect2}: ${x.effectNote}`);
    lines.push(`      ${L.location}: ${x.file}  ${x.pointer}`);
    if (x.evidence) lines.push(`      ${L.evidence}: ${x.evidence}`);
    lines.push(`      ${L.fix}: ${x.recommendation}`);
  }

  const recs = [...new Set(result.findings.filter((x) => x.level !== 'INFO').map((x) => x.recommendation))];
  if (recs.length > 0) {
    h(L.hRecs);
    recs.forEach((r, i) => lines.push(`  ${i + 1}. ${r}`));
  }

  // ---- 未解析
  const notParsedFiles = result.files.filter((x) => x.status !== 'parsed');
  if (result.unparsed.length > 0 || notParsedFiles.length > 0) {
    h(L.hUnparsed);
    for (const file of notParsedFiles) lines.push(`  ${file.displayPath}: ${L.status[file.status]}${file.reason ? L.paren(file.reason) : ''}`);
    for (const u of result.unparsed) lines.push(`  ${u.file} ${u.pointer}: ${u.reason}`);
  }

  lines.push('', c.dim(result.disclaimer), '');
  return lines.join('\n');
}

/** 全角文字を幅2として数える（表の桁揃え用） */
function displayWidth(s: string): number {
  let w = 0;
  for (const ch of s) w += /[ᄀ-ᅟ⺀-꓏가-힣豈-﫿︰-﹏＀-｠￠-￦]/.test(ch) ? 2 : 1;
  return w;
}

function pad(s: string, width: number): string {
  return s + ' '.repeat(Math.max(0, width - displayWidth(s)));
}

/**
 * 端末に出す前に、制御文字（ESC による色・カーソル操作、改行など）と、
 * 表示順を入れ替える双方向制御文字・不可視文字を \xNN / \u{NNNN} 形式に置き換える。
 */
export function sanitizeForTerminal(s: string): string {
  return s
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, (ch) => `\\x${ch.charCodeAt(0).toString(16).padStart(2, '0')}`)
    .replace(/[\u061c\u200b-\u200f\u202a-\u202e\u2028\u2029\u2060-\u2064\u2066-\u2069\ufeff]/g, (ch) => `\\u{${ch.charCodeAt(0).toString(16)}}`);
}

function sanitizeDeep<T>(v: T): T {
  if (typeof v === 'string') return sanitizeForTerminal(v) as T;
  if (Array.isArray(v)) return v.map(sanitizeDeep) as T;
  if (typeof v === 'object' && v !== null) {
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, sanitizeDeep(x)])) as T;
  }
  return v;
}
