import pc from 'picocolors';
import {
  AGENT_LABELS,
  type ConfigFile,
  type ConfigScope,
  type FileStatus,
  type McpApproval,
  type RiskLevel,
  type RuleEffect,
  type ScanResult,
} from '../types.js';

export interface TerminalOptions {
  color?: boolean;
}

const SCOPE_LABELS: Record<ConfigScope, string> = {
  project: 'プロジェクト共有',
  'project-local': 'プロジェクト個人',
  user: 'ユーザー全体',
};

const STATUS_LABELS: Record<FileStatus, string> = {
  parsed: '解析済み',
  'parse-error': '解析エラー',
  skipped: 'スキップ',
  unsupported: '未対応',
};

const EFFECT_LABELS: Record<RuleEffect, string> = {
  allow: '許可',
  ask: '要承認',
  deny: '禁止',
  'guidance-allow': '許可寄りヒント',
  'guidance-block': '拒否寄りヒント',
};

const APPROVAL_LABELS: Record<McpApproval, string> = {
  approved: '承認済み',
  rejected: '拒否',
  'not-required': '承認不要',
  unknown: '不明',
};

export function renderTerminal(result: ScanResult, opts: TerminalOptions = {}): string {
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
  const agentLabel = (a: keyof typeof AGENT_LABELS) => AGENT_LABELS[a];

  lines.push(c.bold(`AgentScope Security Report (v${result.tool.version})`));
  lines.push(`対象ディレクトリ: ${result.target}`);
  lines.push(`対象エージェント: ${result.agents.map(agentLabel).join(', ')}${result.includeGlobal ? '（ユーザー設定を含む）' : ''}`);
  const f = result.summary.findings;
  lines.push(
    `設定ファイル: ${result.summary.files}  権限ルール: ${result.summary.rules}  MCPサーバー: ${result.summary.mcpServers}  ` +
      `検出: ${levelColor.HIGH(`HIGH ${f.HIGH}`)} / ${levelColor.MEDIUM(`MEDIUM ${f.MEDIUM}`)} / ${levelColor.LOW(`LOW ${f.LOW}`)} / ${levelColor.INFO(`INFO ${f.INFO}`)}`,
  );

  // ---- 設定ファイル
  h('検出された設定ファイル');
  if (result.files.length === 0) {
    lines.push('  対象の設定ファイルは見つかりませんでした。');
    if (!result.includeGlobal) lines.push(c.dim('  ユーザー単位の設定も確認するには --include-global を指定してください。'));
  }
  for (const file of result.files) {
    lines.push(`  [${agentLabel(file.agent)}] ${file.displayPath}  (${SCOPE_LABELS[file.scope]})  ${statusText(file, c)}`);
    if (file.symlinkTarget) lines.push(c.dim(`      シンボリックリンク → ${file.symlinkTarget}`));
    if (file.reason) lines.push(c.dim(`      ${file.reason}`));
  }

  // ---- 権限ルール
  h('権限ルール');
  if (result.rules.length === 0) lines.push('  権限ルールは見つかりませんでした。');
  for (const agent of result.agents) {
    const rules = result.rules.filter((r) => r.agent === agent);
    if (rules.length === 0) continue;
    lines.push(`  ${c.bold(agentLabel(agent))}`);
    const width = Math.max(...rules.map((r) => displayWidth(EFFECT_LABELS[r.effect])));
    for (const r of rules) {
      const eff = pad(EFFECT_LABELS[r.effect], width);
      const effColored = r.effect === 'deny' ? c.green(eff) : r.effect === 'allow' ? c.yellow(eff) : eff;
      lines.push(`    ${effColored}  ${r.raw}  ${c.dim(`${r.source.file} ${r.source.pointer}`)}`);
      if (r.note) lines.push(c.dim(`      ※ ${r.note}`));
    }
  }

  if (result.settings.length > 0) {
    h('権限に関わる設定');
    for (const s of result.settings) {
      lines.push(`  [${agentLabel(s.agent)}] ${s.key} = ${s.value}  ${c.dim(s.source.file)}`);
    }
  }

  // ---- MCP
  h('MCP サーバー');
  if (result.mcpServers.length === 0) lines.push('  MCP サーバーの設定は見つかりませんでした。');
  for (const s of result.mcpServers) {
    const target = s.commandName ? `コマンド: ${s.commandName}` : s.urlHost ? `接続先: ${s.urlHost}` : '接続先: 不明';
    lines.push(`  [${agentLabel(s.agent)}] ${c.bold(s.name)}  ${s.transport}  ${target}  (${SCOPE_LABELS[s.scope]})`);
    if (s.envNames.length) lines.push(`      環境変数: ${s.envNames.join(', ')}`);
    if (s.headerNames.length) lines.push(`      ヘッダー: ${s.headerNames.join(', ')}`);
    lines.push(`      承認状態: ${APPROVAL_LABELS[s.approval]}${s.approvalNote ? c.dim(`（${s.approvalNote}）`) : ''}`);
    lines.push(`      ツール権限: 不明（サーバーに接続しないため未検証）`);
    lines.push(c.dim(`      定義: ${s.source.file} ${s.source.pointer}`));
  }

  // ---- 検出結果
  h('検出されたリスク');
  if (result.findings.length === 0) {
    lines.push('  既知の検査ルールに該当する設定は見つかりませんでした（安全であることを保証するものではありません）。');
  }
  for (const x of result.findings) {
    lines.push(`  ${levelColor[x.level](`[${x.level}]`)} ${x.ruleId} ${x.title}  ${c.dim(`(${agentLabel(x.agent)})`)}`);
    lines.push(`      理由: ${x.reason}`);
    lines.push(`      場所: ${x.file}  ${x.pointer}`);
    if (x.evidence) lines.push(`      該当: ${x.evidence}`);
    lines.push(`      対応: ${x.recommendation}`);
  }

  const recs = [...new Set(result.findings.filter((x) => x.level !== 'INFO').map((x) => x.recommendation))];
  if (recs.length > 0) {
    h('推奨される対応');
    recs.forEach((r, i) => lines.push(`  ${i + 1}. ${r}`));
  }

  // ---- 未解析
  const notParsedFiles = result.files.filter((x) => x.status !== 'parsed');
  if (result.unparsed.length > 0 || notParsedFiles.length > 0) {
    h('解析できなかった項目');
    for (const file of notParsedFiles) lines.push(`  ${file.displayPath}: ${STATUS_LABELS[file.status]}（${file.reason ?? ''}）`);
    for (const u of result.unparsed) lines.push(`  ${u.file} ${u.pointer}: ${u.reason}`);
  }

  lines.push('', c.dim(result.disclaimer), '');
  return lines.join('\n');
}

function statusText(file: ConfigFile, c: ReturnType<typeof pc.createColors>): string {
  const label = STATUS_LABELS[file.status];
  return file.status === 'parsed' ? c.green(label) : file.status === 'unsupported' ? c.dim(label) : c.yellow(label);
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
