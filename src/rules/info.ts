import { tx } from '../i18n.js';
import type { AgentId, Finding } from '../types.js';
import { AGENT_LABELS } from '../types.js';
import { AUTO_EXEC_KEYS } from '../parsers/claude.js';
import { finding, type SecurityRule } from './types.js';

/**
 * 静的解析では確認できない範囲を INFO として明示するルール。
 * 「問題が見つからない＝安全」と読まれないようにするためのもの。
 */

const mcpRule = { id: 'I001', title: tx('MCP サーバーの実際のツール一覧は未検証', 'The actual tool list of MCP servers is not verified') };

export const i001: SecurityRule = {
  ...mcpRule,
  description: tx(
    'MCP サーバーに接続しないため、提供されるツールとその権限は確認できないことを明示します。',
    'States that the tools and permissions MCP servers provide cannot be checked, because AgentScope does not connect to them.',
  ),
  check(ctx) {
    const out: Finding[] = [];
    const byAgent = new Map<AgentId, number>();
    for (const s of ctx.mcpServers) byAgent.set(s.agent, (byAgent.get(s.agent) ?? 0) + 1);
    for (const [agent, count] of byAgent) {
      const first = ctx.mcpServers.find((s) => s.agent === agent)!;
      const label = AGENT_LABELS[agent];
      out.push(finding(mcpRule, {
        level: 'INFO',
        agent,
        reason: tx(
          `${label} に ${count} 件の MCP サーバーが設定されています。AgentScope はサーバーを起動・接続しないため、各サーバーが提供するツールと、その操作範囲は確認していません。`,
          `${count} MCP server(s) are configured for ${label}. AgentScope does not start or connect to servers, so the tools each one provides and their reach were not checked.`,
        ),
        file: first.source.file,
        pointer: first.source.pointer,
        recommendation: tx(
          '各サーバーの提供元・利用目的を確認し、不要なサーバーは削除してください。',
          'Check who provides each server and why it is used, and remove servers you do not need.',
        ),
      }));
    }
    return out;
  },
};

const cursorRule = { id: 'I002', title: tx('Cursor の IDE 設定は未検証', 'Cursor IDE settings are not verified') };

export const i002: SecurityRule = {
  ...cursorRule,
  description: tx(
    'Cursor の Run Mode や IDE 側の許可リストは設定ファイルの外にあるため確認できないことを明示します。',
    "States that Cursor's Run Mode and IDE allowlists live outside config files and cannot be checked.",
  ),
  check(ctx) {
    const cursorFiles = ctx.files.filter((f) => f.agent === 'cursor' && f.status === 'parsed');
    if (cursorFiles.length === 0) return [];
    return [finding(cursorRule, {
      level: 'INFO',
      agent: 'cursor',
      reason: tx(
        'Cursor の Run Mode（自動実行の可否）、IDE の設定画面で登録した許可リスト、チーム管理者の設定は設定ファイルの外にあるため、確認していません。',
        "Cursor's Run Mode (whether actions auto-run), allowlists registered in the IDE settings, and team admin settings live outside config files, so they were not checked.",
      ),
      file: cursorFiles[0]!.displayPath,
      pointer: '(file)',
      recommendation: tx(
        'Cursor の設定画面で Run Mode と許可リストもあわせて確認してください。',
        'Also review Run Mode and the allowlists in the Cursor settings.',
      ),
    })];
  },
};

const autoExecRule = { id: 'I003', title: tx('自動実行されるコマンドが設定されている', 'Automatically executed commands are configured') };

/** フックやヘルパーコマンドは、エージェントの権限ルールとは別に自動で実行される。中身は解析しないため存在だけを示す */
export const i003: SecurityRule = {
  ...autoExecRule,
  description: tx(
    'フックやステータスライン、認証ヘルパーなど、権限ルールとは別に自動実行されるコマンドの存在を明示します。',
    'States that commands run automatically outside the permission rules, such as hooks, the status line, or auth helpers.',
  ),
  check(ctx) {
    const byFile = new Map<string, string[]>();
    const first = new Map<string, string>();
    for (const s of ctx.settings) {
      if (s.agent !== 'claude-code' || !AUTO_EXEC_KEYS.has(s.key) || s.status !== 'active') continue;
      byFile.set(s.source.file, [...(byFile.get(s.source.file) ?? []), s.key]);
      if (!first.has(s.source.file)) first.set(s.source.file, s.source.pointer);
    }
    return [...byFile].map(([file, keys]) =>
      finding(autoExecRule, {
        level: 'INFO',
        agent: 'claude-code',
        reason: tx(
          `${keys.join(', ')} に、Claude Code が自動で実行するコマンドが設定されています。これらは権限ルールの確認を経ずに実行され、AgentScope は中身を解析していません。`,
          `${keys.join(', ')} configure commands that Claude Code runs automatically. They run without going through permission rules, and AgentScope does not analyze them.`,
        ),
        file,
        pointer: first.get(file)!,
        recommendation: tx(
          '各コマンドの内容と、リポジトリから変更されうるかを確認してください。',
          'Review what each command does and whether it can be changed through the repository.',
        ),
      }),
    );
  },
};
