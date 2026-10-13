import type { AgentId, Finding } from '../types.js';
import { AGENT_LABELS } from '../types.js';
import { finding, type SecurityRule } from './types.js';

/**
 * 静的解析では確認できない範囲を INFO として明示するルール。
 * 「問題が見つからない＝安全」と読まれないようにするためのもの。
 */

const mcpRule = { id: 'I001', title: 'MCP サーバーの実際のツール一覧は未検証' };

export const i001: SecurityRule = {
  ...mcpRule,
  description: 'MCP サーバーに接続しないため、提供されるツールとその権限は確認できないことを明示します。',
  check(ctx) {
    const out: Finding[] = [];
    const byAgent = new Map<AgentId, number>();
    for (const s of ctx.mcpServers) byAgent.set(s.agent, (byAgent.get(s.agent) ?? 0) + 1);
    for (const [agent, count] of byAgent) {
      const first = ctx.mcpServers.find((s) => s.agent === agent)!;
      out.push(finding(mcpRule, {
        level: 'INFO',
        agent,
        reason: `${AGENT_LABELS[agent]} に ${count} 件の MCP サーバーが設定されています。AgentScope はサーバーを起動・接続しないため、各サーバーが提供するツールと、その操作範囲は確認していません。`,
        file: first.source.file,
        pointer: first.source.pointer,
        recommendation: '各サーバーの提供元・利用目的を確認し、不要なサーバーは削除してください。',
      }));
    }
    return out;
  },
};

const cursorRule = { id: 'I002', title: 'Cursor の IDE 設定は未検証' };

export const i002: SecurityRule = {
  ...cursorRule,
  description: 'Cursor の Run Mode や IDE 側の許可リストは設定ファイルの外にあるため確認できないことを明示します。',
  check(ctx) {
    const cursorFiles = ctx.files.filter((f) => f.agent === 'cursor' && f.status === 'parsed');
    if (cursorFiles.length === 0) return [];
    return [finding(cursorRule, {
      level: 'INFO',
      agent: 'cursor',
      reason: 'Cursor の Run Mode（自動実行の可否）、IDE の設定画面で登録した許可リスト、チーム管理者の設定は設定ファイルの外にあるため、確認していません。',
      file: cursorFiles[0]!.displayPath,
      pointer: '(ファイル全体)',
      recommendation: 'Cursor の設定画面で Run Mode と許可リストもあわせて確認してください。',
    })];
  },
};
