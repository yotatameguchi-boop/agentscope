import type { Finding } from '../types.js';
import { redactIfSecret } from '../util/secrets.js';
import { finding, type SecurityRule } from './types.js';

const rule = { id: 'R002', title: 'すべての MCP ツールを自動承認する設定' };

export const r002: SecurityRule = {
  ...rule,
  description: 'MCP サーバーのツールをまとめて承認なしで実行できる設定や、プロジェクトの MCP サーバーを一括承認する設定を検出します。',
  check(ctx) {
    const out: Finding[] = [];
    const recClaude = '必要なツールだけを「mcp__<server>__<tool>」の形で個別に allow に入れてください。';
    const recCursor = '必要なツールだけを「server:tool」の形で mcpAllowlist に入れてください。';

    for (const r of ctx.rules) {
      if (r.effect !== 'allow' || r.category !== 'mcp') continue;
      const base = { agent: r.agent, file: r.source.file, pointer: r.source.pointer, evidence: redactIfSecret(r.raw) };

      if (r.agent === 'claude-code') {
        const rest = r.tool.slice('mcp__'.length);
        const sep = rest.indexOf('__');
        const server = sep === -1 ? rest : rest.slice(0, sep);
        const toolPart = sep === -1 ? undefined : rest.slice(sep + 2);
        if (server === '' || server.includes('*')) {
          // mcp__* のようにサーバー名にワイルドカードを含む allow は Claude Code が無視する
          out.push(finding(rule, {
            ...base,
            level: 'INFO',
            reason: 'サーバー名を特定しないワイルドカードの allow ルールは Claude Code に無視されますが、意図としては全 MCP ツールの自動承認です',
            recommendation: recClaude,
          }));
          continue;
        }
        if (toolPart === undefined || toolPart === '*') {
          out.push(finding(rule, {
            ...base,
            level: 'MEDIUM',
            reason: `MCP サーバー「${server}」のすべてのツールを承認なしで実行できます（ツールの一覧は設定ファイルからは分かりません）`,
            recommendation: recClaude,
          }));
        }
        continue;
      }

      // Cursor mcpAllowlist: server:tool（大文字小文字を区別しない、glob 可）
      const spec = r.specifier ?? '';
      const idx = spec.indexOf(':');
      const server = spec.slice(0, idx).trim();
      const tool = spec.slice(idx + 1).trim();
      const serverAll = server === '*' || server === '';
      const toolAll = tool === '*' || tool === '';
      if (serverAll && toolAll) {
        out.push(finding(rule, { ...base, level: 'HIGH', reason: 'すべての MCP サーバーのすべてのツールを承認なしで実行できます', recommendation: recCursor }));
      } else if (toolAll) {
        out.push(finding(rule, { ...base, level: 'MEDIUM', reason: `MCP サーバー「${server}」のすべてのツールを承認なしで実行できます`, recommendation: recCursor }));
      } else if (serverAll) {
        out.push(finding(rule, { ...base, level: 'MEDIUM', reason: `すべての MCP サーバーの「${tool}」ツールを承認なしで実行できます（今後追加されるサーバーも含みます）`, recommendation: recCursor }));
      }
    }

    for (const s of ctx.settings) {
      if (s.agent === 'claude-code' && s.key === 'enableAllProjectMcpServers' && s.value === 'true') {
        out.push(finding(rule, {
          level: 'MEDIUM',
          agent: s.agent,
          reason: 'プロジェクトの .mcp.json に書かれた MCP サーバーが、確認なしで起動・利用されます。リポジトリに追加されたサーバーもそのまま有効になります',
          file: s.source.file,
          pointer: s.source.pointer,
          evidence: 'enableAllProjectMcpServers: true',
          recommendation: 'enableAllProjectMcpServers を外し、信頼できるサーバーだけを enabledMcpjsonServers に列挙してください。',
        }));
      }
    }
    return out;
  },
};
