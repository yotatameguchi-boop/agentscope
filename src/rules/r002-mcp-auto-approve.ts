import { tx } from '../i18n.js';
import type { Finding } from '../types.js';
import { redactIfSecret } from '../util/secrets.js';
import { finding, type SecurityRule } from './types.js';

const rule = { id: 'R002', title: tx('すべての MCP ツールを自動承認する設定', 'All MCP tools are auto-approved') };

const REC_CLAUDE = tx(
  '必要なツールだけを「mcp__<server>__<tool>」の形で個別に allow に入れてください。',
  'Add only the tools you need to allow, one by one, as "mcp__<server>__<tool>".',
);
const REC_CURSOR_CLI = tx(
  '必要なツールだけを「Mcp(server:tool)」の形で permissions.allow に入れてください。',
  'Add only the tools you need to permissions.allow as "Mcp(server:tool)".',
);
const REC_CURSOR = tx(
  '必要なツールだけを「server:tool」の形で mcpAllowlist に入れてください。',
  'Add only the tools you need to mcpAllowlist as "server:tool".',
);

export const r002: SecurityRule = {
  ...rule,
  description: tx(
    'MCP サーバーのツールをまとめて承認なしで実行できる設定や、プロジェクトの MCP サーバーを一括承認する設定を検出します。',
    'Detects settings that let MCP tools run without approval in bulk, or that approve all project MCP servers at once.',
  ),
  check(ctx) {
    const out: Finding[] = [];

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
            reason: tx(
              'サーバー名を特定しないワイルドカードの allow ルールは Claude Code に無視されますが、意図としては全 MCP ツールの自動承認です',
              'Claude Code ignores allow rules whose server name is a wildcard, but the intent is to auto-approve every MCP tool',
            ),
            recommendation: REC_CLAUDE,
          }));
          continue;
        }
        if (toolPart === undefined || toolPart === '*') {
          out.push(finding(rule, {
            ...base,
            level: 'MEDIUM',
            reason: tx(
              `MCP サーバー「${server}」のすべてのツールを承認なしで実行できます（ツールの一覧は設定ファイルからは分かりません）`,
              `Every tool of MCP server "${server}" can run without approval (the tool list is not visible from config files)`,
            ),
            recommendation: REC_CLAUDE,
          }));
        }
        continue;
      }

      // Cursor mcpAllowlist / CLI の Mcp(...): server:tool（大文字小文字を区別しない、glob 可）
      const recCursor = r.nativeKind.startsWith('cursor.cli.') ? REC_CURSOR_CLI : REC_CURSOR;
      const spec = r.specifier ?? '';
      const idx = spec.indexOf(':');
      const server = spec.slice(0, idx).trim();
      const tool = spec.slice(idx + 1).trim();
      const serverAll = server === '*' || server === '';
      const toolAll = tool === '*' || tool === '';
      if (serverAll && toolAll) {
        out.push(finding(rule, {
          ...base,
          level: 'HIGH',
          reason: tx('すべての MCP サーバーのすべてのツールを承認なしで実行できます', 'Every tool of every MCP server can run without approval'),
          recommendation: recCursor,
        }));
      } else if (toolAll) {
        out.push(finding(rule, {
          ...base,
          level: 'MEDIUM',
          reason: tx(`MCP サーバー「${server}」のすべてのツールを承認なしで実行できます`, `Every tool of MCP server "${server}" can run without approval`),
          recommendation: recCursor,
        }));
      } else if (serverAll) {
        out.push(finding(rule, {
          ...base,
          level: 'MEDIUM',
          reason: tx(
            `すべての MCP サーバーの「${tool}」ツールを承認なしで実行できます（今後追加されるサーバーも含みます）`,
            `The "${tool}" tool of every MCP server can run without approval (including servers added later)`,
          ),
          recommendation: recCursor,
        }));
      }
    }

    for (const s of ctx.settings) {
      if (s.agent === 'claude-code' && s.key === 'enableAllProjectMcpServers' && s.value === 'true') {
        out.push(finding(rule, {
          level: 'MEDIUM',
          agent: s.agent,
          reason: tx(
            'プロジェクトの .mcp.json に書かれた MCP サーバーが、確認なしで起動・利用されます。リポジトリに追加されたサーバーもそのまま有効になります',
            'MCP servers listed in the project .mcp.json are started and used without confirmation. Servers added to the repository are enabled as-is',
          ),
          file: s.source.file,
          pointer: s.source.pointer,
          evidence: 'enableAllProjectMcpServers: true',
          recommendation: tx(
            'enableAllProjectMcpServers を外し、信頼できるサーバーだけを enabledMcpjsonServers に列挙してください。',
            'Remove enableAllProjectMcpServers and list only trusted servers in enabledMcpjsonServers.',
          ),
        }));
      }
    }
    return out;
  },
};
