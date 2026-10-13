import { tx } from '../i18n.js';
import type { AgentId, Finding } from '../types.js';
import { AGENT_LABELS } from '../types.js';
import { AUTO_EXEC_KEYS } from '../parsers/claude.js';
import { SOURCE_LABEL } from '../precedence.js';
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

const managedRule = { id: 'I004', title: tx('組織の管理設定の配布元', 'Sources of organization-managed settings') };

/**
 * どの管理設定の配布元を確認でき、どれを使うと判定したか、どれを確認できなかったかを明示する（-g のときだけ）。
 */
export const i004: SecurityRule = {
  ...managedRule,
  description: tx(
    '確認できた管理設定の配布元と使われる配布元、確認できない配布元（Windows のレジストリ、サーバー配信の最新の内容）を明示します。',
    'States which managed settings sources were found and used, and which cannot be checked (the Windows registry, the latest server-managed payload).',
  ),
  check(ctx) {
    if (!ctx.includeGlobal || !ctx.agents.includes('claude-code')) return [];
    const managed = ctx.files.filter((f) => f.managedSource);
    const selected = managed.find((f) => f.managedSelected && f.managedSource !== undefined);
    const found = [...new Set(managed.map((f) => f.managedSource!))];
    const label = (s: string) => SOURCE_LABEL[s as keyof typeof SOURCE_LABEL];
    const parts: Array<{ ja: string; en: string }> = [];
    if (found.length === 0) {
      parts.push(tx('管理設定は見つかりませんでした。', 'No managed settings were found.'));
    } else {
      parts.push(tx(`見つかった配布元: ${found.map((s) => label(s).ja).join('、')}。`, `Sources found: ${found.map((s) => label(s).en).join(', ')}.`));
      if (selected) parts.push(tx(`使われる配布元: ${label(selected.managedSource!).ja}。`, `Source in effect: ${label(selected.managedSource!).en}.`));
    }
    if (found.includes('remote')) {
      parts.push(tx(
        'サーバー配信の設定はローカルのキャッシュを読んでいます。最新の内容とは異なる場合があり、サードパーティのプロバイダや公式以外の ANTHROPIC_BASE_URL を使うセッションには適用されません。',
        'Server-managed settings are read from the local cache. It may differ from the latest payload, and it does not apply to sessions that use a third-party provider or a non-default ANTHROPIC_BASE_URL.',
      ));
    } else {
      parts.push(tx(
        'サーバー配信の管理設定は、取得済みのキャッシュがないため確認していません（AgentScope は通信しません）。',
        'Server-managed settings were not checked because there is no local cache (AgentScope does not use the network).',
      ));
    }
    if (ctx.platform === 'win32') {
      parts.push(tx(
        'Windows のレジストリ（HKLM / HKCU の SOFTWARE\\Policies\\ClaudeCode）は、外部コマンドを実行しない方針のため確認していません。',
        'The Windows registry (SOFTWARE\\Policies\\ClaudeCode under HKLM / HKCU) was not checked, because AgentScope does not run external commands.',
      ));
    }
    return [finding(managedRule, {
      level: 'INFO',
      agent: 'claude-code',
      reason: tx(parts.map((p) => p.ja).join(''), parts.map((p) => p.en).join(' ')),
      file: selected?.displayPath ?? '(managed settings)',
      pointer: '(sources)',
      recommendation: tx(
        '管理設定が意図どおりに適用されているかは、Claude Code の /status や claude doctor でも確認してください。',
        'Also check with /status or claude doctor in Claude Code that the managed policy is applied as intended.',
      ),
    })];
  },
};
