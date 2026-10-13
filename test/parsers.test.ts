import { describe, expect, it } from 'vitest';
import {
  parseClaudeGlobalState,
  parseClaudeMcpJson,
  parseClaudeSettings,
  resolveClaudeMcpApproval,
  splitClaudeRule,
} from '../src/parsers/claude.js';
import type { ParseContext } from '../src/parsers/common.js';
import { parseCursorMcpJson, parseCursorPermissions } from '../src/parsers/cursor.js';
import { FAKE } from './helpers.js';

const claudeCtx: ParseContext = { agent: 'claude-code', scope: 'project', file: '.claude/settings.json', root: '/repo' };
const cursorCtx: ParseContext = { agent: 'cursor', scope: 'project', file: '.cursor/permissions.json', root: '/repo' };

describe('splitClaudeRule', () => {
  it.each([
    ['Bash', { tool: 'Bash' }],
    ['Bash(npm run *)', { tool: 'Bash', specifier: 'npm run *' }],
    ['Edit(./Finance (2024)/**)', { tool: 'Edit', specifier: './Finance (2024)/**' }],
    ['mcp__github__create_issue', { tool: 'mcp__github__create_issue' }],
  ])('%s', (raw, expected) => {
    expect(splitClaudeRule(raw)).toEqual(expected);
  });

  it.each(['', 'Bash(npm', '(x)', 'Ba)sh'])('壊れた書式 %j は undefined', (raw) => {
    expect(splitClaudeRule(raw)).toBeUndefined();
  });
});

describe('parseClaudeSettings', () => {
  it('allow / ask / deny と関連設定を抽出する', () => {
    const r = parseClaudeSettings(claudeCtx, {
      permissions: {
        allow: ['Bash(npm test)', 'Read(src/**)', 'mcp__gh__list', 'WebFetch(domain:example.com)', 'Frobnicate'],
        ask: ['Bash(git push *)'],
        deny: ['Read(./.env)'],
        defaultMode: 'acceptEdits',
        additionalDirectories: ['../shared'],
      },
      enableAllProjectMcpServers: false,
      env: { NODE_ENV: 'test' },
      model: 'whatever',
    });
    expect(r.rules.map((x) => [x.effect, x.category, x.tool, x.specifier])).toEqual([
      ['allow', 'command', 'Bash', 'npm test'],
      ['allow', 'file-read', 'Read', 'src/**'],
      ['allow', 'mcp', 'mcp__gh__list', undefined],
      ['allow', 'network', 'WebFetch', 'domain:example.com'],
      ['allow', 'unknown', 'Frobnicate', undefined],
      ['ask', 'command', 'Bash', 'git push *'],
      ['deny', 'file-read', 'Read', './.env'],
    ]);
    expect(r.rules[0]!.nativeKind).toBe('claude.permissions.allow');
    expect(r.rules[0]!.source).toEqual({ file: '.claude/settings.json', pointer: 'permissions.allow[0]' });
    expect(r.rules[4]!.note).toMatch(/知らないツール/);
    expect(r.settings.map((s) => [s.key, s.value])).toEqual([
      ['permissions.defaultMode', 'acceptEdits'],
      ['permissions.additionalDirectories', '../shared'],
      ['enableAllProjectMcpServers', 'false'],
      ['env', 'NODE_ENV（値は表示しません）'],
    ]);
    expect(r.unparsed).toEqual([]); // model は権限に無関係な既知キーなので未解析にしない
  });

  it('不明なキー・型違い・壊れたルールを未解析として明示する', () => {
    const r = parseClaudeSettings(claudeCtx, {
      permissions: { allow: ['Bash(', 42], deny: 'Bash', futureKey: true },
      hooks: { PreToolUse: [] },
      brandNewSetting: 1,
    });
    expect(r.rules).toEqual([]);
    expect(r.unparsed.map((u) => u.pointer)).toEqual([
      'permissions.allow[1]',
      'permissions.allow[0]',
      'permissions.deny',
      'permissions.futureKey',
      'hooks',
      'brandNewSetting',
    ]);
  });

  it('括弧付きの mcp__ ルールは無視される旨を注記する', () => {
    const r = parseClaudeSettings(claudeCtx, { permissions: { allow: ['mcp__gh__run(x)'] } });
    expect(r.rules[0]!.note).toMatch(/無視/);
  });

  it('apiKeyHelper のコマンドや env の値を表示用データに含めない', () => {
    const r = parseClaudeSettings(claudeCtx, { apiKeyHelper: `/bin/echo ${FAKE.anthropic}`, env: { ANTHROPIC_API_KEY: FAKE.anthropic } });
    expect(JSON.stringify(r.settings)).not.toContain(FAKE.anthropic);
    expect(r.secretHits.map((h) => h.pointer).sort()).toEqual(['apiKeyHelper', 'env.ANTHROPIC_API_KEY']);
  });

  it('ルール文字列に秘密情報が含まれる場合は伏せて保持する', () => {
    const r = parseClaudeSettings(claudeCtx, { permissions: { allow: [`Bash(curl -H "x-api-key: ${FAKE.anthropic}" https://x)`] } });
    expect(r.rules[0]!.raw).toBe('[REDACTED]');
    expect(JSON.stringify(r)).not.toContain(FAKE.anthropic);
  });

  it('トップレベルがオブジェクトでなければ未解析にする', () => {
    expect(parseClaudeSettings(claudeCtx, []).unparsed).toHaveLength(1);
  });
});

describe('Claude Code の MCP 設定', () => {
  const mcpCtx: ParseContext = { ...claudeCtx, file: '.mcp.json' };

  it('.mcp.json から名前・方式・コマンド名・ホスト名・環境変数名だけを取り出す', () => {
    const r = parseClaudeMcpJson(mcpCtx, {
      mcpServers: {
        a: { command: '/opt/bin/server --token abc', args: ['--secret', 'zzz'], env: { B: '1', A: '2' } },
        b: { type: 'http', url: 'https://user:pw@api.example.com/mcp?k=1', headers: { Authorization: 'Bearer ${T}' } },
        c: { type: 'sse', url: '${BASE_URL}/sse' },
        d: 'oops',
      },
    });
    const [a, b, c] = r.mcpServers;
    expect(a).toMatchObject({ name: 'a', transport: 'stdio', commandName: 'server', envNames: ['A', 'B'], toolPermissions: 'unknown' });
    expect(b).toMatchObject({ name: 'b', transport: 'http', urlHost: 'api.example.com', headerNames: ['Authorization'] });
    expect(c).toMatchObject({ name: 'c', transport: 'sse', urlHost: undefined });
    expect(JSON.stringify(r.mcpServers)).not.toMatch(/abc|zzz|pw|\?k=1/);
    expect(r.unparsed.map((u) => u.pointer)).toEqual(['mcpServers.c.url', 'mcpServers.d']);
    expect(r.secretHits.map((h) => h.kind)).toContain('url-credential');
  });

  it('~/.claude.json は mcpServers と対象プロジェクトのエントリだけを読む', () => {
    const r = parseClaudeGlobalState(
      { ...claudeCtx, scope: 'user', file: '~/.claude.json' },
      {
        oauthAccount: { emailAddress: 'someone@example.com' },
        userID: 'should-not-appear',
        mcpServers: { userSrv: { command: 'node' } },
        projects: {
          '/repo': { mcpServers: { localSrv: { type: 'http', url: 'https://local.example.com' } }, enabledMcpjsonServers: ['team'] },
          '/other': { mcpServers: { otherSrv: { command: 'x' } } },
        },
      },
      ['/repo'],
    );
    expect(r.mcpServers.map((s) => [s.name, s.scope, s.approval])).toEqual([
      ['userSrv', 'user', 'not-required'],
      ['localSrv', 'project-local', 'not-required'],
    ]);
    expect(r.approvalHints.enabled).toEqual([{ name: 'team', file: '~/.claude.json' }]);
    const dump = JSON.stringify(r);
    expect(dump).not.toContain('someone@example.com');
    expect(dump).not.toContain('should-not-appear');
    expect(dump).not.toContain('otherSrv');
    expect(r.unparsed).toEqual([]);
  });

  it('承認状態を disabled > enableAll > enabled の順で解決する', () => {
    const servers = parseClaudeMcpJson(mcpCtx, { mcpServers: { x: { command: 'a' }, y: { command: 'b' }, z: { command: 'c' } } }).mcpServers;
    resolveClaudeMcpApproval(servers, [
      { enabled: [{ name: 'y', file: 's' }], disabled: [{ name: 'x', file: 's' }] },
    ]);
    expect(servers.map((s) => s.approval)).toEqual(['rejected', 'approved', 'unknown']);
    resolveClaudeMcpApproval(servers, [{ enableAll: { value: true, file: 's' }, enabled: [], disabled: [] }]);
    expect(servers.map((s) => s.approval)).toEqual(['approved', 'approved', 'approved']);
  });
});

describe('Cursor', () => {
  it('permissions.json の許可リストと autoRun を区別して抽出する', () => {
    const r = parseCursorPermissions(cursorCtx, {
      mcpAllowlist: ['gh:list_*', 'bad', 1],
      terminalAllowlist: ['git status'],
      autoRun: { allow_instructions: ['tests are fine'], block_instructions: ['no deploys'], extra: [] },
      future: true,
    });
    expect(r.rules.map((x) => [x.effect, x.category, x.nativeKind, x.specifier])).toEqual([
      ['allow', 'mcp', 'cursor.mcpAllowlist', 'gh:list_*'],
      ['allow', 'command', 'cursor.terminalAllowlist', 'git status'],
      ['guidance-allow', 'other', 'cursor.autoRun.allow_instructions', 'tests are fine'],
      ['guidance-block', 'other', 'cursor.autoRun.block_instructions', 'no deploys'],
    ]);
    expect(r.rules[2]!.note).toMatch(/強制力はなく/);
    expect(r.unparsed.map((u) => u.pointer)).toEqual(['mcpAllowlist[2]', 'mcpAllowlist[1]', 'autoRun.extra', 'future']);
  });

  it('mcp.json の接続方式を推定し、url のみの場合は不明とする', () => {
    const r = parseCursorMcpJson({ ...cursorCtx, file: '.cursor/mcp.json' }, {
      mcpServers: {
        s: { command: 'C:\\tools\\srv.exe' },
        u: { url: 'https://mcp.example.org/x' },
        h: { type: 'streamable-http', url: 'https://h.example.org' },
        e: { command: 'node', envFile: '.env' },
      },
    });
    expect(r.mcpServers.map((s) => [s.name, s.transport, s.commandName ?? s.urlHost, s.approval])).toEqual([
      ['s', 'stdio', 'srv', 'unknown'],
      ['u', 'unknown', 'mcp.example.org', 'unknown'],
      ['h', 'http', 'h.example.org', 'unknown'],
      ['e', 'stdio', 'node', 'unknown'],
    ]);
    expect(r.unparsed.map((u) => u.pointer)).toEqual(['mcpServers.e.envFile']);
  });
});
