import { promises as fs } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

// Windows ではシンボリックリンクの作成に管理者権限か開発者モードが必要なため省略する
const noSymlink = process.platform === 'win32';
import { scan } from '../src/scan.js';
import { FAKE, FIXTURES, makeDir } from './helpers.js';

describe('scan: 固定フィクスチャ', () => {
  it('危険な設定をまとめて検出する', async () => {
    const r = await scan({ root: path.join(FIXTURES, 'risky-project'), home: await makeDir() });
    expect(r.files.map((f) => [f.displayPath, f.status])).toEqual([
      ['.claude/settings.json', 'parsed'],
      ['.claude/settings.local.json', 'parsed'],
      ['.mcp.json', 'parsed'],
      ['.cursor/mcp.json', 'parsed'],
      ['.cursor/permissions.json', 'parsed'],
    ]);
    const ids = new Set(r.findings.map((f) => f.ruleId));
    for (const id of ['R001', 'R002', 'R003', 'R004', 'R005', 'I001', 'I002']) expect(ids, id).toContain(id);
    expect(r.summary.findings.HIGH).toBeGreaterThan(0);
    // enableAllProjectMcpServers: true により .mcp.json のサーバーは承認済み
    expect(r.mcpServers.filter((s) => s.agent === 'claude-code').map((s) => s.approval)).toEqual(['approved', 'approved']);
    expect(r.unparsed.map((u) => u.pointer)).toEqual(expect.arrayContaining(['hooks', 'someUnknownKey', 'mcpAllowlist[3]']));
  });

  it('限定された設定では HIGH / MEDIUM を出さない', async () => {
    const r = await scan({ root: path.join(FIXTURES, 'clean-project'), home: await makeDir() });
    expect(r.summary.rules).toBe(6);
    expect(r.summary.findings).toMatchObject({ HIGH: 0, MEDIUM: 0 });
  });

  it('壊れた設定はエラー終了せず解析エラーとして記録する', async () => {
    const r = await scan({ root: path.join(FIXTURES, 'broken-project'), home: await makeDir() });
    const byPath = Object.fromEntries(r.files.map((f) => [f.displayPath, f]));
    expect(byPath['.claude/settings.json']!.status).toBe('parse-error');
    expect(byPath['.mcp.json']!.status).toBe('parsed');
    expect(r.unparsed).toEqual([expect.objectContaining({ file: '.mcp.json', pointer: '(root)' })]);
  });

  it('設定ファイルがなければ空の結果を返す', async () => {
    const r = await scan({ root: path.join(FIXTURES, 'empty-project'), home: await makeDir() });
    expect(r.files).toEqual([]);
    expect(r.findings).toEqual([]);
  });
});

describe('scan: オプション', () => {
  it('--agent で対象を絞る', async () => {
    const root = path.join(FIXTURES, 'risky-project');
    const home = await makeDir();
    const claude = await scan({ root, home, agents: ['claude-code'] });
    expect(new Set(claude.files.map((f) => f.agent))).toEqual(new Set(['claude-code']));
    const cursor = await scan({ root, home, agents: ['cursor'] });
    expect(new Set(cursor.files.map((f) => f.agent))).toEqual(new Set(['cursor']));
  });

  it('既定ではユーザー設定を読まず、--include-global で読む', async () => {
    const root = await makeDir();
    const home = await makeDir({
      '.claude/settings.json': JSON.stringify({ permissions: { defaultMode: 'bypassPermissions' } }),
      '.claude.json': JSON.stringify({
        oauthAccount: { emailAddress: 'someone@example.com' },
        mcpServers: { userSrv: { command: 'uvx', env: { API_TOKEN: FAKE.github } } },
        projects: { [root]: { mcpServers: { localSrv: { type: 'http', url: 'https://local.example.com/mcp' } } } },
      }),
      '.cursor/mcp.json': JSON.stringify({ mcpServers: { c: { command: 'node' } } }),
      '.cursor/permissions.json': JSON.stringify({ mcpAllowlist: ['*:*'] }),
      '.cursor/cli-config.json': JSON.stringify({ permissions: { allow: ['Shell(*)'] } }),
    });

    const local = await scan({ root, home });
    expect(local.files).toEqual([]);

    const g = await scan({ root, home, includeGlobal: true });
    expect(g.files.map((f) => [f.displayPath, f.scope, f.status])).toEqual([
      ['~/.claude/settings.json', 'user', 'parsed'],
      ['~/.claude.json', 'user', 'parsed'],
      ['~/.cursor/mcp.json', 'user', 'parsed'],
      ['~/.cursor/permissions.json', 'user', 'parsed'],
      ['~/.cursor/cli-config.json', 'user', 'unsupported'],
    ]);
    expect(g.mcpServers.map((s) => [s.name, s.scope])).toEqual([
      ['userSrv', 'user'],
      ['localSrv', 'project-local'],
      ['c', 'user'],
    ]);
    expect(g.findings.find((f) => f.ruleId === 'R003')?.level).toBe('HIGH');
    expect(g.findings.find((f) => f.ruleId === 'R004')).toMatchObject({ level: 'HIGH', file: '~/.claude.json', pointer: 'mcpServers.userSrv.env.API_TOKEN' });
    const dump = JSON.stringify(g);
    expect(dump).not.toContain(FAKE.github);
    expect(dump).not.toContain('someone@example.com');
  });

  it('存在しないディレクトリはエラーにする', async () => {
    await expect(scan({ root: '/definitely/not/here/agentscope' })).rejects.toThrow(/not found/);
  });

  it.skipIf(noSymlink)('プロジェクト外を指すシンボリックリンクの設定は読まずにスキップと表示する', async () => {
    const outside = await makeDir({ 'evil.json': JSON.stringify({ permissions: { allow: ['Bash'] } }) });
    const root = await makeDir();
    await fs.mkdir(path.join(root, '.claude'));
    await fs.symlink(path.join(outside, 'evil.json'), path.join(root, '.claude', 'settings.json'));
    const r = await scan({ root, home: await makeDir() });
    expect(r.files[0]).toMatchObject({ status: 'skipped', displayPath: '.claude/settings.json' });
    expect(r.rules).toEqual([]);
  });
});
