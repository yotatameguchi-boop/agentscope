/**
 * 回帰テスト ④検出範囲の拡充
 * これまで見落としていた危険な書き方を検出し、限定された書き方は検出しないことを確認する。
 */
import { describe, expect, it } from 'vitest';
import { classifyCommand } from '../src/rules/r001-broad-command.js';
import { scan } from '../src/scan.js';
import type { ScanResult } from '../src/types.js';
import { makeDir } from './helpers.js';

const json = (v: unknown) => JSON.stringify(v);

async function run(files: Record<string, string>): Promise<ScanResult> {
  const home = await makeDir();
  return scan({ root: await makeDir(files), home, managedDir: await makeDir() });
}

const levelsOf = (r: ScanResult, id: string) => r.findings.filter((f) => f.ruleId === id).map((f) => [f.evidence, f.level]);

describe('回帰: R001 コマンド実行の見落とし', () => {
  it.each([
    ['python3 -c *', 'HIGH'],
    ['node -e *', 'HIGH'],
    ['bash -c *', 'HIGH'],
    ['python3 *.py', 'HIGH'],
    ['timeout *', 'HIGH'],
    ['npm exec *', 'HIGH'],
    ['docker run *', 'HIGH'],
    ['uv run *', 'HIGH'],
    ['git -c *', 'HIGH'],
    ['/usr/bin/python3 *', 'HIGH'],
    ['git * main', 'MEDIUM'],
    ['gh api *', 'MEDIUM'],
    ['git push *', 'MEDIUM'],
    ['curl*', 'MEDIUM'],
  ])('Bash(%s) → %s', (spec, level) => {
    expect(classifyCommand(spec, false)?.level).toBe(level);
  });

  it.each(['npm run test *', 'python3 manage.py test *', 'docker compose ps *', 'git status', 'uv run pytest *'])('限定された Bash(%s) は検出しない', (spec) => {
    expect(classifyCommand(spec, false)).toBeUndefined();
  });

  it('Cursor の前方一致でも多語のランナーを検出する', () => {
    expect(classifyCommand('npm exec', true)?.level).toBe('HIGH');
    expect(classifyCommand('python3 -c', true)?.level).toBe('HIGH');
    expect(classifyCommand('npm:install*', true)).toBeUndefined();
  });
});

describe('回帰: Cursor CLI（cli.json）の解析', () => {
  it('Shell / Read / Write / WebFetch / Mcp を解析し、各ルールで検査する', async () => {
    const r = await run({
      '.cursor/cli.json': json({
        permissions: {
          allow: ['Shell(*)', 'Shell(git)', 'Shell(ls)', 'Mcp(*:*)', 'Mcp(datadog:*)', 'Write(/**)', 'Write(**)', 'Read(~/.ssh/**)', 'WebFetch(*)', 'WebFetch(docs.github.com)'],
          deny: ['Read(.env)'],
        },
        editor: { vimMode: true },
      }),
    });
    expect(r.files[0]).toMatchObject({ displayPath: '.cursor/cli.json', status: 'parsed', kind: 'cursor-cli' });
    expect(r.rules.map((x) => x.nativeKind)).toContain('cursor.cli.permissions.deny');
    expect(levelsOf(r, 'R001')).toEqual([['Shell(*)', 'HIGH'], ['Shell(git)', 'MEDIUM']]);
    expect(levelsOf(r, 'R002')).toEqual([['Mcp(*:*)', 'HIGH'], ['Mcp(datadog:*)', 'MEDIUM']]);
    expect(levelsOf(r, 'R005')).toEqual([['Write(/**)', 'HIGH'], ['Read(~/.ssh/**)', 'MEDIUM'], ['Write(**)', 'LOW']]);
    expect(levelsOf(r, 'R006')).toEqual([['WebFetch(*)', 'MEDIUM']]);
    expect(r.unparsed).toEqual([]); // permissions 以外の CLI 設定は対象外として読み飛ばす
  });
});

describe('回帰: R005 ファイル操作の見落とし', () => {
  it.each([
    ['Edit(.github/workflows/**)', 'MEDIUM'],
    ['Edit(.vscode/tasks.json)', 'MEDIUM'],
    ['Edit(.husky/**)', 'MEDIUM'],
    ['Read(~/.aws/**)', 'MEDIUM'],
    ['Read(~/.netrc)', 'MEDIUM'],
    ['Read(~/.kube/**)', 'MEDIUM'],
    ['Read(**/*.pem)', 'MEDIUM'],
    ['Edit(//c/**)', 'HIGH'],
  ])('%s → %s', async (rule, level) => {
    const r = await run({ '.claude/settings.json': json({ permissions: { allow: [rule] } }) });
    expect(levelsOf(r, 'R005')).toEqual([[rule, level]]);
  });

  it('additionalDirectories にホームディレクトリの絶対パスを入れた場合も検出する', async () => {
    const home = await makeDir();
    const root = await makeDir({ '.claude/settings.json': json({ permissions: { additionalDirectories: [home] } }) });
    const r = await scan({ root, home });
    expect(r.findings.find((f) => f.ruleId === 'R005')?.level).toBe('MEDIUM');
  });
});

describe('回帰: R006 ネットワーク', () => {
  it.each([
    [{ permissions: { allow: ['WebFetch'] } }, 1],
    [{ permissions: { allow: ['WebFetch(domain:*)'] } }, 1],
    [{ sandbox: { network: { allowedDomains: ['github.com', '*'] } } }, 1],
    [{ permissions: { allow: ['WebFetch(domain:docs.github.com)'] } }, 0],
    [{ sandbox: { network: { allowedDomains: ['*.github.com'] } } }, 0],
  ])('%j → %d 件', async (settings, n) => {
    const r = await run({ '.claude/settings.json': json(settings) });
    expect(r.findings.filter((f) => f.ruleId === 'R006')).toHaveLength(n);
  });
});

describe('回帰: I003 自動実行されるコマンド', () => {
  it('フックや apiKeyHelper の存在を INFO で示し、コマンドは表示しない', async () => {
    const r = await run({
      '.claude/settings.json': json({
        hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'secret-hook --flag' }] }], Stop: [{ hooks: [{ type: 'command', command: 'b' }] }] },
        statusLine: { type: 'command', command: 'status-cmd' },
        apiKeyHelper: 'get-key-cmd',
      }),
    });
    const f = r.findings.find((x) => x.ruleId === 'I003')!;
    expect(f.level).toBe('INFO');
    expect(f.reason.en).toMatch(/hooks, statusLine, apiKeyHelper/);
    expect(r.settings.find((s) => s.key === 'hooks')?.value).toMatchObject({ en: '2 hook(s) (commands not shown)' });
    const dump = JSON.stringify(r);
    for (const cmd of ['secret-hook', 'status-cmd', 'get-key-cmd']) expect(dump).not.toContain(cmd);
  });
});

describe('回帰: R004 認証情報の見落とし', () => {
  it('データベース URL のパスワードを検出する', async () => {
    const r = await run({ '.mcp.json': json({ mcpServers: { db: { command: 'node', args: ['postgres://app:S3cretPassw0rd@db.example.com/app'] } } }) });
    expect(r.findings.find((f) => f.ruleId === 'R004')?.level).toBe('HIGH');
    expect(JSON.stringify(r)).not.toContain('S3cretPassw0rd');
  });
});
