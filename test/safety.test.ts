import { promises as fs } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildProgram } from '../src/program.js';
import { scan } from '../src/scan.js';
import { FAKE, FIXTURES, makeDir, snapshot } from './helpers.js';

async function runCli(args: string[]): Promise<string> {
  let out = '';
  // 既定は日本語。英語のテストでは args に --lang en を渡す
  await buildProgram({ write: (s) => void (out += s), isTTY: false }, 'ja').parseAsync(['node', 'agentscope', ...args]);
  return out;
}

async function secretProject() {
  return makeDir({
    '.claude/settings.json': JSON.stringify({
      permissions: { allow: [`Bash(curl -H "Authorization: Bearer ${FAKE.anthropic}" https://api.example.com)`] },
      env: { GITHUB_TOKEN: FAKE.github, AWS_ACCESS_KEY_ID: FAKE.aws },
      apiKeyHelper: `echo ${FAKE.anthropic}`,
    }),
    '.mcp.json': JSON.stringify({
      mcpServers: { s: { command: 'npx', args: ['server', `--token=${FAKE.slack}`], env: { SLACK_TOKEN: FAKE.slack } } },
    }),
    '.cursor/mcp.json': JSON.stringify({
      mcpServers: { r: { url: `https://u:${FAKE.github}@mcp.example.com/`, headers: { Authorization: `Bearer ${FAKE.github}` } } },
    }),
  });
}

describe('安全性', () => {
  it('分析対象のファイルを変更しない', async () => {
    const root = path.join(FIXTURES, 'risky-project');
    const before = await snapshot(root);
    await scan({ root, home: await makeDir() });
    await runCli(['scan', root, '--format', 'json']);
    expect(await snapshot(root)).toEqual(before);
  });

  it('対象ディレクトリに新しいファイルを作らない', async () => {
    const root = await secretProject();
    const before = await snapshot(root);
    await runCli(['scan', root]);
    expect(await snapshot(root)).toEqual(before);
  });

  it.each(['text', 'json'])('%s 出力に認証情報の値を含めない', async (format) => {
    const root = await secretProject();
    const out = await runCli(['scan', root, '--format', format]);
    for (const v of Object.values(FAKE)) expect(out).not.toContain(v);
    expect(out).toContain('R004');
  });

  it('ネットワーク・プロセス実行のモジュールを読み込まない', async () => {
    const srcDir = path.join(import.meta.dirname, '..', 'src');
    const files = (await fs.readdir(srcDir, { recursive: true })).filter((f) => f.endsWith('.ts'));
    for (const f of files) {
      const text = await fs.readFile(path.join(srcDir, f), 'utf8');
      expect(text, f).not.toMatch(/from ['"](?:node:)?(?:http|https|http2|net|tls|dgram|child_process|worker_threads)['"]/);
      expect(text, f).not.toMatch(/\bfetch\(/);
      expect(text, f).not.toMatch(/\b(?:writeFile|appendFile|unlink|rm|rename|mkdir|copyFile|chmod)\w*\(/);
    }
  });
});

describe('CLI', () => {
  it('テキストレポートに主要な見出しを表示する', async () => {
    const out = await runCli(['scan', path.join(FIXTURES, 'risky-project')]);
    for (const h of ['AgentScope Security Report', '検出された設定ファイル', '権限ルール', 'MCP サーバー', '検出されたリスク', '推奨される対応', '解析できなかった項目']) {
      expect(out).toContain(h);
    }
    expect(out).toMatch(/\[HIGH\] R001/);
    expect(out).not.toMatch(/\u001b\[/); // TTY でなければ色を付けない
  });

  it('JSON 出力はパースでき、主要なキーを持つ', async () => {
    const out = await runCli(['scan', path.join(FIXTURES, 'risky-project'), '--format', 'json', '--agent', 'cursor']);
    const json = JSON.parse(out);
    expect(json.tool).toEqual({ name: 'agentscope', version: '0.1.0' });
    expect(json.agents).toEqual(['cursor']);
    expect(Object.keys(json)).toEqual(
      expect.arrayContaining(['files', 'rules', 'settings', 'mcpServers', 'findings', 'unparsed', 'summary', 'disclaimer']),
    );
  });

  it('不正なオプションは受け付けない', async () => {
    const program = buildProgram({ write: () => {}, isTTY: false });
    program.exitOverride().configureOutput({ writeErr: () => {}, writeOut: () => {} });
    for (const c of program.commands) c.exitOverride().configureOutput({ writeErr: () => {}, writeOut: () => {} });
    await expect(program.parseAsync(['node', 'agentscope', 'scan', '--agent', 'copilot'])).rejects.toThrow();
  });
});
