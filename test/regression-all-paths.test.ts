/**
 * 回帰テスト: 秘密情報の出力保護を入力経路ごとに統一できているか。
 * 既知形式のダミーキーを、AgentScope が読むすべての入力経路に置き、どの出力にも残らないことを確認する。
 */
import { describe, expect, it } from 'vitest';
import { buildProgram } from '../src/program.js';
import { FAKE, makeDir } from './helpers.js';

const K = FAKE.anthropic;
const G = FAKE.github;
const json = (v: unknown) => JSON.stringify(v);

describe('回帰: すべての入力経路で秘密情報を出力しない', () => {
  it('設定ファイル・MCP・Cursor・起動コマンド・環境変数のどこに置いても残らない', async () => {
    const root = await makeDir({
      '.claude/settings.json': json({
        [K]: true,
        permissions: { allow: [`Bash(echo ${K})`, `Edit(/${G}/**)`], deny: [`Read(${K})`], defaultMode: K, additionalDirectories: [`/tmp/${K}`] },
        enabledMcpjsonServers: [K],
        sandbox: { excludedCommands: [K], network: { allowedDomains: [K] } },
        env: { [K]: 'x', ANTHROPIC_BASE_URL: `https://${K}.example.com`, NODE_EXTRA_CA_CERTS: `/certs/${K}.pem` },
        hooks: { Stop: [{ hooks: [{ type: 'command', command: `curl -H "x: ${K}"` }] }] },
      }),
      '.mcp.json': json({ mcpServers: { [G]: { command: `/opt/${K}/bin`, args: [K], url: `https://u:${K}@h.example/${K}?token=${K}`, env: { [K]: K }, headers: { [K]: K } } } }),
      '.cursor/mcp.json': json({ mcpServers: { s: { url: `https://h.example/?api_key=${G}` } } }),
      '.cursor/permissions.json': json({ mcpAllowlist: [`${K}:*`], terminalAllowlist: [`echo ${G}`], autoRun: { allow_instructions: [`token is ${K}`] } }),
      '.cursor/cli.json': json({ permissions: { allow: [`Shell(${K})`, `WebFetch(${G})`] } }),
      'package.json': json({ scripts: { ai: `claude --add-dir /tmp/${K} --permission-mode ${G} --tools ${K}` } }),
      '.github/workflows/ci.yml': `env:\n  ANTHROPIC_API_KEY: ${K}\njobs:\n  a:\n    steps:\n      - run: agent --sandbox ${G} --api-key ${K}\n`,
      '.devcontainer/devcontainer.json': json({ containerEnv: { HTTPS_PROXY: `http://u:${K}@proxy` }, postCreateCommand: `claude --settings '{"env":{"X_TOKEN":"${G}"}}'` }),
      Makefile: `ai:\n\tclaude --setting-sources ${K}\n`,
    });
    // シェルの設定ファイル（-g）の経路は test/env.test.ts と test/launch.test.ts で確認している
    const before = process.env.CURSOR_API_KEY;
    process.env.CURSOR_API_KEY = G;
    try {
      for (const lang of ['ja', 'en'] as const) {
        for (const format of ['text', 'json']) {
          let out = '';
          const program = buildProgram({ write: (s) => void (out += s), isTTY: false }, lang);
          await program.parseAsync([
            'node', 'a', 'scan', root, '--format', format, '--lang', lang, '-e',
            '--launch', `ANTHROPIC_API_KEY=${K} claude --mcp-config '{"mcpServers":{"x":{"command":"node","env":{"T":"${G}"}}}}'`,
            '--launch', `claude --add-dir ${G}`,
          ]);
          expect(out, `${lang}/${format}`).not.toContain(K);
          expect(out, `${lang}/${format}`).not.toContain(G);
          expect(out).toContain('[REDACTED]');
        }
      }
    } finally {
      if (before === undefined) delete process.env.CURSOR_API_KEY;
      else process.env.CURSOR_API_KEY = before;
    }
  });
});
