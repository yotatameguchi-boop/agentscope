/**
 * 回帰テスト ①秘密情報の出力防止
 * 値が「名前」や「別の配列要素」「文字列の途中」にある場合も、どの出力にも値が出ないことを確認する。
 */
import { describe, expect, it } from 'vitest';
import { buildProgram } from '../src/program.js';
import { classifySecret, redactIfSecret, scanForSecrets } from '../src/util/secrets.js';
import { FAKE, makeDir } from './helpers.js';

const PLAIN = 'Zq8wLmT4vXp2Rk9s'; // 既知形式に当てはまらない、それらしい値

async function outputs(root: string): Promise<string[]> {
  const res: string[] = [];
  for (const lang of ['ja', 'en'] as const) {
    for (const format of ['text', 'json']) {
      let out = '';
      await buildProgram({ write: (s) => void (out += s), isTTY: false }, lang).parseAsync([
        'node', 'agentscope', 'scan', root, '--format', format, '--lang', lang,
      ]);
      res.push(out);
    }
  }
  return res;
}

describe('回帰: 秘密情報が出力に漏れない', () => {
  it('キー名・サーバー名・環境変数名・ヘッダー名に入った秘密を伏せる', async () => {
    const root = await makeDir({
      '.claude/settings.json': JSON.stringify({ [FAKE.github]: true, permissions: { allow: [`mcp__${FAKE.slack}`] } }),
      '.mcp.json': JSON.stringify({
        mcpServers: {
          [FAKE.anthropic]: { command: 'node', env: { [FAKE.aws]: 'x' }, headers: { [`x-api-key: ${PLAIN}`]: '' } },
        },
      }),
    });
    for (const out of await outputs(root)) {
      for (const v of [...Object.values(FAKE), PLAIN]) expect(out).not.toContain(v);
      expect(out).toContain('[REDACTED]');
    }
  });

  it('args のフラグの次の要素に置かれた値を検出し、出力しない', async () => {
    const root = await makeDir({
      '.mcp.json': JSON.stringify({ mcpServers: { s: { command: 'npx', args: ['-y', 'srv', '--api-key', PLAIN, '--password', PLAIN + '2'] } } }),
    });
    const hits = scanForSecrets({ args: ['--api-key', PLAIN, '--name', 'not-a-secret-value', '--token', '${TOKEN}'] }, 'claude-code', 'x');
    expect(hits.map((h) => h.pointer)).toEqual(['args[1]']);
    for (const out of await outputs(root)) {
      expect(out).not.toContain(PLAIN);
      expect(out).toMatch(/R004/);
    }
  });

  it('ルールや設定値の文字列の途中に埋め込まれた資格情報を伏せる', async () => {
    const rules = [
      `Bash(API_KEY=${PLAIN} npm run deploy)`,
      `Bash(curl -u admin:${PLAIN} https://example.com)`,
      `Bash(curl -H "x-api-key: ${PLAIN}" https://example.com)`,
      `Bash(mysql --password ${PLAIN})`,
      `Bash(curl -H "Authorization: Basic ${Buffer.from('admin:' + PLAIN).toString('base64')}")`,
      `WebFetch(domain:example.com?token=${PLAIN})`,
    ];
    for (const r of rules) expect(redactIfSecret(r), r).toBe('[REDACTED]');
    const root = await makeDir({
      '.claude/settings.json': JSON.stringify({ permissions: { allow: rules }, sandbox: { excludedCommands: [`deploy --token ${PLAIN}`] } }),
      '.cursor/permissions.json': JSON.stringify({ terminalAllowlist: [`export SECRET_TOKEN=${PLAIN}`], autoRun: { allow_instructions: [`password: ${PLAIN}`] } }),
    });
    for (const out of await outputs(root)) {
      expect(out).not.toContain(PLAIN);
      expect(out).not.toContain(Buffer.from('admin:' + PLAIN).toString('base64'));
    }
  });

  it('参照や普通の文字列は秘密として扱わない（誤検知の回帰）', () => {
    for (const v of [
      'Bash(npm run test *)',
      'Bash(git push origin main)',
      'Authorization: Bearer ${TOKEN}',
      'API_KEY=${API_KEY}',
      'Never print the password: ok',
      'Bash(curl -u $USER:$PASS https://example.com)',
    ]) {
      expect(classifySecret(undefined, v), v).toBeUndefined();
    }
  });
});
