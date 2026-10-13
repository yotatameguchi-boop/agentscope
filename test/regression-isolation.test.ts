/**
 * 回帰テスト: パーサーが想定外の例外を投げても、その項目だけを未解析にして分析を続ける。
 * 例外のメッセージ（設定値を含みうる）は出力しない。
 */
import { describe, expect, it, vi } from 'vitest';
import { makeDir } from './helpers.js';

const SECRET_IN_MESSAGE = 'Zq8wLmT4vXp2Rk9s-in-exception-message';

vi.mock('../src/parsers/claude.js', async (importOriginal) => {
  const mod = await importOriginal<typeof import('../src/parsers/claude.js')>();
  return {
    ...mod,
    parseClaudeMcpJson: () => {
      throw new Error(SECRET_IN_MESSAGE);
    },
  };
});

describe('回帰: 例外の閉じ込め', () => {
  it('通常ファイル・--mcp-config のどちらで例外が起きても、他の分析を続け、例外の内容を出さない', async () => {
    const { scan } = await import('../src/scan.js');
    const r = await scan({
      root: await makeDir({ '.mcp.json': '{"mcpServers":{}}', '.claude/settings.json': JSON.stringify({ permissions: { allow: ['Bash'] } }) }),
      home: await makeDir(),
      managedDir: await makeDir(),
      launch: [`claude --mcp-config '{"mcpServers":{}}' --dangerously-skip-permissions`, 'agent --force'],
    });
    expect(r.files.find((f) => f.displayPath === '.mcp.json')?.status).toBe('parse-error');
    expect(r.unparsed.find((u) => u.file === '--launch')?.reason.en).toMatch(/unexpected error/);
    expect(r.findings.map((f) => f.ruleId)).toEqual(expect.arrayContaining(['R001', 'R003']));
    expect(r.launches).toHaveLength(2);
    expect(JSON.stringify(r)).not.toContain(SECRET_IN_MESSAGE);
  });
});
