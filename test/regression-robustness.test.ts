/**
 * 回帰テスト ③例外処理・端末表示
 * 悪意のある、または壊れた設定ファイルでも、分析が止まらず、端末の表示を書き換えられないことを確認する。
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildProgram } from '../src/program.js';
import { sanitizeForTerminal } from '../src/report/terminal.js';
import { scan } from '../src/scan.js';
import { parseJsonc } from '../src/util/jsonc.js';
import { makeDir } from './helpers.js';

async function text(root: string, lang: 'ja' | 'en' = 'en'): Promise<string> {
  let out = '';
  await buildProgram({ write: (s) => void (out += s), isTTY: false }, lang).parseAsync(['node', 'a', 'scan', root, '--lang', lang]);
  return out;
}

describe('回帰: 端末表示の偽装を防ぐ', () => {
  it('ESC シーケンス・改行・復帰を無害な表記に置き換える', async () => {
    const evil = 'Bash(ls \u001b[2K\u001b[1A\r[INFO] all good\nfake line)';
    const root = await makeDir({
      '.claude/settings.json': JSON.stringify({ permissions: { allow: [evil] } }),
      '.mcp.json': JSON.stringify({ mcpServers: { ['srv\u001b]8;;http://x\u0007']: { command: 'node' } } }),
    });
    const out = await text(root);
    expect(out).not.toContain('\u001b');
    expect(out).not.toContain('\r');
    expect(out).not.toContain('\u0007');
    expect(out).toContain('\\x1b[2K');
    expect(out.split('\n').some((l) => l.startsWith('fake line'))).toBe(false);
  });

  it('双方向制御文字（Trojan Source）を表示しない', () => {
    expect(sanitizeForTerminal('Bash(rm ‮exe.txt)')).toBe('Bash(rm \\u{202e}exe.txt)');
    expect(sanitizeForTerminal('a​b⁦c')).toBe('a\\u{200b}b\\u{2066}c');
    expect(sanitizeForTerminal('日本語とEnglish')).toBe('日本語とEnglish');
  });

  it('JSON 出力では元の文字列をエスケープして保持する', async () => {
    const root = await makeDir({ '.claude/settings.json': JSON.stringify({ permissions: { allow: ['Bash(echo \u001b)'] } }) });
    let out = '';
    await buildProgram({ write: (s) => void (out += s), isTTY: false }, 'en').parseAsync(['node', 'a', 'scan', root, '--format', 'json']);
    expect(out).not.toContain('\u001b');
    expect(JSON.parse(out).rules[0].raw).toBe('Bash(echo \u001b)');
  });
});

describe('回帰: 壊れた・悪意のある入力', () => {
  it('"__proto__" キーで書かれていないキーを見せかけられない', async () => {
    const root = await makeDir({ '.claude/settings.json': '{"permissions": {"__proto__": {"allow": ["Bash"]}}}' });
    const r = await scan({ root, home: await makeDir() });
    expect(r.rules).toEqual([]);
    expect(r.findings.filter((f) => f.ruleId === 'R001')).toEqual([]);
    expect(r.unparsed.map((u) => u.pointer)).toContain('permissions.__proto__');
    expect(({} as Record<string, unknown>).allow).toBeUndefined(); // グローバルなプロトタイプも汚染されない
  });

  it('入れ子が極端に深いファイルは解析せず、他のファイルの分析は続ける', async () => {
    const root = await makeDir({
      '.claude/settings.json': '['.repeat(100000) + ']'.repeat(100000),
      '.mcp.json': JSON.stringify({ mcpServers: { ok: { command: 'node' } } }),
    });
    const r = await scan({ root, home: await makeDir() });
    expect(r.files[0]).toMatchObject({ status: 'parse-error' });
    expect(r.files[0]!.reason?.en).toMatch(/too deep/);
    expect(r.mcpServers.map((s) => s.name)).toEqual(['ok']);
  });

  it('上限以内の入れ子は解析できる', () => {
    const r = parseJsonc('{"a":' + '['.repeat(200) + ']'.repeat(200) + '}');
    expect(r.ok).toBe(true);
  });

  it.each([
    ['空ファイル', ''],
    ['null', 'null'],
    ['文字列', '"hello"'],
    ['数値', '42'],
    ['途中で切れたファイル', '{"permissions": {"allow": ["Bash"'],
    ['不正な UTF-8 を含む', '{"permissions": {"allow": ["�"]}}'],
  ])('%s でも例外にならない', async (_name, content) => {
    const root = await makeDir({ '.claude/settings.json': content, '.cursor/cli.json': content, '.mcp.json': content });
    await expect(scan({ root, home: await makeDir() })).resolves.toBeDefined();
    await expect(text(root)).resolves.toContain('AgentScope Security Report');
  });

  it('型の違う値が並んでも例外にならない', async () => {
    const weird = { permissions: { allow: [null, 1, {}, [], 'Bash'], deny: {}, ask: 'x', defaultMode: ['a'] }, sandbox: { network: [] }, hooks: 'x', env: [] };
    const root = await makeDir({
      '.claude/settings.json': JSON.stringify(weird),
      '.mcp.json': JSON.stringify({ mcpServers: { a: { command: 1, url: {}, env: 'x', headers: [] } } }),
      '.cursor/permissions.json': JSON.stringify({ mcpAllowlist: {}, terminalAllowlist: [1, null], autoRun: [] }),
      '.cursor/cli.json': JSON.stringify({ permissions: { allow: ['Shell(', 'Unknown(x)', 3], deny: 'Shell(*)' } }),
    });
    const r = await scan({ root, home: await makeDir() });
    expect(r.files.every((f) => f.status === 'parsed')).toBe(true);
    expect(r.unparsed.length).toBeGreaterThan(5);
  });

  it('対象がファイルならディレクトリではないと伝える', async () => {
    const root = await makeDir({ 'a.txt': 'x' });
    await expect(scan({ root: path.join(root, 'a.txt') })).rejects.toThrow(/Not a directory/);
  });

  it('読み取り権限のないファイルはスキップとして表示する', async () => {
    if (process.platform === 'win32' || process.getuid?.() === 0) return;
    const root = await makeDir({ '.claude/settings.json': '{}' });
    const p = path.join(root, '.claude/settings.json');
    await fs.chmod(p, 0o000);
    try {
      const r = await scan({ root, home: await makeDir() });
      expect(r.files[0]).toMatchObject({ status: 'skipped' });
      expect(r.files[0]!.reason?.en).toMatch(/EACCES/);
    } finally {
      await fs.chmod(p, 0o644);
    }
  });
});
