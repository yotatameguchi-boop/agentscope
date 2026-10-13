import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { detectLang, isText, localize, tx } from '../src/i18n.js';
import { buildProgram, pickLang } from '../src/program.js';
import { SECURITY_RULES } from '../src/rules/index.js';
import { scan } from '../src/scan.js';
import { FIXTURES, makeDir } from './helpers.js';

const JAPANESE = /[぀-ヿ一-鿿！-｠]/;

async function runCli(args: string[], lang: 'ja' | 'en' = 'ja'): Promise<string> {
  let out = '';
  await buildProgram({ write: (s) => void (out += s), isTTY: false }, lang).parseAsync(['node', 'agentscope', ...args]);
  return out;
}

/** 結果の中の Text をすべて集める */
function collectTexts(v: unknown, out: Array<{ ja: string; en: string }> = []) {
  if (isText(v)) out.push(v);
  else if (Array.isArray(v)) v.forEach((x) => collectTexts(x, out));
  else if (typeof v === 'object' && v !== null) Object.values(v).forEach((x) => collectTexts(x, out));
  return out;
}

describe('言語の判定', () => {
  it.each([
    [{ AGENTSCOPE_LANG: 'en', LANG: 'ja_JP.UTF-8' }, 'en'],
    [{ AGENTSCOPE_LANG: 'ja', LANG: 'en_US.UTF-8' }, 'ja'],
    [{ LANG: 'ja_JP.UTF-8' }, 'ja'],
    [{ LC_ALL: 'en_US.UTF-8', LANG: 'ja_JP.UTF-8' }, 'en'],
    [{ LANG: 'de_DE.UTF-8' }, 'en'],
    [{ LANG: 'C.UTF-8' }, 'en'],
  ])('%j → %s', (env, expected) => {
    expect(detectLang(env)).toBe(expected);
  });

  it('--lang は環境変数より優先する', () => {
    expect(pickLang(['scan', '--lang', 'en'], { LANG: 'ja_JP.UTF-8' })).toBe('en');
    expect(pickLang(['--lang=ja', 'scan'], { LANG: 'en_US.UTF-8' })).toBe('ja');
    expect(pickLang(['scan'], { LANG: 'ja_JP.UTF-8' })).toBe('ja');
  });

  it('localize は Text だけを置き換える', () => {
    expect(localize({ a: tx('あ', 'a'), b: ['x', tx('い', 'i')], n: 1 }, 'en')).toEqual({ a: 'a', b: ['x', 'i'], n: 1 });
  });
});

describe('英語出力', () => {
  const risky = path.join(FIXTURES, 'risky-project');

  it('テキストレポートに日本語が混ざらない', async () => {
    const out = await runCli(['scan', risky, '--lang', 'en'], 'en');
    expect(out).toContain('Security findings');
    expect(out).toContain('Recommendations');
    expect(out).toMatch(/\[HIGH\] R001 Broad command execution is auto-approved/);
    const bad = out.split('\n').filter((l) => JAPANESE.test(l));
    expect(bad).toEqual([]);
  });

  it('ルート側の --lang でも切り替わる', async () => {
    const out = await runCli(['--lang', 'en', 'scan', risky], 'ja');
    expect(out).toContain('Security findings');
  });

  it('JSON 出力に lang が入り、日本語が混ざらない', async () => {
    const json = JSON.parse(await runCli(['scan', risky, '--format', 'json', '--lang', 'en'], 'en'));
    expect(json.lang).toBe('en');
    expect(JSON.stringify(json)).not.toMatch(JAPANESE);
  });

  it('日本語指定では日本語で出る', async () => {
    const json = JSON.parse(await runCli(['scan', risky, '--format', 'json', '--lang', 'ja'], 'en'));
    expect(json.lang).toBe('ja');
    expect(json.findings[0].title).toMatch(JAPANESE);
  });

  it('ヘルプも英語になる', async () => {
    let help = '';
    const program = buildProgram({ write: () => {}, isTTY: false }, 'en');
    program.exitOverride().configureOutput({ writeOut: (s) => void (help += s) });
    const scanCmd = program.commands.find((c) => c.name() === 'scan')!;
    scanCmd.exitOverride().configureOutput({ writeOut: (s) => void (help += s) });
    await expect(program.parseAsync(['node', 'agentscope', 'scan', '--help'])).rejects.toThrow();
    expect(help).toContain('also analyze user-level settings');
    expect(help).not.toMatch(JAPANESE);
  });
});

describe('翻訳の網羅性', () => {
  it('すべてのルールのタイトルと説明に日英がある', () => {
    for (const r of SECURITY_RULES) {
      for (const t of [r.title, r.description]) {
        expect(t.ja, r.id).toMatch(JAPANESE);
        expect(t.en, r.id).not.toBe('');
        expect(t.en, r.id).not.toMatch(JAPANESE);
      }
    }
  });

  it('スキャン結果の文言はすべて英語訳を持つ', async () => {
    const results = await Promise.all(
      ['risky-project', 'clean-project', 'broken-project'].map(async (d) => scan({ root: path.join(FIXTURES, d), home: await makeDir() })),
    );
    const texts = results.flatMap((r) => collectTexts(r));
    expect(texts.length).toBeGreaterThan(50);
    for (const t of texts) {
      if (t.ja === '') continue; // 空の付記（tx('', '')）
      expect(t.en, t.ja).not.toBe('');
      expect(t.en, t.ja).not.toMatch(JAPANESE);
    }
  });
});
