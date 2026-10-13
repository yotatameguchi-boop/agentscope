import { execFileSync } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

// Windows ではシンボリックリンクの作成に管理者権限か開発者モードが必要なため省略する
const noSymlink = process.platform === 'win32';
import { parseJsonc } from '../src/util/jsonc.js';
import { safeReadFile } from '../src/util/safeRead.js';
import { classifySecret, redactIfSecret, scanForSecrets } from '../src/util/secrets.js';
import { FAKE, makeDir } from './helpers.js';

describe('parseJsonc', () => {
  it('コメントと末尾カンマを受け付ける', () => {
    const r = parseJsonc('{\n // c\n "a": [1, 2,],\n}');
    expect(r).toEqual({ ok: true, value: { a: [1, 2] } });
  });

  it('壊れた JSON は行番号付きのエラーにする（内容は含めない）', () => {
    const r = parseJsonc('{\n "secret": "abc"\n "b": 1 }');
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason.ja).toMatch(/3行目/);
      expect(r.reason.en).toMatch(/line 3/);
      expect(JSON.stringify(r.reason)).not.toContain('abc');
    }
  });
});

describe('safeReadFile', () => {
  it('存在しないファイルは missing を返す', async () => {
    const dir = await makeDir();
    expect(await safeReadFile(path.join(dir, 'nope.json'))).toEqual({ ok: false, missing: true });
  });

  it.skipIf(noSymlink)('対象ディレクトリ外を指すシンボリックリンクは読まない', async () => {
    const outside = await makeDir({ 'target.json': '{"a":1}' });
    const root = await makeDir();
    await fs.symlink(path.join(outside, 'target.json'), path.join(root, 'link.json'));
    const r = await safeReadFile(path.join(root, 'link.json'), { confineTo: root });
    expect(r.ok).toBe(false);
    if (!r.ok && !r.missing) {
      expect(r.reason.ja).toMatch(/外を指している/);
      expect(r.symlinkTarget).toBe(path.join(outside, 'target.json'));
    }
  });

  it.skipIf(noSymlink)('途中のディレクトリがリンクで外を指す場合も読まない', async () => {
    const outside = await makeDir({ 'settings.json': '{}' });
    const root = await makeDir();
    await fs.symlink(outside, path.join(root, '.claude'));
    const r = await safeReadFile(path.join(root, '.claude', 'settings.json'), { confineTo: root });
    expect(r.ok).toBe(false);
  });

  it.skipIf(noSymlink)('対象ディレクトリ内を指すシンボリックリンクは読む', async () => {
    const root = await makeDir({ 'real.json': '{"a":1}' });
    await fs.symlink(path.join(root, 'real.json'), path.join(root, 'link.json'));
    const r = await safeReadFile(path.join(root, 'link.json'), { confineTo: root });
    expect(r).toMatchObject({ ok: true, text: '{"a":1}' });
  });

  it.skipIf(noSymlink)('リンク切れは理由付きでスキップする', async () => {
    const root = await makeDir();
    await fs.symlink(path.join(root, 'missing.json'), path.join(root, 'broken.json'));
    const r = await safeReadFile(path.join(root, 'broken.json'), { confineTo: root });
    expect(r).toMatchObject({ ok: false, missing: false });
  });

  it.skipIf(process.platform === 'win32')('FIFO を開いてもブロックせずスキップする', async () => {
    const root = await makeDir();
    const fifo = path.join(root, 'settings.json');
    execFileSync('mkfifo', [fifo]);
    const r = await safeReadFile(fifo, { confineTo: root });
    expect(r).toMatchObject({ ok: false, missing: false });
  });

  it('BOM を取り除く', async () => {
    const root = await makeDir({ 'a.json': '﻿{}' });
    expect(await safeReadFile(path.join(root, 'a.json'))).toMatchObject({ ok: true, text: '{}' });
  });
});

describe('secrets', () => {
  it.each(Object.entries(FAKE))('既知形式の %s を検出する', (_name, value) => {
    expect(classifySecret(undefined, value)?.kind).toBe('value-pattern');
  });

  it('環境変数参照やプレースホルダーは検出しない', () => {
    for (const v of ['${GITHUB_TOKEN}', '$TOKEN', '${env:API_KEY}', 'Bearer ${TOKEN}', '<YOUR_API_KEY>', 'changeme', 'xxxxxxxxxx', 'short']) {
      expect(classifySecret('API_KEY', v), v).toBeUndefined();
    }
  });

  it('キー名から推定する（camelCase・引数形式も含む）', () => {
    expect(classifySecret('githubToken', 'abcdefghijklmnop')?.kind).toBe('key-name');
    expect(classifySecret('DB_PASSWORD', 'hunter2hunter2')?.kind).toBe('key-name');
    expect(classifySecret(undefined, '--api-key=abcdefghijkl')?.kind).toBe('key-name');
    expect(classifySecret('author', 'someone-name')).toBeUndefined();
    expect(classifySecret('FILES_ROOT', '/tmp/somewhere')).toBeUndefined();
  });

  it('URL に埋め込まれた認証情報を検出する', () => {
    expect(classifySecret(undefined, 'https://user:p4ssw0rd@example.com/')?.kind).toBe('url-credential');
    expect(classifySecret(undefined, 'https://example.com/mcp?api_key=abcdef123456')?.kind).toBe('url-credential');
    expect(classifySecret(undefined, 'https://example.com/mcp?page=2')).toBeUndefined();
  });

  it('検出結果に値を含めない', () => {
    const hits = scanForSecrets({ env: { GH: FAKE.github }, args: ['--token', FAKE.slack] }, 'claude-code', 'x.json');
    expect(hits.map((h) => h.pointer)).toEqual(['env.GH', 'args[1]']);
    expect(JSON.stringify(hits)).not.toContain(FAKE.github);
    expect(JSON.stringify(hits)).not.toContain(FAKE.slack);
  });

  it('redactIfSecret は秘密情報を含む文字列全体を伏せる', () => {
    expect(redactIfSecret(`Bash(curl -H "Authorization: Bearer ${'a'.repeat(30)}")`)).toBe('[REDACTED]');
    expect(redactIfSecret('Bash(npm test)')).toBe('Bash(npm test)');
  });
});
