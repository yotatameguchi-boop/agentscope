/**
 * 回帰テスト: 残っていた制約への対応
 * 1. 形式に特徴のない秘密情報（保管庫による伏せ字、ランダム性による伏せ字）
 * 2. 管理設定の配布元（サーバー配信のキャッシュ、MDM の構成プロファイル、ファイル）と優先順位
 * 3. 壊れた・読めない管理設定（起動を拒否する／適用されない）
 */
import { promises as fs, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { scan } from '../src/scan.js';
import type { ScanResult } from '../src/types.js';
import { looksRandom, maskSecrets } from '../src/util/protect.js';
import { parsePlist } from '../src/util/plist.js';
import { FIXTURES, makeDir } from './helpers.js';

const json = (v: unknown) => JSON.stringify(v);
const PLAIN = 'Zq8wLmT4vXp2Rk9s';
const FAKE_GH = ['gh', 'p_', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'].join('');
const FAKE_GH_SPLIT = FAKE_GH.slice(0, 10) + '\u200b' + FAKE_GH.slice(10);

describe('1. 形式に特徴のない秘密情報', () => {
  it('秘密情報と判定した値は、出力の別の場所に現れても伏せる', async () => {
    const r = await scan({
      root: await makeDir({
        '.mcp.json': json({ mcpServers: { s: { command: 'node', env: { SERVICE_TOKEN: PLAIN } } } }),
        '.claude/settings.json': json({ permissions: { allow: [`Read(/data/${PLAIN}/**)`], additionalDirectories: [`/srv/${PLAIN}`] } }),
      }),
      home: await makeDir(),
      launch: [`claude --add-dir /tmp/${PLAIN}`],
    });
    expect(r.findings.some((f) => f.ruleId === 'R004')).toBe(true);
    expect(JSON.stringify(r)).not.toContain(PLAIN);
    expect(r.rules[0]!.raw).toBe('Read(/data/[REDACTED]/**)');
  });

  it('実行中の環境の資格情報（-e）と同じ値も伏せる', async () => {
    const r = await scan({ root: await makeDir({ '.claude/settings.json': json({ permissions: { allow: [`Bash(deploy ${PLAIN})`] } }) }), home: await makeDir(), env: { ANTHROPIC_API_KEY: PLAIN } });
    expect(JSON.stringify(r)).not.toContain(PLAIN);
  });

  it('保管庫はスキャンごとに独立している（並行実行しても混ざらない）', async () => {
    // ランダム性の判定では伏せられない値（小文字だけ）を使い、保管庫による伏せ字だけを確かめる
    const WORDS = 'correcthorsebatterystaple';
    const [a, b] = await Promise.all([
      scan({ root: await makeDir({ '.mcp.json': json({ mcpServers: { s: { command: 'node', env: { TOKEN: WORDS } } } }), '.claude/settings.json': json({ permissions: { additionalDirectories: [`/x/${WORDS}`] } }) }), home: await makeDir() }),
      scan({ root: await makeDir({ '.claude/settings.json': json({ permissions: { additionalDirectories: [`/x/${WORDS}`] } }) }), home: await makeDir() }),
    ]);
    expect(JSON.stringify(a)).not.toContain(WORDS);
    // b では WORDS を秘密情報と判定していないので、そのまま残る（a の保管庫が b に漏れていない）
    expect(JSON.stringify(b)).toContain(WORDS);
  });

  it('見えない文字を挟んだ値も伏せる（形式による判定・保管庫による判定の両方）', async () => {
    const r = await scan({
      root: await makeDir({
        '.mcp.json': json({ mcpServers: { s: { command: 'node', env: { SERVICE_TOKEN: 'correcthorsebatterystaple' } } } }),
        '.claude/settings.json': json({ permissions: { allow: [`Bash(echo ${FAKE_GH_SPLIT})`, 'Bash(echo correct\u200bhorsebatterystaple)'] } }),
      }),
      home: await makeDir(),
    });
    const dump = JSON.stringify(r).replace(/\\u200b|\u200b/g, '');
    expect(dump).not.toContain(FAKE_GH);
    expect(dump).not.toContain('correcthorsebatterystaple');
  });

  it('一時ディレクトリのパスを伏せない（CI の macOS で見つかった誤検知。乱数を変えて 2,000 回試す）', () => {
    const pick = (c: string, n: number, i: number) => Array.from({ length: n }, (_, k) => c[(i * 7919 + k * 104729) % c.length]).join('');
    const lower = 'abcdefghijklmnopqrstuvwxyz0123456789_';
    const alnum = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const bad: string[] = [];
    for (let i = 0; i < 2000; i++) {
      const p = `/private/var/folders/${pick(lower, 2, i)}/${pick(lower, 28, i + 1)}/T/agentscope-test-${pick(alnum, 6, i + 2)}/com.anthropic.claudecode.plist`;
      if (maskSecrets(p) !== p) bad.push(p);
    }
    expect(bad).toEqual([]);
  });

  it('ランダム性の高い長い文字列は伏せ、ハッシュ・UUID・人が付けた名前は残す', () => {
    const token = 'aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY';
    expect(looksRandom(token)).toBe(true);
    expect(maskSecrets(`Bash(curl -H x:${token})`)).toBe('Bash(curl -H x:[REDACTED])');
    for (const keep of [
      '3f786850e387550fdab836ed7e6dc881de23001b', // git のハッシュ（16進）
      '550e8400-e29b-41d4-a716-446655440000', // UUID
      'Miejscu-pracy-koparka-budowlanych-3741', // 単語をつないだファイル名
      'MyVeryLongServerName2024Production', // 単語をつないだ名前（エントロピーが低い）
      '/Users/someone/Projects/AgentScope2/src/index.ts',
    ]) {
      expect(maskSecrets(keep), keep).toBe(keep);
    }
  });
});

describe('2. 管理設定の配布元', () => {
  const plistBinary = readFileSync(path.join(FIXTURES, 'plist', 'managed.binary.plist'));

  async function run(opts: { remote?: unknown; mdm?: Buffer | string; files?: Record<string, string>; project?: Record<string, string>; platform?: NodeJS.Platform }): Promise<ScanResult> {
    const home = await makeDir(opts.remote === undefined ? {} : { '.claude/remote-settings.json': typeof opts.remote === 'string' ? opts.remote : json(opts.remote) });
    const mdmDir = await makeDir();
    const mdmPath = path.join(mdmDir, 'com.anthropic.claudecode.plist');
    if (opts.mdm !== undefined) await fs.writeFile(mdmPath, opts.mdm);
    return scan({
      root: await makeDir(opts.project ?? {}),
      home,
      managedDir: await makeDir(opts.files ?? {}),
      mdmPaths: [mdmPath],
      includeGlobal: true,
      platform: opts.platform,
    });
  }
  const sel = (r: ScanResult) => r.files.filter((f) => f.managedSource).map((f) => [f.managedSource, f.managedSelected]);

  it('plist はバイナリ形式・XML 形式とも plutil と同じ内容に読める', () => {
    const expected = JSON.parse(readFileSync(path.join(FIXTURES, 'plist', 'managed.json'), 'utf8'));
    for (const f of ['managed.binary.plist', 'managed.xml.plist']) {
      const r = parsePlist(readFileSync(path.join(FIXTURES, 'plist', f)));
      expect(r.ok).toBe(true);
      expect(JSON.parse(JSON.stringify(r.ok ? r.value : null))).toEqual(expected);
    }
  });

  it('MDM の構成プロファイルを読み、ファイルより優先する（first-wins）', async () => {
    const r = await run({ mdm: plistBinary, files: { 'managed-settings.json': json({ permissions: { allow: ['Bash'], defaultMode: 'bypassPermissions' } }) } });
    expect(sel(r)).toEqual([['mdm', true], ['file', false]]);
    // MDM の内容（deny、disableBypassPermissionsMode、env）が読める
    expect(r.rules.filter((x) => x.managedSource === 'mdm').map((x) => x.raw)).toEqual(['Bash(npm run test *)', 'Bash(curl *)', 'Read(./.env)']);
    // ファイルの値は使われない
    expect(r.rules.find((x) => x.raw === 'Bash')?.status).toBe('ignored');
    expect(r.findings.find((f) => f.ruleId === 'R001')).toMatchObject({ level: 'INFO', originalLevel: 'HIGH' });
    expect(r.findings.find((f) => f.ruleId === 'R007')?.file).toMatch(/com\.anthropic\.claudecode\.plist$/);
  });

  it('サーバー配信のキャッシュは MDM より優先する', async () => {
    const r = await run({ remote: { permissions: { deny: ['WebFetch'] } }, mdm: plistBinary });
    expect(sel(r)).toEqual([['remote', true], ['mdm', false]]);
    expect(r.rules.filter((x) => x.status === 'active').map((x) => x.raw)).toEqual(['WebFetch']);
  });

  it('制御用のキーしか持たない配布元は選ばれない', async () => {
    const r = await run({ remote: { managedSourcesBehavior: 'first-wins' }, files: { 'managed-settings.json': json({ permissions: { deny: ['Bash'] } }) } });
    expect(sel(r)).toEqual([['remote', false], ['file', true]]);
  });

  it('managedSourcesBehavior: "merge" ならすべての配布元を使い、上位の値が勝つ', async () => {
    const r = await run({
      remote: { managedSourcesBehavior: 'merge', permissions: { defaultMode: 'plan' } },
      files: { 'managed-settings.json': json({ permissions: { defaultMode: 'bypassPermissions', deny: ['Bash(rm *)'] } }) },
    });
    expect(sel(r)).toEqual([['remote', true], ['file', true]]);
    expect(r.rules.map((x) => [x.raw, x.status])).toEqual([['Bash(rm *)', 'active']]);
    expect(r.settings.filter((s) => s.key === 'permissions.defaultMode').map((s) => [s.value, s.status])).toEqual([
      ['plan', 'active'],
      ['bypassPermissions', 'overridden'],
    ]);
  });

  it('env は選ばれなかった配布元からも、上位が設定していない変数を補う', async () => {
    const r = await run({
      remote: { env: { NODE_OPTIONS: '--require ./a.js' } },
      files: { 'managed-settings.json': json({ env: { NODE_OPTIONS: '--max-old-space-size=1', NODE_TLS_REJECT_UNAUTHORIZED: '0' } }) },
    });
    const env = r.settings.filter((s) => s.key.startsWith('env.')).map((s) => [s.key, s.managedSource, s.status]);
    expect(env).toEqual([
      ['env.NODE_OPTIONS', 'remote', 'active'],
      ['env.NODE_OPTIONS', 'file', 'overridden'],
      ['env.NODE_TLS_REJECT_UNAUTHORIZED', 'file', 'active'],
    ]);
  });

  it('I004 で配布元と確認できない範囲を示す', async () => {
    const r = await run({ files: { 'managed-settings.json': json({ permissions: { deny: ['Bash'] } }) }, platform: 'win32' });
    const info = r.findings.find((f) => f.ruleId === 'I004')!;
    expect(info.reason.en).toMatch(/Sources found: managed-settings files\. Source in effect: managed-settings files\./);
    expect(info.reason.en).toMatch(/no local cache/);
    expect(info.reason.en).toMatch(/Windows registry/);
    const darwin = await run({ remote: { permissions: { deny: ['Bash'] } }, platform: 'darwin' });
    expect(darwin.findings.find((f) => f.ruleId === 'I004')!.reason.en).toMatch(/third-party provider/);
  });
});

describe('3. 壊れた・読めない管理設定', () => {
  async function managed(files: Record<string, string>, mdm?: string): Promise<ScanResult> {
    const mdmDir = await makeDir(mdm === undefined ? {} : { 'p.plist': mdm });
    return scan({ root: await makeDir(), home: await makeDir(), managedDir: await makeDir(files), mdmPaths: [path.join(mdmDir, 'p.plist')], includeGlobal: true });
  }
  const r008 = (r: ScanResult) => r.findings.filter((f) => f.ruleId === 'R008').map((f) => [f.file.split('/').pop(), f.level]);

  it.each([
    ['コメント', '// policy\n{"permissions":{"deny":["Bash"]}}'],
    ['末尾カンマ', '{"permissions":{"deny":["Bash"],}}'],
    ['構文エラー', '{"permissions":'],
    ['トップレベルが配列', '[]'],
  ])('%s を含む managed-settings.json は「起動を拒否する」と報告する', async (_name, content) => {
    expect(r008(await managed({ 'managed-settings.json': content }))).toEqual([['managed-settings.json', 'LOW']]);
  });

  it('分割ファイルの不備も報告する', async () => {
    expect(r008(await managed({ 'managed-settings.d/10.json': '{"a":1,}' }))).toEqual([['10.json', 'LOW']]);
  });

  it('空のファイルは {} として扱い、不備としない', async () => {
    expect(r008(await managed({ 'managed-settings.json': '' }))).toEqual([]);
  });

  it('壊れた構成プロファイル（plist）も報告する', async () => {
    expect(r008(await managed({}, '<plist><dict><key>a</key></plist>'))).toEqual([['p.plist', 'LOW']]);
    expect(r008(await managed({}, '<plist><array/></plist>'))).toEqual([['p.plist', 'LOW']]);
  });

  it.skipIf(process.platform === 'win32' || process.getuid?.() === 0)('権限で読めない管理設定は「適用されない」と報告する（MEDIUM）', async () => {
    const dir = await makeDir({ 'managed-settings.json': json({ permissions: { deny: ['Bash'] } }) });
    const p = path.join(dir, 'managed-settings.json');
    await fs.chmod(p, 0o000);
    try {
      const r = await scan({ root: await makeDir(), home: await makeDir(), managedDir: dir, mdmPaths: [], includeGlobal: true });
      expect(r.findings.find((f) => f.ruleId === 'R008')).toMatchObject({ level: 'MEDIUM' });
      expect(r.findings.find((f) => f.ruleId === 'R008')!.reason.en).toMatch(/starts without applying/);
    } finally {
      await fs.chmod(p, 0o644);
    }
  });

  it('サーバー配信のキャッシュが壊れていても起動拒否とは報告しない（キャッシュは次の取得で置き換わる）', async () => {
    const r = await scan({ root: await makeDir(), home: await makeDir({ '.claude/remote-settings.json': '{"x":' }), managedDir: await makeDir(), mdmPaths: [], includeGlobal: true });
    expect(r.findings.filter((f) => f.ruleId === 'R008')).toEqual([]);
  });
});
