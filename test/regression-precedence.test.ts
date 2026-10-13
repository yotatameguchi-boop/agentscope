/**
 * 回帰テスト ②設定の優先順位とルールの有効性
 * 「書かれているが効かない」設定を危険と断定せず、逆に「効いている」設定を見落とさないことを確認する。
 */
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { scan } from '../src/scan.js';
import type { Finding, ScanResult } from '../src/types.js';
import { makeDir } from './helpers.js';

const json = (v: unknown) => JSON.stringify(v);

async function run(files: Record<string, string>, opts: { managed?: Record<string, string>; global?: boolean } = {}): Promise<ScanResult> {
  const root = await makeDir(files);
  const home = await makeDir(Object.fromEntries(Object.entries(files).filter(([k]) => k.startsWith('~/')).map(([k, v]) => [k.slice(2), v])));
  const managedDir = await makeDir(opts.managed ?? {});
  return scan({ root, home, managedDir, includeGlobal: opts.global ?? false });
}

const find = (r: ScanResult, id: string, evidence?: string): Finding | undefined =>
  r.findings.find((f) => f.ruleId === id && (evidence === undefined || f.evidence === evidence));

describe('回帰: deny / ask による打ち消し', () => {
  it('別ファイルの deny Bash は allow Bash を打ち消し、検出は INFO（本来 HIGH）になる', async () => {
    const r = await run({
      '.claude/settings.json': json({ permissions: { allow: ['Bash'] } }),
      '.claude/settings.local.json': json({ permissions: { deny: ['Bash'] } }),
    });
    const f = find(r, 'R001', 'Bash')!;
    expect(f).toMatchObject({ level: 'INFO', originalLevel: 'HIGH' });
    expect(f.effectNote?.en).toMatch(/deny rule "Bash"/);
    expect(r.rules.find((x) => x.raw === 'Bash' && x.effect === 'allow')?.status).toBe('overridden');
  });

  it('ask は allow を打ち消す（毎回承認が必要）', async () => {
    const r = await run({ '.claude/settings.json': json({ permissions: { allow: ['Bash(python3 *)'], ask: ['Bash(python3:*)'] } }) });
    expect(find(r, 'R001')).toMatchObject({ level: 'INFO', originalLevel: 'HIGH' });
  });

  it('deny "mcp__github" はサーバーの全ツールの allow を打ち消す', async () => {
    const r = await run({ '.claude/settings.json': json({ permissions: { allow: ['mcp__github__*'], deny: ['mcp__github'] } }) });
    expect(find(r, 'R002')).toMatchObject({ level: 'INFO', originalLevel: 'MEDIUM' });
  });

  it('一部だけ重なる deny では打ち消したと判定しない（安全側に倒さない）', async () => {
    const r = await run({ '.claude/settings.json': json({ permissions: { allow: ['Bash'], deny: ['Bash(rm *)'] } }) });
    expect(find(r, 'R001', 'Bash')).toMatchObject({ level: 'HIGH' });
    expect(find(r, 'R001', 'Bash')?.originalLevel).toBeUndefined();
  });

  it('Cursor CLI でも deny が allow より優先される', async () => {
    const r = await run({ '.cursor/cli.json': json({ permissions: { allow: ['Shell(bash)'], deny: ['Shell(bash)'] } }) });
    expect(find(r, 'R001')).toMatchObject({ level: 'INFO', originalLevel: 'HIGH' });
  });
});

describe('回帰: Claude Code が読み込まないルール', () => {
  it.each([
    ['mcp__github(create_issue)', 'R002'],
    ['Write(**)', 'R005'],
    ['Bash(command:python3 *)', 'R001'],
  ])('%s は無効として扱い、危険と断定しない', async (raw, id) => {
    const r = await run({ '.claude/settings.json': json({ permissions: { allow: [raw] } }) });
    const rule = r.rules.find((x) => x.raw === raw)!;
    expect(rule.status).toBe('ignored');
    for (const f of r.findings.filter((x) => x.ruleId === id)) expect(f.level).toBe('INFO');
  });

  it('ツール名のワイルドカードを含む allow（"B*"）は無効', async () => {
    const r = await run({ '.claude/settings.json': json({ permissions: { allow: ['B*'] } }) });
    expect(r.rules[0]!.status).toBe('ignored');
  });

  it('管理設定の allowManagedPermissionRulesOnly は、それ以外の権限ルールを無効にする', async () => {
    const r = await run(
      { '.claude/settings.json': json({ permissions: { allow: ['Bash'] } }) },
      { managed: { 'managed-settings.json': json({ allowManagedPermissionRulesOnly: true }) }, global: true },
    );
    expect(r.rules.find((x) => x.raw === 'Bash')?.status).toBe('ignored');
    expect(find(r, 'R001')).toMatchObject({ level: 'INFO', originalLevel: 'HIGH' });
  });
});

describe('回帰: 単一値の設定の優先順位（managed > local > project > user）', () => {
  it('local の enableAllProjectMcpServers: false が project の true を上書きする', async () => {
    const r = await run({
      '.claude/settings.json': json({ enableAllProjectMcpServers: true }),
      '.claude/settings.local.json': json({ enableAllProjectMcpServers: false }),
      '.mcp.json': json({ mcpServers: { s: { command: 'node' } } }),
    });
    expect(find(r, 'R002')).toMatchObject({ level: 'INFO', originalLevel: 'MEDIUM' });
    // サーバーの承認状態も、上書き後の値で判定する
    expect(r.mcpServers[0]!.approval).toBe('unknown');
  });

  it('project の defaultMode: default がユーザー設定の bypassPermissions を上書きする', async () => {
    const r = await run(
      {
        '.claude/settings.json': json({ permissions: { defaultMode: 'default' } }),
        '~/.claude/settings.json': json({ permissions: { defaultMode: 'bypassPermissions' } }),
      },
      { global: true },
    );
    expect(find(r, 'R003')).toMatchObject({ level: 'INFO', originalLevel: 'HIGH', file: '~/.claude/settings.json' });
  });

  it('project の bypassPermissions はユーザー設定を上書きできない（設定できない値）', async () => {
    const r = await run(
      {
        '.claude/settings.json': json({ permissions: { defaultMode: 'bypassPermissions' } }),
        '~/.claude/settings.json': json({ permissions: { defaultMode: 'acceptEdits' } }),
      },
      { global: true },
    );
    const user = r.findings.find((f) => f.ruleId === 'R003' && f.file === '~/.claude/settings.json');
    expect(user).toMatchObject({ level: 'LOW' }); // acceptEdits はそのまま効く
  });

  it('管理設定の値は最優先で、managed-settings.d も読む', async () => {
    const r = await run(
      { '~/.claude/settings.json': json({ permissions: { defaultMode: 'bypassPermissions' } }) },
      { managed: { 'managed-settings.d/10-mode.json': json({ permissions: { defaultMode: 'plan' } }) }, global: true },
    );
    expect(r.files.map((f) => f.scope)).toContain('managed');
    expect(find(r, 'R003')).toMatchObject({ level: 'INFO', originalLevel: 'HIGH' });
  });

  it('disableBypassPermissionsMode: "disable" があれば bypassPermissions は使えない', async () => {
    const r = await run(
      { '~/.claude/settings.json': json({ permissions: { defaultMode: 'bypassPermissions', disableBypassPermissionsMode: 'disable' } }) },
      { global: true },
    );
    expect(find(r, 'R003')).toMatchObject({ level: 'INFO', originalLevel: 'HIGH' });
  });

  it('置けない場所の skipDangerousModePermissionPrompt（project）は無効', async () => {
    const r = await run({ '.claude/settings.json': json({ skipDangerousModePermissionPrompt: true }) });
    expect(r.settings[0]!.status).toBe('ignored');
    expect(find(r, 'R003')).toMatchObject({ level: 'INFO', originalLevel: 'MEDIUM' });
  });
});

describe('回帰: 表示', () => {
  it('無効・打ち消しのルールに目印を付けて表示する', async () => {
    const { buildProgram } = await import('../src/program.js');
    const root = await makeDir({ '.claude/settings.json': json({ permissions: { allow: ['Bash', 'mcp__x(y)'], deny: ['Bash'] } }) });
    let out = '';
    await buildProgram({ write: (s) => void (out += s), isTTY: false }, 'en').parseAsync(['node', 'a', 'scan', root, '--lang', 'en']);
    expect(out).toMatch(/allow\s+Bash \[neutralized\]/);
    expect(out).toMatch(/mcp__x\(y\) \[not applied\]/);
    expect(out).toMatch(/\[INFO\] \(originally HIGH\) R001/);
    expect(path.isAbsolute(root)).toBe(true);
  });
});
