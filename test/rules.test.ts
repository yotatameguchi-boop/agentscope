import { describe, expect, it } from 'vitest';
import { parseClaudeSettings } from '../src/parsers/claude.js';
import type { ParseContext } from '../src/parsers/common.js';
import { parseCursorPermissions } from '../src/parsers/cursor.js';
import { runRules, SECURITY_RULES } from '../src/rules/index.js';
import type { RuleContext } from '../src/rules/types.js';
import type { ConfigScope, Finding } from '../src/types.js';

function claude(json: unknown, scope: ConfigScope = 'project'): Finding[] {
  const ctx: ParseContext = { agent: 'claude-code', scope, file: '.claude/settings.json', root: '/repo' };
  const p = parseClaudeSettings(ctx, json);
  return runRules(ruleCtx(p));
}

function cursor(json: unknown): Finding[] {
  const ctx: ParseContext = { agent: 'cursor', scope: 'project', file: '.cursor/permissions.json', root: '/repo' };
  return runRules(ruleCtx(parseCursorPermissions(ctx, json)));
}

function ruleCtx(p: { rules: RuleContext['rules']; settings: RuleContext['settings']; mcpServers: RuleContext['mcpServers']; secretHits: RuleContext['secretHits'] }): RuleContext {
  return { agents: ['claude-code', 'cursor'], files: [], rules: p.rules, settings: p.settings, mcpServers: p.mcpServers, secretHits: p.secretHits };
}

const levels = (fs: Finding[], id: string) => fs.filter((f) => f.ruleId === id).map((f) => f.level);
const allow = (...rules: string[]) => ({ permissions: { allow: rules } });

describe('ルール定義', () => {
  it('R001〜R005 が登録されている', () => {
    expect(SECURITY_RULES.map((r) => r.id)).toEqual(expect.arrayContaining(['R001', 'R002', 'R003', 'R004', 'R005']));
  });
});

describe('R001 広範囲のコマンド実行', () => {
  it.each([
    ['Bash', 'HIGH'],
    ['Bash(*)', 'HIGH'],
    ['Bash(* --version)', 'HIGH'],
    ['PowerShell', 'HIGH'],
    ['Bash(python3 *)', 'HIGH'],
    ['Bash(npx:*)', 'HIGH'],
    ['Bash(sudo *)', 'HIGH'],
    ['Bash(git *)', 'MEDIUM'],
    ['Bash(curl*)', 'MEDIUM'],
  ])('%s → %s', (rule, level) => {
    expect(levels(claude(allow(rule)), 'R001')).toEqual([level]);
  });

  it.each(['Bash(npm run test *)', 'Bash(git status)', 'Bash(ls *)', 'Bash(python3 -V)'])('具体的なルール %s は検出しない', (rule) => {
    expect(levels(claude(allow(rule)), 'R001')).toEqual([]);
  });

  it('ask / deny のルールは対象外', () => {
    expect(levels(claude({ permissions: { ask: ['Bash'], deny: ['Bash(*)'] } }), 'R001')).toEqual([]);
  });

  it('Cursor の terminalAllowlist（前方一致）を評価する', () => {
    const f = cursor({ terminalAllowlist: ['*', 'bash', 'node:*', 'git', 'npm:install*', 'git status', 'ls'] });
    expect(f.filter((x) => x.ruleId === 'R001').map((x) => [x.evidence, x.level])).toEqual([
      ['*', 'HIGH'],
      ['bash', 'HIGH'],
      ['node:*', 'HIGH'],
      ['git', 'MEDIUM'],
    ]);
  });
});

describe('R002 MCP ツールの自動承認', () => {
  it('Claude Code: サーバー単位の許可は MEDIUM、ワイルドカードの allow は無視される旨を INFO', () => {
    const f = claude(allow('mcp__github', 'mcp__github__*', 'mcp__github__get_issue', 'mcp__*'));
    expect(f.filter((x) => x.ruleId === 'R002').map((x) => [x.evidence, x.level])).toEqual([
      ['mcp__github', 'MEDIUM'],
      ['mcp__github__*', 'MEDIUM'],
      ['mcp__*', 'INFO'],
    ]);
  });

  it('Claude Code: enableAllProjectMcpServers を検出する', () => {
    expect(levels(claude({ enableAllProjectMcpServers: true }), 'R002')).toEqual(['MEDIUM']);
    expect(levels(claude({ enableAllProjectMcpServers: false }), 'R002')).toEqual([]);
  });

  it('Cursor: *:* は HIGH、server:* と *:tool は MEDIUM、個別指定は対象外', () => {
    const f = cursor({ mcpAllowlist: ['*:*', 'gh:*', '*:search', 'gh:list_issues'] });
    expect(f.filter((x) => x.ruleId === 'R002').map((x) => [x.evidence, x.level])).toEqual([
      ['*:*', 'HIGH'],
      ['gh:*', 'MEDIUM'],
      ['*:search', 'MEDIUM'],
    ]);
  });
});

describe('R003 権限チェックの緩和', () => {
  it('bypassPermissions はユーザー設定で HIGH、プロジェクト設定で MEDIUM（バージョン注記付き）', () => {
    const mode = { permissions: { defaultMode: 'bypassPermissions' } };
    expect(levels(claude(mode, 'user'), 'R003')).toEqual(['HIGH']);
    const proj = claude(mode, 'project').filter((x) => x.ruleId === 'R003');
    expect(proj.map((x) => x.level)).toEqual(['MEDIUM']);
    expect(proj[0]!.reason.ja).toMatch(/v2\.1\.257/);
    expect(proj[0]!.reason.en).toMatch(/v2\.1\.257/);
  });

  it.each([
    [{ permissions: { defaultMode: 'auto' } }, ['LOW']],
    [{ permissions: { defaultMode: 'acceptEdits' } }, ['LOW']],
    [{ permissions: { defaultMode: 'default' } }, []],
    [{ permissions: { defaultMode: 'plan' } }, []],
    [{ skipDangerousModePermissionPrompt: true }, ['MEDIUM']],
    [{ sandbox: { filesystem: { disabled: true } } }, ['LOW']],
  ])('%j', (json, expected) => {
    expect(levels(claude(json, 'user'), 'R003')).toEqual(expected);
  });
});

describe('R004 認証情報の直書き', () => {
  it('値は表示せず、場所だけを示す', () => {
    const secret = 'super-secret-value-123';
    const f = claude({ env: { MY_API_KEY: secret } }).filter((x) => x.ruleId === 'R004');
    expect(f.map((x) => [x.level, x.pointer])).toEqual([['MEDIUM', 'env.MY_API_KEY']]);
    expect(JSON.stringify(f)).not.toContain(secret);
  });
});

describe('R005 広範囲のファイル操作', () => {
  it.each([
    ['Edit', 'HIGH'],
    ['Write', 'HIGH'],
    ['Edit(//**)', 'HIGH'],
    ['Edit(~/**)', 'HIGH'],
    ['Read', 'MEDIUM'],
    ['Read(//**)', 'MEDIUM'],
    ['Read(~/.ssh/**)', 'MEDIUM'],
    ['Edit(.claude/**)', 'MEDIUM'],
    ['Edit(~/.zshrc)', 'MEDIUM'],
    ['Edit(**)', 'LOW'],
    ['Edit(*)', 'LOW'],
    ['Edit(/**)', 'LOW'],
  ])('%s → %s', (rule, level) => {
    expect(levels(claude(allow(rule)), 'R005')).toEqual([level]);
  });

  it.each(['Edit(/src/**)', 'Read(src/**)', 'Edit(docs/*.md)'])('限定されたルール %s は検出しない', (rule) => {
    expect(levels(claude(allow(rule)), 'R005')).toEqual([]);
  });

  it('additionalDirectories のルート・ホーム指定を検出する', () => {
    const f = claude({ permissions: { additionalDirectories: ['/', '~', '../lib', 'C:\\'] } });
    expect(f.filter((x) => x.ruleId === 'R005').map((x) => x.evidence)).toEqual(['/', '~', 'C:\\']);
  });
});

describe('検出結果の形式', () => {
  it('すべての検出に必須項目がそろっている', () => {
    const f = claude({ permissions: { allow: ['Bash', 'Edit', 'mcp__x'], defaultMode: 'bypassPermissions' }, env: { TOKEN_X: 'abcdefghijkl' } });
    expect(f.length).toBeGreaterThan(0);
    for (const x of f) {
      expect(x.ruleId).toMatch(/^[RI]\d{3}$/);
      expect(['HIGH', 'MEDIUM', 'LOW', 'INFO']).toContain(x.level);
      expect(x.reason).not.toBe('');
      expect(x.file).toBe('.claude/settings.json');
      expect(x.pointer).not.toBe('');
      expect(x.recommendation).not.toBe('');
    }
    // 重要度順に並ぶ
    const order = f.map((x) => ['HIGH', 'MEDIUM', 'LOW', 'INFO'].indexOf(x.level));
    expect(order).toEqual([...order].sort((a, b) => a - b));
  });
});
