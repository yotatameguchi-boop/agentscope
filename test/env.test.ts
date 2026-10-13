/**
 * 環境変数の分析
 */
import { describe, expect, it } from 'vitest';
import { buildProgram } from '../src/program.js';
import { scan } from '../src/scan.js';
import type { ScanResult } from '../src/types.js';
import { FAKE, makeDir } from './helpers.js';

const json = (v: unknown) => JSON.stringify(v);
const PLAIN = 'Zq8wLmT4vXp2Rk9s';

async function run(files: Record<string, string>, opts: { env?: NodeJS.ProcessEnv; home?: Record<string, string>; global?: boolean; launch?: string[] } = {}): Promise<ScanResult> {
  return scan({
    root: await makeDir(files),
    home: await makeDir(opts.home ?? {}),
    managedDir: await makeDir(),
    env: opts.env ?? false,
    includeGlobal: opts.global ?? false,
    launch: opts.launch,
  });
}

const r007 = (r: ScanResult) => r.findings.filter((f) => f.ruleId === 'R007').map((f) => [f.evidence, f.level, f.originalLevel]);

describe('設定ファイルの env ブロック', () => {
  it('危険な変数を R007 で検出する', async () => {
    const r = await run({ '.claude/settings.json': json({ env: { NODE_TLS_REJECT_UNAUTHORIZED: '0', NODE_OPTIONS: '--max-old-space-size=4096' } }) });
    expect(r007(r)).toEqual([['NODE_TLS_REJECT_UNAUTHORIZED=0', 'HIGH', undefined]]);
  });

  it('設定ファイルの env では無視される安全チェック無効化は、効かないと判定する', async () => {
    const r = await run({ '~x': '', '.claude/settings.json': json({ env: { CLAUDE_CODE_DISABLE_INLINE_SHELL_RM_PROMPT: '1' } }) });
    expect(r.settings.find((s) => s.key === 'env.CLAUDE_CODE_DISABLE_INLINE_SHELL_RM_PROMPT')?.status).toBe('ignored');
    expect(r007(r)).toEqual([['CLAUDE_CODE_DISABLE_INLINE_SHELL_RM_PROMPT=1', 'INFO', 'MEDIUM']]);
  });

  it('project 設定では無視される変数を判定する', async () => {
    const r = await run({ '.claude/settings.json': json({ env: { CLAUDE_CONFIG_DIR: '/tmp/x', DISABLE_TELEMETRY: '1' } }) });
    expect(r.settings.filter((s) => s.key.startsWith('env.')).map((s) => s.status)).toEqual(['ignored', 'ignored']);
  });

  it('API の接続先: 共有設定での変更は MEDIUM、http は MEDIUM、公式ホストは報告しない', async () => {
    const r = await run({
      '.claude/settings.json': json({ env: { ANTHROPIC_BASE_URL: 'https://proxy.example.com/v1?key=x' } }),
      '.claude/settings.local.json': json({ env: { ANTHROPIC_BEDROCK_BASE_URL: 'http://10.0.0.5' } }),
    });
    expect(r007(r)).toEqual([
      ['ANTHROPIC_BASE_URL=https://proxy.example.com', 'MEDIUM', undefined],
      ['ANTHROPIC_BEDROCK_BASE_URL=http://10.0.0.5', 'MEDIUM', undefined],
    ]);
    const official = await run({ '.claude/settings.json': json({ env: { ANTHROPIC_BASE_URL: 'https://api.anthropic.com' } }) });
    expect(r007(official)).toEqual([]);
  });

  it('env ブロックはキーごとに上位のスコープが勝つ（local が project を上書き）', async () => {
    const r = await run({
      '.claude/settings.json': json({ env: { NODE_TLS_REJECT_UNAUTHORIZED: '0' } }),
      '.claude/settings.local.json': json({ env: { NODE_TLS_REJECT_UNAUTHORIZED: '1' } }),
    });
    expect(r007(r)).toEqual([['NODE_TLS_REJECT_UNAUTHORIZED=0', 'INFO', 'HIGH']]);
  });
});

describe('実行中の環境（--include-env）', () => {
  it('既定では読まない', async () => {
    const r = await scan({ root: await makeDir(), home: await makeDir(), managedDir: await makeDir() });
    expect(r.settings.filter((s) => s.source.file === '(environment)')).toEqual([]);
  });

  it('一覧にある変数だけを読み、秘密情報の値は保持しない', async () => {
    const r = await run({}, {
      env: {
        ANTHROPIC_API_KEY: FAKE.anthropic,
        CURSOR_API_KEY: PLAIN,
        NODE_TLS_REJECT_UNAUTHORIZED: '0',
        CLAUDE_CODE_DISABLE_INLINE_SHELL_RM_PROMPT: '1',
        HTTPS_PROXY: `http://user:${PLAIN}@proxy:3128`,
        CLAUDECODE: '1',
        UNRELATED_SECRET: PLAIN,
        PATH: '/usr/bin',
      },
    });
    expect(r.settings.map((s) => s.key).sort()).toEqual([
      'env.ANTHROPIC_API_KEY',
      'env.CLAUDE_CODE_DISABLE_INLINE_SHELL_RM_PROMPT',
      'env.CURSOR_API_KEY',
      'env.HTTPS_PROXY',
      'env.NODE_TLS_REJECT_UNAUTHORIZED',
    ]);
    expect(r007(r).map((x) => x[0])).toEqual(['NODE_TLS_REJECT_UNAUTHORIZED=0', 'CLAUDE_CODE_DISABLE_INLINE_SHELL_RM_PROMPT=1']);
    // 実行中の環境の値はファイルに書かれたものではないので、R004 の対象にしない
    expect(r.findings.filter((f) => f.ruleId === 'R004')).toEqual([]);
    const dump = JSON.stringify(r);
    for (const v of [FAKE.anthropic, PLAIN]) expect(dump).not.toContain(v);
  });

  it('CLI の -e / --include-env で実行中の環境を読み、値を出力しない', async () => {
    const root = await makeDir();
    const before = process.env.ANTHROPIC_AUTH_TOKEN;
    process.env.ANTHROPIC_AUTH_TOKEN = PLAIN;
    try {
      for (const format of ['text', 'json']) {
        let out = '';
        await buildProgram({ write: (s) => void (out += s), isTTY: false }, 'en').parseAsync(['node', 'a', 'scan', root, '-e', '--format', format]);
        expect(out).toContain('ANTHROPIC_AUTH_TOKEN');
        expect(out).not.toContain(PLAIN);
      }
    } finally {
      if (before === undefined) delete process.env.ANTHROPIC_AUTH_TOKEN;
      else process.env.ANTHROPIC_AUTH_TOKEN = before;
    }
  });
});

describe('ファイルに書かれた環境変数', () => {
  it('devcontainer の containerEnv / remoteEnv と、ワークフローの env を読む', async () => {
    const r = await run({
      '.devcontainer/devcontainer.json': json({ containerEnv: { NODE_TLS_REJECT_UNAUTHORIZED: '0' }, remoteEnv: { ANTHROPIC_API_KEY: PLAIN } }),
      '.github/workflows/ci.yml': 'env:\n  ANTHROPIC_API_KEY: ${{ secrets.KEY }}\n  NODE_OPTIONS: "--require ./x.js"\n  OTHER: 1\n',
    });
    expect(r.settings.map((s) => `${s.source.file} ${s.key}`)).toEqual([
      '.devcontainer/devcontainer.json env.NODE_TLS_REJECT_UNAUTHORIZED',
      '.devcontainer/devcontainer.json env.ANTHROPIC_API_KEY',
      '.github/workflows/ci.yml env.ANTHROPIC_API_KEY',
      '.github/workflows/ci.yml env.NODE_OPTIONS',
    ]);
    expect(r.settings.find((s) => s.source.file === '.github/workflows/ci.yml' && s.key === 'env.ANTHROPIC_API_KEY')?.value).toMatchObject({ en: 'reference (value unknown)' });
    // devcontainer に直接書かれた API キーは R004（共有される場所）
    const leak = r.findings.find((f) => f.ruleId === 'R004')!;
    expect(leak.file).toBe('.devcontainer/devcontainer.json');
    expect(leak.reason.en).toMatch(/shared through the repository/);
    expect(JSON.stringify(r)).not.toContain(PLAIN);
  });

  it('シェルの設定ファイルの export は -g のときだけ読む', async () => {
    const home = { '.zshrc': `export PATH=/x:$PATH\nexport NODE_TLS_REJECT_UNAUTHORIZED=0\nexport ANTHROPIC_API_KEY="${FAKE.anthropic}"\n`, '.config/fish/config.fish': 'set -gx CLAUDE_CODE_DISABLE_SUBSTITUTION_RM_PROMPT 1\n' };
    expect((await run({}, { home })).settings).toEqual([]);
    const r = await run({}, { home, global: true });
    expect(r.settings.map((s) => `${s.source.file} ${s.source.pointer} ${s.key}`)).toEqual([
      '~/.zshrc line 2 env.NODE_TLS_REJECT_UNAUTHORIZED',
      '~/.zshrc line 3 env.ANTHROPIC_API_KEY',
      '~/.config/fish/config.fish line 1 env.CLAUDE_CODE_DISABLE_SUBSTITUTION_RM_PROMPT',
    ]);
    expect(r.findings.find((f) => f.ruleId === 'R004')).toMatchObject({ level: 'HIGH', file: '~/.zshrc' });
    expect(JSON.stringify(r)).not.toContain(FAKE.anthropic);
  });

  it('起動コマンドの前の VAR=値 は、その起動の環境変数として扱う', async () => {
    const r = await run({}, { launch: ['NODE_TLS_REJECT_UNAUTHORIZED=0 CLAUDE_CODE_DISABLE_INLINE_SHELL_RM_PROMPT=1 claude -p hi'] });
    expect(r.settings.map((s) => [s.key, s.scope, s.status])).toEqual([
      ['env.NODE_TLS_REJECT_UNAUTHORIZED', 'cli', 'active'],
      ['env.CLAUDE_CODE_DISABLE_INLINE_SHELL_RM_PROMPT', 'cli', 'active'], // 起動環境なので無視されない
    ]);
    expect(r007(r).map((x) => x[1])).toEqual(['HIGH', 'MEDIUM']);
  });

  it('--agent cursor では Claude Code 用の変数を扱わない', async () => {
    const r = await scan({ root: await makeDir(), home: await makeDir(), agents: ['cursor'], env: { NODE_TLS_REJECT_UNAUTHORIZED: '0', CURSOR_API_KEY: 'x' } });
    expect(r.settings.map((s) => s.key)).toEqual(['env.CURSOR_API_KEY']);
  });
});
