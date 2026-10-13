/**
 * 起動時のオプション（起動コマンド）の解析
 */
import { describe, expect, it } from 'vitest';
import { findInvocation } from '../src/launch/parse.js';
import { splitCommands } from '../src/launch/tokenize.js';
import { buildProgram } from '../src/program.js';
import { scan } from '../src/scan.js';
import type { ScanResult } from '../src/types.js';
import { FAKE, makeDir } from './helpers.js';

const json = (v: unknown) => JSON.stringify(v);

async function run(files: Record<string, string>, launch: string[] = [], extra: { global?: boolean; home?: Record<string, string>; launchFiles?: boolean } = {}): Promise<ScanResult> {
  return scan({
    root: await makeDir(files),
    home: await makeDir(extra.home ?? {}),
    managedDir: await makeDir(),
    launch,
    includeGlobal: extra.global ?? false,
    launchFiles: extra.launchFiles,
  });
}

const ids = (r: ScanResult) => r.findings.map((f) => [f.ruleId, f.level]);

describe('splitCommands（実行しない字句解析）', () => {
  it('引用符・エスケープ・区切り記号を扱う', () => {
    expect(splitCommands(`cd app && claude --allowedTools "Bash(git log *)" 'Read' -p "say \\"hi\\""; echo done | cat`)).toEqual([
      ['cd', 'app'],
      ['claude', '--allowedTools', 'Bash(git log *)', 'Read', '-p', 'say "hi"'],
      ['echo', 'done'],
      ['cat'],
    ]);
  });

  it('変数やコマンド置換は展開しない', () => {
    expect(splitCommands('claude --settings $(cat x) $HOME # comment')).toEqual([['claude', '--settings', '$(cat', 'x)', '$HOME']]);
  });

  it('行継続をつなげる', () => {
    expect(splitCommands('claude \\\n  --permission-mode plan')).toEqual([['claude', '--permission-mode', 'plan']]);
  });
});

describe('findInvocation', () => {
  it.each([
    [['claude', '-p'], 'claude-code'],
    [['/usr/local/bin/claude'], 'claude-code'],
    [['FOO=1', 'exec', 'claude'], 'claude-code'],
    [['npx', '-y', '@anthropic-ai/claude-code@latest', '-p'], 'claude-code'],
    [['timeout', '600', 'claude'], 'claude-code'],
    [['agent', '--force'], 'cursor'],
    [['cursor-agent', '-p'], 'cursor'],
  ])('%j → %s', (words, agent) => {
    expect(findInvocation(words)?.agent).toBe(agent);
  });

  it.each([[['echo', 'claude']], [['ssh-agent']], [['npx', 'something-else']], [['git', 'commit']]])('%j は起動ではない', (words) => {
    expect(findInvocation(words)).toBeUndefined();
  });
});

describe('--launch で渡した起動コマンド', () => {
  it('Claude Code の権限に関わるオプションを読み取る', async () => {
    const r = await run({}, [
      `claude -p --dangerously-skip-permissions --allowedTools "Bash(npm exec *)" "WebFetch" --add-dir / "do the thing"`,
    ]);
    expect(r.launches).toHaveLength(1);
    expect(r.launches[0]!.options.map((o) => o.flag)).toEqual(['-p', '--dangerously-skip-permissions', '--allowedTools', '--add-dir']);
    expect(r.rules.map((x) => [x.raw, x.scope, x.nativeKind])).toEqual([
      ['Bash(npm exec *)', 'cli', 'claude.cli.allowedTools'],
      ['WebFetch', 'cli', 'claude.cli.allowedTools'],
    ]);
    expect(ids(r)).toEqual(expect.arrayContaining([['R001', 'HIGH'], ['R003', 'HIGH'], ['R005', 'MEDIUM'], ['R006', 'MEDIUM']]));
  });

  it('--permission-mode manual は default の別名', async () => {
    const r = await run({}, ['claude --permission-mode manual']);
    expect(r.settings[0]).toMatchObject({ key: 'permissions.defaultMode', value: 'default', scope: 'cli' });
  });

  it('Cursor の --force / --approve-mcps / --sandbox disabled / --trust を検出する', async () => {
    const r = await run({}, ['agent -p --yolo --approve-mcps --sandbox disabled --trust "fix"']);
    expect(ids(r)).toEqual([['R003', 'HIGH'], ['R002', 'MEDIUM'], ['R003', 'LOW'], ['R003', 'LOW']]);
  });

  it('--settings / --mcp-config のインライン JSON を解析する', async () => {
    const r = await run({}, [
      `claude --settings '{"permissions":{"allow":["Edit"]}}' --mcp-config '{"mcpServers":{"gh":{"command":"npx","env":{"GITHUB_TOKEN":"${FAKE.github}"}}}}'`,
    ]);
    expect(r.rules[0]).toMatchObject({ raw: 'Edit', scope: 'cli' });
    expect(r.rules[0]!.source.pointer).toBe('#1 --settings › permissions.allow[0]');
    expect(r.mcpServers[0]).toMatchObject({ name: 'gh', scope: 'cli', approval: 'not-required' });
    expect(ids(r)).toEqual(expect.arrayContaining([['R005', 'HIGH'], ['R004', 'HIGH']]));
    expect(JSON.stringify(r)).not.toContain(FAKE.github);
  });

  it('--settings のファイルは対象ディレクトリ内なら読み、外なら読まない', async () => {
    const outside = await makeDir({ 's.json': json({ permissions: { allow: ['Bash'] } }) });
    const r = await run({ 'conf/s.json': json({ permissions: { allow: ['Edit'] } }) }, [
      'claude --settings conf/s.json',
      `claude --settings ${outside}/s.json`,
    ]);
    expect(r.rules.map((x) => x.raw)).toEqual(['Edit']);
    expect(r.unparsed.map((u) => u.pointer)).toEqual(['#2 --settings']);
  });

  it('起動コマンドの秘密情報（環境変数・--api-key）を出力しない', async () => {
    const r = await run({}, [`ANTHROPIC_API_KEY=${FAKE.anthropic} claude -p hi`, 'agent --api-key Zq8wLmT4vXp2Rk9s -p hi', 'agent --api-key $CURSOR_API_KEY']);
    expect(r.findings.filter((f) => f.ruleId === 'R004').map((f) => f.level)).toEqual(['HIGH', 'MEDIUM']);
    for (const lang of ['ja', 'en'] as const) {
      for (const format of ['text', 'json']) {
        let out = '';
        await buildProgram({ write: (s) => void (out += s), isTTY: false }, lang).parseAsync([
          'node', 'a', 'scan', await makeDir(), '--format', format, '--lang', lang,
          '--launch', `ANTHROPIC_API_KEY=${FAKE.anthropic} claude -p hi`, '--launch', 'agent --api-key Zq8wLmT4vXp2Rk9s',
        ]);
        expect(out).not.toContain(FAKE.anthropic);
        expect(out).not.toContain('Zq8wLmT4vXp2Rk9s');
      }
    }
  });

  it('--agent で対象を絞ると、他のエージェントの起動コマンドは無視する', async () => {
    const r = await scan({ root: await makeDir(), home: await makeDir(), agents: ['cursor'], launch: ['claude --dangerously-skip-permissions', 'agent --force'] });
    expect(r.launches.map((l) => l.executable)).toEqual(['agent']);
  });
});

describe('起動オプションと設定ファイルの関係', () => {
  it('設定ファイルの deny は起動オプションの --allowedTools を打ち消す', async () => {
    const r = await run({ '.claude/settings.json': json({ permissions: { deny: ['Bash'] } }) }, ['claude --allowedTools Bash']);
    expect(r.rules.find((x) => x.scope === 'cli')?.status).toBe('overridden');
    expect(r.findings.find((f) => f.ruleId === 'R001')).toMatchObject({ level: 'INFO', originalLevel: 'HIGH' });
  });

  it('起動オプションの --disallowedTools は同じ起動のルールだけを打ち消す', async () => {
    const r = await run({ '.claude/settings.json': json({ permissions: { allow: ['Bash'] } }) }, [
      'claude --allowedTools "Bash(python3 *)" --disallowedTools Bash',
    ]);
    expect(r.rules.find((x) => x.source.file === '.claude/settings.json')?.status).toBe('active'); // 他の起動では効く
    expect(r.rules.find((x) => x.raw === 'Bash(python3 *)')?.status).toBe('overridden');
  });

  it('起動オプションの --permission-mode は設定ファイルの値を上書きしたと扱わない', async () => {
    const r = await run({ '.claude/settings.local.json': json({ permissions: { defaultMode: 'acceptEdits' } }) }, ['claude --permission-mode plan']);
    expect(r.settings.find((s) => s.scope === 'project-local')?.status).toBe('active');
  });

  it('disableBypassPermissionsMode があれば --dangerously-skip-permissions も効かない', async () => {
    const r = await run({ '.claude/settings.json': json({ permissions: { disableBypassPermissionsMode: 'disable' } }) }, ['claude --dangerously-skip-permissions']);
    expect(r.findings.find((f) => f.ruleId === 'R003')).toMatchObject({ level: 'INFO', originalLevel: 'HIGH' });
  });

  it('--restricted と一緒に指定した bypassPermissions は効かない', async () => {
    const r = await run({}, ['claude --restricted --permission-mode bypassPermissions', 'claude --permission-mode bypassPermissions']);
    expect(r.findings.filter((f) => f.ruleId === 'R003').map((f) => f.level).sort()).toEqual(['HIGH', 'INFO']);
  });
});

describe('起動コマンドが書かれたファイル', () => {
  it('package.json / tasks.json / devcontainer / Makefile / ワークフローから見つける', async () => {
    const r = await run({
      'package.json': json({ scripts: { ai: 'claude --dangerously-skip-permissions', test: 'vitest', fix: 'agent -p --force "fix lint"' } }),
      '.vscode/tasks.json': json({ tasks: [{ label: 'review', command: 'claude', args: ['--allowedTools', 'Bash(npm exec *)', '-p', 'review'] }] }),
      '.devcontainer/devcontainer.json': json({ postCreateCommand: { ai: 'npx -y @anthropic-ai/claude-code --permission-mode acceptEdits -p hi' } }),
      Makefile: 'review:\n\tclaude -p \\\n\t  --allowedTools "Bash(*)" "review"\n',
      '.github/workflows/claude.yml': [
        'jobs:',
        '  review:',
        '    steps:',
        '      - uses: anthropics/claude-code-action@v1',
        '        with:',
        '          claude_args: |',
        '            --allowedTools "Bash(git *)"',
        '            --permission-mode acceptEdits',
        '      - run: claude -p --dangerously-skip-permissions "ci"',
      ].join('\n'),
    });
    expect(r.launches.map((l) => `${l.source.file} ${l.source.pointer}`)).toEqual([
      'package.json scripts.ai',
      'package.json scripts.fix',
      '.vscode/tasks.json tasks[0]',
      '.devcontainer/devcontainer.json postCreateCommand.ai',
      'Makefile line 2',
      '.github/workflows/claude.yml line 6 (claude_args)',
      '.github/workflows/claude.yml line 9',
    ]);
    expect(r.rules.map((x) => x.raw)).toEqual(['Bash(npm exec *)', 'Bash(*)', 'Bash(git *)']);
  });

  it('--no-launch-files ではファイルを探さない', async () => {
    const r = await run({ 'package.json': json({ scripts: { ai: 'claude --dangerously-skip-permissions' } }) }, [], { launchFiles: false });
    expect(r.launches).toEqual([]);
  });

  it('シェルの設定ファイルの alias は -g のときだけ読む', async () => {
    const home = { '.zshrc': "export PATH=$PATH:/x\nalias cc='claude --dangerously-skip-permissions'\nalias ls='ls -G'\n" };
    expect((await run({}, [], { home })).launches).toEqual([]);
    const r = await run({}, [], { home, global: true });
    expect(r.launches.map((l) => `${l.source.file} ${l.source.pointer}`)).toEqual(['~/.zshrc line 2']);
    expect(r.findings.find((f) => f.ruleId === 'R003')).toMatchObject({ level: 'HIGH' });
  });

  it('起動コマンドを含まないファイルからは何も拾わない', async () => {
    const r = await run({ 'package.json': json({ scripts: { build: 'tsc', agent: 'node server.js' } }), Makefile: 'all:\n\techo user-agent\n' });
    expect(r.launches).toEqual([]);
  });
});
