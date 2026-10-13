/**
 * 回帰テスト: 再レビュー（対象コミット 5b4713f）で指摘された5項目と、入力経路ごとの秘密情報保護の統一
 */
import { describe, expect, it } from 'vitest';
import { buildProgram } from '../src/program.js';
import { scan } from '../src/scan.js';
import type { ScanResult } from '../src/types.js';
import { maskSecrets, protectOutput } from '../src/util/protect.js';
import { classifySecret, parseVarRef } from '../src/util/secrets.js';
import { FAKE, makeDir } from './helpers.js';

const json = (v: unknown) => JSON.stringify(v);
/** 既知の形式に当てはまらないダミーの認証文字列 */
const PLAIN = 'Zq8wLmT4vXp2Rk9s';

async function cliOutputs(root: string, extra: string[] = []): Promise<string[]> {
  const outs: string[] = [];
  for (const lang of ['ja', 'en'] as const) {
    for (const format of ['text', 'json']) {
      let out = '';
      await buildProgram({ write: (s) => void (out += s), isTTY: false }, lang).parseAsync(['node', 'a', 'scan', root, '--format', format, '--lang', lang, ...extra]);
      outs.push(out);
    }
  }
  return outs;
}

function expectClean(outs: string[], values: string[]) {
  for (const out of outs) for (const v of values) expect(out, v).not.toContain(v);
}

describe('1. 起動オプションの秘密情報が出力されない', () => {
  it('再現ケース: claude --add-dir /tmp/<ダミーキー>', async () => {
    const root = await makeDir();
    const outs = await cliOutputs(root, ['--launch', `claude --add-dir /tmp/${FAKE.anthropic}`]);
    expectClean(outs, [FAKE.anthropic]);
    expect(outs[1]).toContain('R004'); // 検出はする
  });

  it.each([
    ['claude --add-dir', true],
    ['claude --permission-mode', true],
    ['claude --tools', true],
    ['claude --setting-sources', true],
    ['claude --settings', true],
    ['claude --mcp-config', true],
    ['claude --plugin-dir', true],
    ['claude --model', true],
    ['claude --allowedTools', true],
    ['claude --disallowedTools', true],
    ['agent --sandbox', true],
    ['agent --workspace', true],
    ['agent --api-key', true],
    ['agent --model', true],
  ])('%s <ダミーキー> の値はどの出力にも残らない', async (prefix) => {
    const root = await makeDir();
    for (const key of [FAKE.anthropic, FAKE.github, FAKE.slack]) {
      expectClean(await cliOutputs(root, ['--launch', `${prefix} ${key}`]), [key]);
      expectClean(await cliOutputs(root, ['--launch', `${prefix}=${key}`]), [key]);
    }
  });

  it('環境変数の代入・位置引数・フラグ名・パスに埋め込まれても残らない', async () => {
    const root = await makeDir();
    const launches = [
      `ANTHROPIC_API_KEY=${FAKE.anthropic} claude -p hi`,
      `claude -p "use ${FAKE.github} please"`,
      `claude --${FAKE.slack}`,
      `claude --settings ./conf/${FAKE.aws}.json`,
      `agent --api-key ${PLAIN}`,
      `agent -- --api-key ${FAKE.anthropic}`,
    ];
    expectClean(await cliOutputs(root, launches.flatMap((l) => ['--launch', l])), [...Object.values(FAKE), PLAIN]);
  });

  it('出力保護は文字列の一部だけを伏せる（検出とは独立して働く）', () => {
    expect(maskSecrets(`/tmp/${FAKE.anthropic}/x`)).toBe('/tmp/[REDACTED]/x');
    expect(maskSecrets(`https://u:${PLAIN}@host/x?token=${PLAIN}&page=2`)).toBe('https://[REDACTED]@host/x?token=[REDACTED]&page=2');
    expect(maskSecrets(`deploy --token ${PLAIN} --name app`)).toBe('deploy --token [REDACTED] --name app');
    expect(maskSecrets(`curl -u admin:${PLAIN} https://x`)).toBe('curl -u admin:[REDACTED] https://x');
    expect(maskSecrets('Bash(npm run test *)')).toBe('Bash(npm run test *)');
    expect(maskSecrets('API_KEY=${API_KEY}')).toBe('API_KEY=${API_KEY}');
    // 日英の文言（Text）も対象
    expect(protectOutput({ reason: { ja: `値 ${FAKE.github}`, en: `value ${FAKE.github}` } })).toEqual({ reason: { ja: '値 [REDACTED]', en: 'value [REDACTED]' } });
  });
});

describe('2. 壊れた URL でも解析全体が止まらない', () => {
  const broken = { mcpServers: { s: { url: 'https://u:%ZZ@host.example/[' } } };

  it('URL のパスワード部分の % エンコードが壊れていても例外にならない', () => {
    expect(() => classifySecret(undefined, 'https://u:%ZZ@host.example/[')).not.toThrow();
  });

  it.each([
    ['通常ファイル', { '.mcp.json': json(broken) }, [] as string[]],
    ['--mcp-config のインライン JSON', {}, ['--launch', `claude --mcp-config '${json(broken)}'`]],
    ['--mcp-config の参照ファイル', { 'conf/mcp.json': json(broken) }, ['--launch', 'claude --mcp-config conf/mcp.json']],
  ])('%s', async (_name, files, extra) => {
    const root = await makeDir({ ...files, '.claude/settings.json': json({ permissions: { allow: ['Bash'] } }) });
    const outs = await cliOutputs(root, [...extra, '--launch', 'claude --dangerously-skip-permissions']);
    for (const out of outs) {
      expect(out).not.toMatch(/URIError|\n\s+at /);
      expect(out).toMatch(/R001/); // 他の設定の分析は続いている
      expect(out).toMatch(/R003/); // 他の起動コマンドの分析も続いている
      expect(out).not.toContain('%ZZ'); // 例外メッセージや設定値を出さない
    }
  });

  it('壊れた URL を含む起動コマンドの後に書かれた危険なオプションも検出する', async () => {
    const r = await scan({ root: await makeDir(), home: await makeDir(), managedDir: await makeDir(), launch: [`claude --mcp-config '${json(broken)}' --dangerously-skip-permissions`] });
    expect(r.findings.find((f) => f.ruleId === 'R003')?.level).toBe('HIGH');
    expect(r.mcpServers.map((s) => s.name)).toEqual(['s']);
  });
});

describe('3. 管理設定の分割ファイルを公式仕様どおりに合成する', () => {
  async function managed(files: Record<string, string>, project: Record<string, string> = {}): Promise<ScanResult> {
    return scan({ root: await makeDir(project), home: await makeDir(), managedDir: await makeDir(files), includeGlobal: true });
  }
  const active = (r: ScanResult, key: string) => r.settings.filter((s) => s.key === key && s.status === 'active').map((s) => [s.source.file.split('/').slice(-2).join('/'), s.value]);

  it('managed-settings.json を先に、分割ファイルを名前順に読む', async () => {
    const r = await managed({
      'managed-settings.json': json({}),
      'managed-settings.d/20-b.json': json({}),
      'managed-settings.d/10-a.json': json({}),
      'managed-settings.d/.hidden.json': json({ permissions: { allow: ['Bash'] } }),
      'managed-settings.d/notes.txt': 'x',
    });
    const order = r.files.filter((f) => f.scope === 'managed' && f.kind === 'claude-settings').map((f) => f.displayPath.split('/').slice(-2).join('/'));
    expect(order).toEqual([expect.stringMatching(/\/managed-settings\.json$/), 'managed-settings.d/10-a.json', 'managed-settings.d/20-b.json']);
    expect(r.rules).toEqual([]); // 隠しファイルは読まない
  });

  it('本体と分割ファイルが競合したら分割ファイルが勝つ', async () => {
    const r = await managed({
      'managed-settings.json': json({ permissions: { defaultMode: 'bypassPermissions' } }),
      'managed-settings.d/10-mode.json': json({ permissions: { defaultMode: 'plan' } }),
    });
    expect(active(r, 'permissions.defaultMode')).toEqual([['managed-settings.d/10-mode.json', 'plan']]);
    expect(r.findings.find((f) => f.ruleId === 'R003')).toMatchObject({ level: 'INFO', originalLevel: 'HIGH' });
  });

  it.each([
    [true, false, 'unknown'],
    [false, true, 'approved'],
  ])('再現ケース: 10-base=%s, 20-override=%s → MCP 承認は %s', async (a, b, approval) => {
    const r = await managed(
      { 'managed-settings.d/10-base.json': json({ enableAllProjectMcpServers: a }), 'managed-settings.d/20-override.json': json({ enableAllProjectMcpServers: b }) },
      { '.mcp.json': json({ mcpServers: { s: { command: 'node' } } }) },
    );
    expect(active(r, 'enableAllProjectMcpServers')).toEqual([['managed-settings.d/20-override.json', String(b)]]);
    expect(r.mcpServers.find((s) => s.name === 's')?.approval).toBe(approval);
  });

  it('リストは結合し、env はキーごとに後のファイルが勝つ', async () => {
    const r = await managed({
      'managed-settings.json': json({ permissions: { deny: ['Bash(rm *)'] }, env: { NODE_TLS_REJECT_UNAUTHORIZED: '0', NODE_OPTIONS: '--require ./a.js' } }),
      'managed-settings.d/10.json': json({ permissions: { deny: ['WebFetch'] }, env: { NODE_TLS_REJECT_UNAUTHORIZED: '1' } }),
    });
    expect(r.rules.filter((x) => x.effect === 'deny').map((x) => x.raw)).toEqual(['Bash(rm *)', 'WebFetch']);
    expect(active(r, 'env.NODE_TLS_REJECT_UNAUTHORIZED')).toEqual([['managed-settings.d/10.json', '1']]);
    expect(active(r, 'env.NODE_OPTIONS')).toHaveLength(1); // 後のファイルが設定しないキーは前の値が残る
  });

  it('権限制限（allowManagedPermissionRulesOnly）も合成後の値で判定する', async () => {
    const project = { '.claude/settings.json': json({ permissions: { allow: ['Bash'] } }) };
    const on = await managed({ 'managed-settings.json': json({ allowManagedPermissionRulesOnly: false }), 'managed-settings.d/10.json': json({ allowManagedPermissionRulesOnly: true }) }, project);
    expect(on.rules.find((x) => x.raw === 'Bash')?.status).toBe('ignored');
    const off = await managed({ 'managed-settings.json': json({ allowManagedPermissionRulesOnly: true }), 'managed-settings.d/10.json': json({ allowManagedPermissionRulesOnly: false }) }, project);
    expect(off.rules.find((x) => x.raw === 'Bash')?.status).toBe('active');
  });

  it('disableBypassPermissionsMode も合成後の値で判定する', async () => {
    const r = await managed({
      'managed-settings.json': json({ permissions: { disableBypassPermissionsMode: 'disable' } }),
      'managed-settings.d/10.json': json({ permissions: { disableBypassPermissionsMode: 'allow' } }),
    }, { '.claude/settings.local.json': json({}) });
    const lock = r.settings.filter((s) => s.key === 'permissions.disableBypassPermissionsMode');
    expect(lock.map((s) => s.status)).toEqual(['overridden', 'active']);
  });
});

describe('4. 環境変数のデフォルト値に書かれた秘密情報', () => {
  it('参照の形を区別する', () => {
    expect(parseVarRef('$TOKEN')).toEqual({ name: 'TOKEN' });
    expect(parseVarRef('${TOKEN}')).toEqual({ name: 'TOKEN' });
    expect(parseVarRef(`\${TOKEN:-${PLAIN}}`)).toEqual({ name: 'TOKEN', fallback: PLAIN });
    expect(parseVarRef(`\${TOKEN-${PLAIN}}`)).toEqual({ name: 'TOKEN', fallback: PLAIN });
    expect(parseVarRef(`\${TOKEN:=${PLAIN}}`)).toEqual({ name: 'TOKEN', fallback: PLAIN });
    expect(parseVarRef('plain')).toBeUndefined();
  });

  it('${TOKEN} は直接記述として検出せず、${TOKEN:-<値>} は検出する', () => {
    expect(classifySecret('TOKEN', '${TOKEN}')).toBeUndefined();
    expect(classifySecret('TOKEN', '${TOKEN:-}')).toBeUndefined();
    expect(classifySecret('TOKEN', '${TOKEN:-${OTHER}}')).toBeUndefined();
    expect(classifySecret('TOKEN', `\${TOKEN:-${PLAIN}}`)?.kind).toBe('key-name');
    expect(classifySecret('TOKEN', `\${TOKEN:-${FAKE.github}}`)?.kind).toBe('value-pattern');
  });

  it('再現ケース: MCP の env の ${TOKEN:-abcdefghijklmnop} を R004 で検出し、値を出力しない', async () => {
    const root = await makeDir({
      '.mcp.json': json({ mcpServers: { s: { command: 'node', env: { TOKEN: '${TOKEN:-abcdefghijklmnop}', OTHER_TOKEN: '${OTHER_TOKEN}' } } } }),
    });
    const outs = await cliOutputs(root);
    const r = JSON.parse(outs[3]!);
    expect(r.findings.filter((f: { ruleId: string }) => f.ruleId === 'R004').map((f: { pointer: string }) => f.pointer)).toEqual(['mcpServers.s.env.TOKEN']);
    expectClean(outs, ['abcdefghijklmnop']);
  });

  it('設定ファイル・シェル設定・起動コマンドの環境変数でも同じ扱いにする', async () => {
    const r = await scan({
      root: await makeDir({ '.claude/settings.json': json({ env: { ANTHROPIC_API_KEY: `\${ANTHROPIC_API_KEY:-${PLAIN}}` } }) }),
      home: await makeDir({ '.zshrc': `export CURSOR_API_KEY="\${CURSOR_API_KEY:-${PLAIN}}"\n` }),
      managedDir: await makeDir(),
      includeGlobal: true,
      launch: [`ANTHROPIC_AUTH_TOKEN=\${ANTHROPIC_AUTH_TOKEN:-${PLAIN}} claude -p hi`],
    });
    expect(r.findings.filter((f) => f.ruleId === 'R004').map((f) => f.file).sort()).toEqual(['--launch', '.claude/settings.json', '~/.zshrc'].sort());
    expect(JSON.stringify(r)).not.toContain(PLAIN);
  });
});

describe('5. オプション終端の --', () => {
  it('再現ケース: claude -- --dangerously-skip-permissions は起動オプションとして扱わない', async () => {
    const r = await scan({ root: await makeDir(), home: await makeDir(), launch: ['claude -- --dangerously-skip-permissions'] });
    expect(r.findings.filter((f) => f.ruleId === 'R003')).toEqual([]);
    expect(r.launches[0]!.options).toEqual([]);
  });

  it('-- より前の危険なオプションは検出する', async () => {
    const r = await scan({ root: await makeDir(), home: await makeDir(), launch: ['claude --dangerously-skip-permissions -p -- --allowedTools Bash'] });
    expect(r.findings.filter((f) => f.ruleId === 'R003').map((f) => f.level)).toEqual(['HIGH']);
    expect(r.rules).toEqual([]); // -- の後の --allowedTools は位置引数
  });

  it('Cursor でも同じ', async () => {
    const r = await scan({ root: await makeDir(), home: await makeDir(), launch: ['agent -p -- --force', 'agent --yolo -- x'] });
    expect(r.findings.filter((f) => f.ruleId === 'R003').map((f) => f.evidence)).toEqual(['force: true']);
  });
});
