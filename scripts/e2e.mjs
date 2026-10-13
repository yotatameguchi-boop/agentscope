// ビルド済みの CLI を実際に起動して、終了コードとパイプ切断時の挙動を確認する（CI でビルド後に実行）
import { spawnSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import os from 'node:os';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'dist', 'cli.js');
const fixture = path.join(root, 'test', 'fixtures', 'risky-project');
let failed = 0;

function check(name, ok, detail = '') {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${ok ? '' : `  ${detail}`}`);
  if (!ok) failed++;
}

const cases = [
  [['--help'], 0],
  [['--version'], 0],
  [['scan', fixture], 0],
  [['scan', fixture, '--format', 'json', '--lang', 'en'], 0],
  [['scan', '--agent', 'copilot'], 2],
  [['scan', path.join(root, 'does-not-exist')], 2],
  [['scan', path.join(root, 'package.json')], 2],
  [['no-such-command'], 2],
  [['scan', fixture, '--include-env', '--format', 'json'], 0],
  [['scan', fixture, '--launch', 'claude --dangerously-skip-permissions -p hi', '--launch', 'agent --force'], 0],
];
for (const [args, code] of cases) {
  const r = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  check(`agentscope ${args.join(' ')} → exit ${code}`, r.status === code, `got ${r.status}: ${r.stderr.slice(0, 200)}`);
  check(`agentscope ${args.join(' ')} → no stack trace`, !/\n\s+at /.test(r.stderr), r.stderr.slice(0, 200));
}

const json = spawnSync(process.execPath, [cli, 'scan', fixture, '--format', 'json'], { encoding: 'utf8' });
let parsed;
try {
  parsed = JSON.parse(json.stdout);
} catch {}
check('JSON output parses', parsed !== undefined);

// 読み手が1行で閉じても、EPIPE のスタックトレースを出さずに終える。
// パイプのバッファ（数十KB）に収まらないよう、ルールを大量に持つ一時プロジェクトを使う
const big = mkdtempSync(path.join(os.tmpdir(), 'agentscope-e2e-'));
mkdirSync(path.join(big, '.claude'));
writeFileSync(
  path.join(big, '.claude', 'settings.json'),
  JSON.stringify({ permissions: { allow: Array.from({ length: 5000 }, (_, i) => `Bash(npm run task-${i})`) } }),
);
await new Promise((resolve) => {
  const child = spawn(process.execPath, [cli, 'scan', big], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', (d) => (stderr += d));
  child.stdout.once('data', () => child.stdout.destroy());
  child.on('close', (code) => {
    check('closed pipe → no error output', !/EPIPE|\n\s+at /.test(stderr), stderr.slice(0, 200));
    check('closed pipe → exit 0', code === 0, `got ${code}`);
    resolve();
  });
});

rmSync(big, { recursive: true, force: true });

if (failed) {
  console.error(`${failed} check(s) failed`);
  process.exit(1);
}
