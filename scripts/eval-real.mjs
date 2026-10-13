// 実データでの誤検知の計測。指定したディレクトリ内の設定ファイル・ロックファイル・ワークフローなどから
// 文字列を集め、出力保護で変更されたものを数える。元の文字列は表示しない（本物の秘密情報を含みうるため）。
// 使い方: node scripts/eval-real.mjs <dir>...   （先に npm run build が必要）
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { maskSecrets } from '../dist/util/protect.js';

const FILES = /^(?:package(?:-lock)?\.json|tsconfig.*\.json|settings(?:\.local)?\.json|\.mcp\.json|mcp\.json|.*\.ya?ml|Makefile|Dockerfile|\.env\.example|README(?:\.ja)?\.md|CLAUDE\.md)$/;
const SKIP = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage', '.venv', 'venv', '__pycache__']);
const strings = [];

function walk(dir, depth) {
  if (depth > 6) return;
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (!SKIP.has(e.name)) walk(p, depth + 1); continue; }
    if (!e.isFile() || !FILES.test(e.name)) continue;
    try { if (statSync(p).size > 5_000_000) continue; } catch { continue; }
    const text = readFileSync(p, 'utf8');
    if (p.endsWith('.json')) {
      try { collect(JSON.parse(text), p); continue; } catch { /* 行単位にする */ }
    }
    for (const line of text.split(/\r?\n/)) if (line.trim()) strings.push({ file: p, s: line });
  }
}
function collect(v, file) {
  if (typeof v === 'string') strings.push({ file, s: v });
  else if (Array.isArray(v)) v.forEach((x) => collect(x, file));
  else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) { strings.push({ file, s: k }); collect(x, file); }
}

for (const d of process.argv.slice(2)) walk(path.resolve(d), 0);
const changed = strings.filter((x) => maskSecrets(x.s) !== x.s);
console.log(`strings: ${strings.length}  changed: ${changed.length}  (${((1 - changed.length / strings.length) * 100).toFixed(3)}% unchanged)`);
const byFile = new Map();
for (const c of changed) byFile.set(path.basename(c.file), (byFile.get(path.basename(c.file)) ?? 0) + 1);
console.log('changed by file name:', Object.fromEntries(byFile));
// 伏せた後の文字列だけを、前後を短くして表示する
for (const c of changed.slice(0, 40)) {
  const after = maskSecrets(c.s);
  const i = after.indexOf('[REDACTED]');
  console.log(`  ${path.basename(c.file)}: …${after.slice(Math.max(0, i - 50), i + 60).replace(/\s+/g, ' ')}…`);
}
