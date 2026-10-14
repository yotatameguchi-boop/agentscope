import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

/**
 * 公開データ（node_modules の package.json・README・設定ファイル）から文字列を集める。
 * ロックファイルでバージョンが固定されているため、CI でも同じ内容になる。
 */
const FILES = /^(?:package\.json|tsconfig.*\.json|.*\.ya?ml|README(?:\.[a-z]+)?\.md|CHANGELOG\.md)$/i;

export function collectPublicStrings(dir: string, maxDepth = 12): Array<{ file: string; s: string }> {
  const out: Array<{ file: string; s: string }> = [];
  const walk = (d: string, depth: number) => {
    if (depth > maxDepth) return;
    let entries;
    try {
      entries = readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) {
        if (e.name !== '.git') walk(p, depth + 1);
        continue;
      }
      if (!e.isFile() || !FILES.test(e.name)) continue;
      try {
        if (statSync(p).size > 2_000_000) continue;
      } catch {
        continue;
      }
      const text = readFileSync(p, 'utf8');
      if (p.endsWith('.json')) {
        try {
          collect(JSON.parse(text), p, out);
          continue;
        } catch {
          // 行単位で読む
        }
      }
      for (const line of text.split(/\r?\n/)) if (line.trim()) out.push({ file: p, s: line });
    }
  };
  walk(dir, 0);
  return out;
}

function collect(v: unknown, file: string, out: Array<{ file: string; s: string }>) {
  if (typeof v === 'string') out.push({ file, s: v });
  else if (Array.isArray(v)) v.forEach((x) => collect(x, file, out));
  else if (v && typeof v === 'object') {
    for (const [k, x] of Object.entries(v)) {
      out.push({ file, s: k });
      collect(x, file, out);
    }
  }
}
