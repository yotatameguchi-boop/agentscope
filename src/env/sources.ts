import path from 'node:path';
import { promises as fs } from 'node:fs';
import { toDisplayPath } from '../discovery/discover.js';
import { isPlainObject, parseJsonc } from '../util/jsonc.js';
import { joinPointer } from '../util/pointer.js';
import { safeReadFile } from '../util/safeRead.js';
import { ENV_CATALOG } from './catalog.js';
import type { EnvInput } from './record.js';

/**
 * ファイルに書かれた環境変数を集める。一覧（ENV_CATALOG）にある変数だけを対象にし、他の行や値は読み捨てる。
 * - devcontainer の containerEnv / remoteEnv（プロジェクト）
 * - GitHub Actions ワークフローの env:（プロジェクト。YAML は解析せず行単位）
 * - シェルの設定ファイルの export / set -x（-g のとき）
 */
export async function collectFileEnv(opts: { root: string; home: string; projectFiles: boolean; shellFiles: boolean }): Promise<EnvInput[]> {
  const out: EnvInput[] = [];
  const { root, home } = opts;
  const display = (p: string) => toDisplayPath(p, root, home);
  const push = (name: string, value: string, file: string, pointer: string) => {
    if (name in ENV_CATALOG) out.push({ name, value, scope: 'shell', origin: 'process', source: { file, pointer }, writtenInFile: true });
  };

  if (opts.projectFiles) {
    for (const p of [path.join(root, '.devcontainer', 'devcontainer.json'), path.join(root, '.devcontainer.json')]) {
      const r = await safeReadFile(p, { confineTo: root });
      if (!r.ok) continue;
      const j = parseJsonc(r.text);
      if (!j.ok || !isPlainObject(j.value)) continue;
      for (const key of ['containerEnv', 'remoteEnv']) {
        const env = j.value[key];
        if (!isPlainObject(env)) continue;
        for (const [name, value] of Object.entries(env)) if (typeof value === 'string') push(name, value, display(p), joinPointer(key, name));
      }
    }
    const dir = path.join(root, '.github', 'workflows');
    const names = await fs.readdir(dir).then((n) => n.filter((x) => /\.ya?ml$/.test(x)).sort().slice(0, 200)).catch(() => [] as string[]);
    for (const n of names) {
      const p = path.join(dir, n);
      const r = await safeReadFile(p, { confineTo: root });
      if (!r.ok) continue;
      r.text.split(/\r?\n/).forEach((line, i) => {
        const m = /^\s*([A-Z][A-Z0-9_]*)\s*:\s*(.*?)\s*$/.exec(line);
        if (m) push(m[1]!, unquote(m[2]!), display(p), `line ${i + 1}`);
      });
    }
  }

  if (opts.shellFiles) {
    for (const rel of ['.zshrc', '.zprofile', '.zshenv', '.bashrc', '.bash_profile', '.profile', path.join('.config', 'fish', 'config.fish')]) {
      const p = path.join(home, rel);
      const r = await safeReadFile(p);
      if (!r.ok) continue;
      r.text.split(/\r?\n/).forEach((line, i) => {
        const sh = /^\s*(?:export\s+)([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
        const fish = /^\s*set\s+(?:-[a-zA-Z]+\s+)*([A-Za-z_][A-Za-z0-9_]*)\s+(.*)$/.exec(line);
        const m = sh ?? fish;
        if (m) push(m[1]!, unquote(m[2]!.replace(/\s+#.*$/, '')), display(p), `line ${i + 1}`);
      });
    }
  }
  return out;
}

function unquote(v: string): string {
  const t = v.trim();
  return /^(['"]).*\1$/.test(t) ? t.slice(1, -1) : t;
}
