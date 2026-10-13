import { promises as fs } from 'node:fs';
import path from 'node:path';
import { toDisplayPath } from '../discovery/discover.js';
import { isPlainObject, parseJsonc } from '../util/jsonc.js';
import { joinPointer } from '../util/pointer.js';
import { safeReadFile } from '../util/safeRead.js';

/**
 * 起動コマンドが書かれていそうな場所から、コマンド文字列を集める。
 * 決まったファイルだけを読み、ディレクトリを再帰的に走査しない。ファイルの中身は表示しない。
 */

export interface LaunchText {
  file: string;
  pointer: string;
  text: string;
}

export interface CollectOptions {
  root: string;
  home: string;
  /** --launch で直接渡されたコマンド */
  explicit: string[];
  /** プロジェクト内の package.json などを調べる */
  projectFiles: boolean;
  /** シェルの設定ファイル（~/.zshrc など）も調べる */
  shellFiles: boolean;
}

/** エージェントの起動を含みうるか（読み込んだ行を絞り込むための粗い判定） */
const MENTIONS_AGENT = /\b(?:claude|cursor-agent|agent|claude-code)\b/;

const MAX_WORKFLOW_FILES = 200;

export async function collectLaunchTexts(opts: CollectOptions): Promise<LaunchText[]> {
  const out: LaunchText[] = opts.explicit.map((text, i) => ({ file: '--launch', pointer: `#${i + 1}`, text }));
  if (opts.projectFiles) {
    const { root, home } = opts;
    const display = (p: string) => toDisplayPath(p, root, home);
    out.push(...(await fromPackageJson(path.join(root, 'package.json'), display(path.join(root, 'package.json')), root)));
    out.push(...(await fromVscodeTasks(path.join(root, '.vscode', 'tasks.json'), display(path.join(root, '.vscode', 'tasks.json')), root)));
    for (const p of [path.join(root, '.devcontainer', 'devcontainer.json'), path.join(root, '.devcontainer.json')]) {
      out.push(...(await fromDevcontainer(p, display(p), root)));
    }
    // 大文字小文字を区別しないファイルシステムでは Makefile と makefile が同じファイルになるため、実体で重複を除く
    const seen = new Set<string>();
    for (const name of ['Makefile', 'makefile', 'GNUmakefile', 'justfile', 'Justfile']) {
      const p = path.join(root, name);
      const st = await fs.stat(p).catch(() => undefined);
      if (!st) continue;
      const id = st.ino ? `${st.dev}:${st.ino}` : p.toLowerCase();
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(...(await fromLines(p, display(p), root)));
    }
    for (const p of await workflowFiles(root)) out.push(...(await fromWorkflow(p, display(p), root)));
  }
  if (opts.shellFiles) {
    for (const rel of ['.zshrc', '.zprofile', '.bashrc', '.bash_profile', '.profile', path.join('.config', 'fish', 'config.fish')]) {
      const p = path.join(opts.home, rel);
      out.push(...(await fromLines(p, toDisplayPath(p, opts.root, opts.home), undefined, true)));
    }
  }
  return out;
}

async function readText(p: string, confineTo: string | undefined): Promise<string | undefined> {
  const r = await safeReadFile(p, { confineTo });
  return r.ok ? r.text : undefined;
}

async function readJson(p: string, confineTo: string): Promise<unknown> {
  const text = await readText(p, confineTo);
  if (text === undefined) return undefined;
  const j = parseJsonc(text);
  return j.ok ? j.value : undefined;
}

/** 配列で渡されるコマンド（["claude", "-p", "..."]）を、引数の区切りを保ったまま1つの文字列にする */
function quoteArgs(args: unknown[]): string {
  return args
    .filter((a): a is string => typeof a === 'string')
    .map((a) => (/^[\w@%+=:,./-]+$/.test(a) ? a : `'${a.replace(/'/g, `'\\''`)}'`))
    .join(' ');
}

async function fromPackageJson(p: string, file: string, root: string): Promise<LaunchText[]> {
  const json = await readJson(p, root);
  if (!isPlainObject(json) || !isPlainObject(json.scripts)) return [];
  return Object.entries(json.scripts)
    .filter((e): e is [string, string] => typeof e[1] === 'string' && MENTIONS_AGENT.test(e[1]))
    .map(([name, text]) => ({ file, pointer: joinPointer('scripts', name), text }));
}

async function fromVscodeTasks(p: string, file: string, root: string): Promise<LaunchText[]> {
  const json = await readJson(p, root);
  if (!isPlainObject(json) || !Array.isArray(json.tasks)) return [];
  const out: LaunchText[] = [];
  json.tasks.forEach((t, i) => {
    if (!isPlainObject(t) || typeof t.command !== 'string') return;
    const text = [t.command, Array.isArray(t.args) ? quoteArgs(t.args) : ''].join(' ');
    if (MENTIONS_AGENT.test(text)) out.push({ file, pointer: `tasks[${i}]`, text });
  });
  return out;
}

const DEVCONTAINER_KEYS = ['initializeCommand', 'onCreateCommand', 'updateContentCommand', 'postCreateCommand', 'postStartCommand', 'postAttachCommand'];

async function fromDevcontainer(p: string, file: string, root: string): Promise<LaunchText[]> {
  const json = await readJson(p, root);
  if (!isPlainObject(json)) return [];
  const out: LaunchText[] = [];
  const add = (pointer: string, v: unknown) => {
    const text = typeof v === 'string' ? v : Array.isArray(v) ? quoteArgs(v) : undefined;
    if (text !== undefined && MENTIONS_AGENT.test(text)) out.push({ file, pointer, text });
  };
  for (const key of DEVCONTAINER_KEYS) {
    const v = json[key];
    if (isPlainObject(v)) for (const [k, x] of Object.entries(v)) add(joinPointer(key, k), x);
    else add(key, v);
  }
  return out;
}

/** 行単位で読む（Makefile、justfile、シェルの設定ファイル）。行継続はつなげる */
async function fromLines(p: string, file: string, root: string | undefined, shell = false): Promise<LaunchText[]> {
  const text = await readText(p, root);
  if (text === undefined) return [];
  const out: LaunchText[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const start = i;
    let line = lines[i]!;
    while (line.endsWith('\\') && i + 1 < lines.length) line = line.slice(0, -1) + ' ' + lines[++i];
    if (!MENTIONS_AGENT.test(line)) continue;
    const cmd = shell ? aliasBody(line) ?? line : line.replace(/^\t@?-?/, '');
    out.push({ file, pointer: `line ${start + 1}`, text: cmd });
  }
  return out;
}

/** alias c='claude --dangerously-skip-permissions' / fish の alias c 'claude ...' から本体を取り出す */
function aliasBody(line: string): string | undefined {
  const m = /^\s*alias\s+(?:-g\s+)?[\w.:-]+(?:=|\s+)(.*)$/.exec(line);
  if (!m) return undefined;
  const v = m[1]!.trim();
  const q = v[0];
  if ((q === "'" || q === '"') && v.lastIndexOf(q) > 0) return v.slice(1, v.lastIndexOf(q));
  return v;
}

async function workflowFiles(root: string): Promise<string[]> {
  const dir = path.join(root, '.github', 'workflows');
  try {
    const names = (await fs.readdir(dir)).filter((n) => /\.ya?ml$/.test(n)).sort().slice(0, MAX_WORKFLOW_FILES);
    return names.map((n) => path.join(dir, n));
  } catch {
    return [];
  }
}

/**
 * GitHub Actions のワークフロー。YAML は解析せず行単位で読む。
 * - run: の行（ブロックの中身も含む）
 * - anthropics/claude-code-action の claude_args: 入力（Claude Code に渡すオプション）
 */
async function fromWorkflow(p: string, file: string, root: string): Promise<LaunchText[]> {
  const text = await readText(p, root);
  if (text === undefined) return [];
  const lines = text.split(/\r?\n/);
  const out: LaunchText[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const args = /^(\s*)(?:-\s+)?claude_args:\s*(.*)$/.exec(line);
    if (args) {
      const indent = args[1]!.length;
      let value = args[2]!.trim();
      const start = i;
      if (/^[|>][-+]?$/.test(value)) {
        const block: string[] = [];
        while (i + 1 < lines.length && (lines[i + 1]!.trim() === '' || lines[i + 1]!.search(/\S/) > indent)) block.push(lines[++i]!.trim());
        value = block.join(' ');
      } else {
        value = value.replace(/^(['"])(.*)\1$/, '$2');
      }
      out.push({ file, pointer: `line ${start + 1} (claude_args)`, text: `claude ${value}` });
      continue;
    }
    if (!MENTIONS_AGENT.test(line)) continue;
    out.push({ file, pointer: `line ${i + 1}`, text: line.replace(/^\s*(?:-\s+)?(?:run:\s*)?/, '') });
  }
  return out;
}
