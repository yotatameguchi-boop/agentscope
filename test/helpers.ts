import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach } from 'vitest';

export const FIXTURES = path.join(import.meta.dirname, 'fixtures');

const created: string[] = [];

afterEach(async () => {
  while (created.length) await fs.rm(created.pop()!, { recursive: true, force: true });
});

/** 一時ディレクトリに設定ファイル群を作る。キーは相対パス、値はファイル内容 */
export async function makeDir(files: Record<string, string> = {}): Promise<string> {
  const dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'agentscope-test-')));
  created.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(dir, rel);
    await fs.mkdir(path.dirname(p), { recursive: true });
    await fs.writeFile(p, content);
  }
  return dir;
}

/**
 * テスト用のダミー認証情報。実在しない値だが、ソース上に完全な形で残さないよう実行時に組み立てる
 * （リポジトリのシークレットスキャンに誤検知されないため）。
 */
export const FAKE = {
  github: ['gh', 'p_', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'].join(''),
  anthropic: ['sk', '-ant-', 'api03-', 'x'.repeat(40)].join(''),
  aws: ['AK', 'IA', 'ABCDEFGHIJKLMNOP'].join(''),
  slack: ['xo', 'xb-', '1234567890-abcdefghij'].join(''),
};

/** ディレクトリ配下の全ファイルの内容と更新時刻を取る（読み取り専用であることの確認用） */
export async function snapshot(dir: string): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  const walk = async (d: string) => {
    for (const e of await fs.readdir(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) await walk(p);
      else if (e.isFile()) {
        const st = await fs.stat(p);
        out.set(p, `${st.mtimeMs}:${st.size}:${(await fs.readFile(p)).toString('base64')}`);
      }
    }
  };
  await walk(dir);
  return out;
}
