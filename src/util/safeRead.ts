import { constants as fsc, promises as fs } from 'node:fs';
import path from 'node:path';

/** 設定ファイルとして読む最大サイズ。~/.claude.json は大きくなりがちなので余裕を持たせる */
export const MAX_FILE_BYTES = 20 * 1024 * 1024;

export type ReadOutcome =
  | { ok: true; text: string; symlinkTarget?: string }
  | { ok: false; missing: true }
  | { ok: false; missing: false; reason: string; symlinkTarget?: string };

export interface SafeReadOptions {
  /**
   * シンボリックリンクのリンク先がこのディレクトリ配下にあるときだけ読む。
   * undefined のときは、リンク先が通常ファイルであれば読む（ユーザー設定の dotfiles 管理を想定）。
   */
  confineTo?: string;
}

/**
 * 読み取り専用で設定ファイルを開く。
 *
 * - 書き込みフラグでは決して開かない
 * - シンボリックリンクは解決先を確認し、範囲外・通常ファイル以外なら読まない
 * - 通常ファイル以外（FIFO、デバイスなど）は読まない。FIFO を開くと処理が止まるため
 * - サイズ上限を超えるファイルは読まない
 */
export async function safeReadFile(filePath: string, opts: SafeReadOptions = {}): Promise<ReadOutcome> {
  let lst;
  try {
    lst = await fs.lstat(filePath);
  } catch (err) {
    if (isNotFound(err)) return { ok: false, missing: true };
    return { ok: false, missing: false, reason: `ファイル情報を取得できません (${errCode(err)})` };
  }

  // ファイル自体だけでなく途中のディレクトリ（.claude/ など）がリンクの場合も実体を確認する
  let target: string;
  try {
    target = await fs.realpath(filePath);
  } catch (err) {
    // リンク切れはファイルが存在しないのと同じ扱いにはせず、明示する
    return { ok: false, missing: false, reason: `シンボリックリンクの解決に失敗しました (${errCode(err)})` };
  }
  const symlinkTarget = lst.isSymbolicLink() ? target : undefined;
  if (opts.confineTo) {
    const root = await realpathOr(opts.confineTo);
    if (!isInside(root, target)) {
      return {
        ok: false,
        missing: false,
        reason: 'シンボリックリンクが対象ディレクトリの外を指しているため読み取りませんでした',
        symlinkTarget,
      };
    }
  }

  // O_NOFOLLOW で開き、確認後にリンクへ差し替えられても追従しないようにする（Windows では未定義のため 0）
  const noFollow = fsc.O_NOFOLLOW ?? 0;
  // FIFO を開いてブロックしないよう O_NONBLOCK も付ける（通常ファイルには影響しない）
  const nonBlock = fsc.O_NONBLOCK ?? 0;
  let handle;
  try {
    handle = await fs.open(target, fsc.O_RDONLY | noFollow | nonBlock);
  } catch (err) {
    if (isNotFound(err)) return { ok: false, missing: true };
    return { ok: false, missing: false, reason: `ファイルを開けません (${errCode(err)})`, symlinkTarget };
  }
  try {
    const st = await handle.stat();
    if (!st.isFile()) {
      return { ok: false, missing: false, reason: '通常のファイルではないため読み取りませんでした', symlinkTarget };
    }
    if (st.size > MAX_FILE_BYTES) {
      return {
        ok: false,
        missing: false,
        reason: `ファイルサイズが上限（${MAX_FILE_BYTES / 1024 / 1024}MB）を超えているため読み取りませんでした`,
        symlinkTarget,
      };
    }
    const text = await handle.readFile({ encoding: 'utf8' });
    return { ok: true, text: stripBom(text), symlinkTarget };
  } catch (err) {
    return { ok: false, missing: false, reason: `ファイルを読み取れません (${errCode(err)})`, symlinkTarget };
  } finally {
    await handle.close();
  }
}

export function isInside(root: string, target: string): boolean {
  const rel = path.relative(root, target);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

async function realpathOr(p: string): Promise<string> {
  try {
    return await fs.realpath(p);
  } catch {
    return path.resolve(p);
  }
}

function stripBom(s: string): string {
  return s.charCodeAt(0) === 0xfeff ? s.slice(1) : s;
}

function isNotFound(err: unknown): boolean {
  const code = errCode(err);
  return code === 'ENOENT' || code === 'ENOTDIR';
}

function errCode(err: unknown): string {
  return (err as NodeJS.ErrnoException)?.code ?? 'UNKNOWN';
}
