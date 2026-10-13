import { promises as fs } from 'node:fs';
import path from 'node:path';
import type { Text } from '../i18n.js';
import type { AgentId, ConfigKind, ConfigScope } from '../types.js';
import { isInside } from '../util/safeRead.js';

export interface Candidate {
  agent: AgentId;
  kind: ConfigKind;
  scope: ConfigScope;
  path: string;
  /** project 系のファイルは対象ディレクトリの外へのシンボリックリンクを読まない */
  confineTo?: string;
  /** unsupported のときの説明 */
  unsupportedReason?: Text;
  /** 管理設定の合成順（大きいほど後に合成され、単一値で勝つ） */
  mergeOrder?: number;
}

export interface DiscoverOptions {
  root: string;
  home: string;
  agents: AgentId[];
  includeGlobal: boolean;
  /** Claude Code の管理設定ディレクトリ（managed-settings.json などの置き場所） */
  managedDir?: string;
}

/** managed-settings.d/ に置ける分割ファイルの上限。決まった1ディレクトリだけを、再帰せずに読む */
const MAX_DROP_INS = 100;

/**
 * 決まった場所だけを見る。ディレクトリの再帰走査はしない（ホームディレクトリ全体を走査しないため）。
 * 存在しないファイルはここではまだ判定せず、読み取り時にスキップする。
 */
export async function discoverCandidates(opts: DiscoverOptions): Promise<Candidate[]> {
  const { root, home } = opts;
  const p = (...seg: string[]) => path.join(...seg);
  const out: Candidate[] = [];

  if (opts.agents.includes('claude-code')) {
    out.push(
      { agent: 'claude-code', kind: 'claude-settings', scope: 'project', path: p(root, '.claude', 'settings.json'), confineTo: root },
      { agent: 'claude-code', kind: 'claude-settings', scope: 'project-local', path: p(root, '.claude', 'settings.local.json'), confineTo: root },
      { agent: 'claude-code', kind: 'claude-mcp', scope: 'project', path: p(root, '.mcp.json'), confineTo: root },
    );
    if (opts.includeGlobal) {
      out.push(
        { agent: 'claude-code', kind: 'claude-settings', scope: 'user', path: p(home, '.claude', 'settings.json') },
        { agent: 'claude-code', kind: 'claude-global-state', scope: 'user', path: p(home, '.claude.json') },
      );
      if (opts.managedDir) out.push(...(await managedCandidates(opts.managedDir)));
    }
  }

  if (opts.agents.includes('cursor')) {
    out.push(
      { agent: 'cursor', kind: 'cursor-mcp', scope: 'project', path: p(root, '.cursor', 'mcp.json'), confineTo: root },
      { agent: 'cursor', kind: 'cursor-permissions', scope: 'project', path: p(root, '.cursor', 'permissions.json'), confineTo: root },
      { agent: 'cursor', kind: 'cursor-cli', scope: 'project', path: p(root, '.cursor', 'cli.json'), confineTo: root },
    );
    if (opts.includeGlobal) {
      out.push(
        { agent: 'cursor', kind: 'cursor-mcp', scope: 'user', path: p(home, '.cursor', 'mcp.json') },
        { agent: 'cursor', kind: 'cursor-permissions', scope: 'user', path: p(home, '.cursor', 'permissions.json') },
        { agent: 'cursor', kind: 'cursor-cli', scope: 'user', path: p(home, '.cursor', 'cli-config.json') },
      );
    }
  }

  return out;
}

/**
 * Claude Code の管理設定。managed-settings.json、managed-settings.d/*.json、managed-mcp.json。
 * https://code.claude.com/docs/en/managed-settings
 */
async function managedCandidates(dir: string): Promise<Candidate[]> {
  let dropIns: string[] = [];
  try {
    // 隠しファイルと .json 以外は Claude Code も読まない。名前順（numeric prefix で順序を決める運用）
    dropIns = (await fs.readdir(path.join(dir, 'managed-settings.d')))
      .filter((n) => n.endsWith('.json') && !n.startsWith('.'))
      .sort()
      .slice(0, MAX_DROP_INS);
  } catch {
    // ディレクトリがなければ分割ファイルはない
  }
  // 公式仕様: managed-settings.json を先に、続いて managed-settings.d/*.json を名前順に合成する（後のファイルが勝つ）
  const out: Candidate[] = [
    { agent: 'claude-code', kind: 'claude-settings', scope: 'managed', path: path.join(dir, 'managed-settings.json'), mergeOrder: 0 },
  ];
  dropIns.forEach((n, i) => {
    out.push({ agent: 'claude-code', kind: 'claude-settings', scope: 'managed', path: path.join(dir, 'managed-settings.d', n), mergeOrder: i + 1 });
  });
  out.push({ agent: 'claude-code', kind: 'claude-mcp', scope: 'managed', path: path.join(dir, 'managed-mcp.json') });
  return out;
}

/** 表示用のパス。対象ディレクトリ配下は相対パス、ホーム配下は ~ 表記、区切りは / に統一する */
export function toDisplayPath(abs: string, root: string, home: string): string {
  if (isInside(root, abs)) return path.relative(root, abs).split(path.sep).join('/') || '.';
  if (isInside(home, abs)) return ['~', ...path.relative(home, abs).split(path.sep)].join('/');
  return abs.split(path.sep).join('/');
}
