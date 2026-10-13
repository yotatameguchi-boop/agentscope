import path from 'node:path';
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
  unsupportedReason?: string;
}

export interface DiscoverOptions {
  root: string;
  home: string;
  agents: AgentId[];
  includeGlobal: boolean;
}

/**
 * 決まった場所だけを見る。ディレクトリの再帰走査はしない（ホームディレクトリ全体を走査しないため）。
 * 存在しないファイルはここではまだ判定せず、読み取り時にスキップする。
 */
export function discoverCandidates(opts: DiscoverOptions): Candidate[] {
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
    }
  }

  if (opts.agents.includes('cursor')) {
    out.push(
      { agent: 'cursor', kind: 'cursor-mcp', scope: 'project', path: p(root, '.cursor', 'mcp.json'), confineTo: root },
      { agent: 'cursor', kind: 'cursor-permissions', scope: 'project', path: p(root, '.cursor', 'permissions.json'), confineTo: root },
      {
        agent: 'cursor',
        kind: 'unsupported',
        scope: 'project',
        path: p(root, '.cursor', 'cli.json'),
        confineTo: root,
        unsupportedReason: 'Cursor CLI の権限設定（cli.json）は v0.1 では解析対象外です',
      },
    );
    if (opts.includeGlobal) {
      out.push(
        { agent: 'cursor', kind: 'cursor-mcp', scope: 'user', path: p(home, '.cursor', 'mcp.json') },
        { agent: 'cursor', kind: 'cursor-permissions', scope: 'user', path: p(home, '.cursor', 'permissions.json') },
        {
          agent: 'cursor',
          kind: 'unsupported',
          scope: 'user',
          path: p(home, '.cursor', 'cli-config.json'),
          unsupportedReason: 'Cursor CLI の権限設定（cli-config.json）は v0.1 では解析対象外です',
        },
      );
    }
  }

  return out;
}

/** 表示用のパス。対象ディレクトリ配下は相対パス、ホーム配下は ~ 表記、区切りは / に統一する */
export function toDisplayPath(abs: string, root: string, home: string): string {
  if (isInside(root, abs)) return path.relative(root, abs).split(path.sep).join('/') || '.';
  if (isInside(home, abs)) return ['~', ...path.relative(home, abs).split(path.sep)].join('/');
  return abs.split(path.sep).join('/');
}
