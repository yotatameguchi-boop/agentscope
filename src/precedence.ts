import { tx, type Text } from './i18n.js';
import { SCOPE_PRECEDENCE, type PermissionRule, type PermissionSetting } from './types.js';

/**
 * 複数の設定ファイルにまたがる優先順位を解決し、ルール・設定に有効性（status）を付ける。
 *
 * 根拠（Claude Code）: https://code.claude.com/docs/en/settings , https://code.claude.com/docs/en/permissions
 * - permissions.allow / ask / deny はスコープをまたいで連結される
 * - 評価順は deny → ask → allow。deny / ask に一致すれば allow は効かない
 * - 単一値のキーは managed > local > project > user の順で上位が勝つ
 * - defaultMode の auto / bypassPermissions は project / local から設定できない（v2.1.257 以降）
 * 根拠（Cursor CLI）: https://cursor.com/docs/cli/reference/permissions — deny は allow より優先
 *
 * 「打ち消されている」と判定するのは確実に言える場合だけにする。部分的な重なりは判定しない
 * （推測で安全側に倒すと、危険な設定を見落とさせることになるため）。
 */
export function applyPrecedence(rules: PermissionRule[], settings: PermissionSetting[]): void {
  // 単一値を先に確定させる（allowManagedPermissionRulesOnly や disable 系のロックも、合成後の値で判定するため）
  applyScalarPrecedence(settings);
  applyManagedOnly(rules, settings);
  applyRuleShadowing(rules);
  applyModeLocks(settings);
}

/** 管理設定で allowManagedPermissionRulesOnly が有効なら、管理設定以外の権限ルールは使われない */
function applyManagedOnly(rules: PermissionRule[], settings: PermissionSetting[]): void {
  const lock = settings.find(
    (s) => s.agent === 'claude-code' && s.scope === 'managed' && s.key === 'allowManagedPermissionRulesOnly' && s.value === 'true' && s.status === 'active',
  );
  if (!lock) return;
  for (const r of rules) {
    // 起動オプションのルールに効くかは公式の記載がないため、判定しない（打ち消しを推測しない）
    if (r.agent === 'claude-code' && r.scope !== 'managed' && r.scope !== 'cli' && r.status === 'active') {
      r.status = 'ignored';
      r.statusNote = tx(
        `管理設定（${lock.source.file}）の allowManagedPermissionRulesOnly により、管理設定以外の権限ルールは使われません`,
        `Not used, because allowManagedPermissionRulesOnly in managed settings (${lock.source.file}) limits permission rules to managed ones`,
      );
    }
  }
}

function toolGlob(tool: string): RegExp {
  return new RegExp(`^${tool.split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`);
}

/** blocker（deny / ask）が allow ルールを必ず覆うか */
export function covers(blocker: PermissionRule, allow: PermissionRule): boolean {
  if (blocker.agent !== allow.agent) return false;
  if (blocker.raw === '[REDACTED]' || allow.raw === '[REDACTED]') return false;
  const wholeTool = blocker.specifier === undefined || blocker.specifier.trim() === '*';

  if (blocker.agent === 'claude-code') {
    // 例: deny "Bash" / "Bash(*)" / "*" / "mcp__*" / "mcp__github" / "mcp__github__*"
    const b = blocker.tool;
    if (wholeTool) {
      if (b.includes('*')) return toolGlob(b).test(allow.tool);
      if (b === allow.tool) return true;
      // サーバー名だけの mcp__github は、そのサーバーの全ツールを指す
      if (/^mcp__/.test(b) && !b.slice(5).includes('__') && allow.tool.startsWith(`${b}__`)) return true;
      return false;
    }
    return b === allow.tool && normalizeSpec(blocker.specifier) === normalizeSpec(allow.specifier);
  }

  // Cursor CLI: Shell(git) / Mcp(server:tool) など。ツール種別が同じで、指定が同一か全体指定なら覆う
  if (blocker.nativeKind.startsWith('cursor.cli.') && allow.nativeKind.startsWith('cursor.cli.')) {
    if (blocker.tool !== allow.tool) return false;
    if (wholeTool) return true;
    return blocker.specifier?.trim() === allow.specifier?.trim();
  }
  return false;
}

/** "ls:*" と "ls *" は同じ意味（末尾の :* は空白 + * と同等） */
function normalizeSpec(spec: string | undefined): string | undefined {
  return spec?.trim().replace(/:\*$/, ' *');
}

function applyRuleShadowing(rules: PermissionRule[]): void {
  const blockers = rules.filter((r) => r.status === 'active' && (r.effect === 'deny' || r.effect === 'ask'));
  // 設定ファイルの deny / ask はすべての起動に効く。起動オプションの deny は、同じ起動のルールにだけ効く
  const applies = (b: PermissionRule, r: PermissionRule) => b.scope !== 'cli' || (r.scope === 'cli' && b.launchId === r.launchId);
  for (const r of rules) {
    if (r.status !== 'active' || r.effect !== 'allow') continue;
    // deny が ask より先に評価される
    const deny = blockers.find((b) => b.effect === 'deny' && applies(b, r) && covers(b, r));
    const ask = deny ? undefined : blockers.find((b) => b.effect === 'ask' && applies(b, r) && covers(b, r));
    const by = deny ?? ask;
    if (!by) continue;
    r.status = 'overridden';
    r.statusNote = deny
      ? tx(`${by.source.file} の deny ルール「${by.raw}」に一致するため実行されません`, `Blocked by the deny rule "${by.raw}" in ${by.source.file}`)
      : tx(`${by.source.file} の ask ルール「${by.raw}」に一致するため、毎回承認が求められます`, `Still asks for approval because of the ask rule "${by.raw}" in ${by.source.file}`);
  }
}

/** 単一値のキー。上位のスコープで設定されていれば下位の値は使われない */
const SCALAR_KEYS = new Set([
  'permissions.defaultMode',
  'permissions.disableBypassPermissionsMode',
  'permissions.disableAutoMode',
  'disableAutoMode',
  'enableAllProjectMcpServers',
  'skipDangerousModePermissionPrompt',
  'skipAutoPermissionPrompt',
  'sandbox.enabled',
  'sandbox.autoAllowBashIfSandboxed',
  'sandbox.allowUnsandboxedCommands',
  'sandbox.filesystem.disabled',
  'allowManagedPermissionRulesOnly',
]);

/** project / local から設定できない defaultMode の値（設定しても上書きにならない） */
function cannotSetFromScope(s: PermissionSetting): boolean {
  return s.key === 'permissions.defaultMode' && (s.scope === 'project' || s.scope === 'project-local') && (s.value === 'auto' || s.value === 'bypassPermissions');
}

function applyScalarPrecedence(settings: PermissionSetting[]): void {
  const byKey = new Map<string, PermissionSetting[]>();
  for (const s of settings) {
    // 起動オプションはその起動に限って効くため、設定ファイルの値を上書きしたとは扱わない
    // 起動オプション・環境変数は設定ファイルの値を上書きしたとは扱わない（その起動・その環境に限るため）。
    // env ブロックの値はキーごとに上位のスコープが勝つ
    if (s.status !== 'active' || !(SCALAR_KEYS.has(s.key) || s.key.startsWith('env.')) || cannotSetFromScope(s) || s.scope === 'cli' || s.scope === 'shell') continue;
    byKey.set(`${s.agent}:${s.key}`, [...(byKey.get(`${s.agent}:${s.key}`) ?? []), s]);
  }
  for (const group of byKey.values()) {
    if (group.length < 2) continue;
    // 上位のスコープが勝つ。同じ管理設定の中では、後に合成されるファイル（mergeOrder が大きい）が勝つ
    const sorted = [...group].sort(
      (a, b) => SCOPE_PRECEDENCE[a.scope] - SCOPE_PRECEDENCE[b.scope] || (b.mergeOrder ?? 0) - (a.mergeOrder ?? 0),
    );
    const winner = sorted[0]!;
    for (const s of sorted.slice(1)) {
      s.status = 'overridden';
      s.statusNote = s.scope === winner.scope ? mergedOverBy(winner) : overriddenBy(winner);
    }
  }
}

function mergedOverBy(winner: PermissionSetting): Text {
  const v = typeof winner.value === 'string' ? winner.value : winner.value.en;
  return tx(
    `管理設定の合成で、後から読まれる ${winner.source.file} の値（${v}）に置き換えられます`,
    `Replaced by the value in ${winner.source.file} (${v}), which is merged later in the managed settings`,
  );
}

function overriddenBy(winner: PermissionSetting): Text {
  const v = typeof winner.value === 'string' ? winner.value : winner.value.en;
  return tx(
    `優先度の高い ${winner.source.file} の値（${v}）で上書きされます`,
    `Overridden by the value in ${winner.source.file} (${v}), which has higher precedence`,
  );
}

/** disableBypassPermissionsMode / disableAutoMode が "disable" なら、そのモードは使えない */
function applyModeLocks(settings: PermissionSetting[]): void {
  const lock = (key: string) =>
    settings.find(
      (s) => s.agent === 'claude-code' && s.status === 'active' && s.scope !== 'cli' && (s.key === `permissions.${key}` || s.key === key) && s.value === 'disable',
    );
  // --restricted で起動すると、その起動では bypassPermissions が使えない
  for (const r of settings.filter((s) => s.scope === 'cli' && s.key === 'restricted' && s.status === 'active')) {
    for (const s of settings) {
      if (s.launchId === r.launchId && s.key === 'permissions.defaultMode' && s.value === 'bypassPermissions' && s.status === 'active') {
        s.status = 'ignored';
        s.statusNote = tx('同じ起動コマンドの --restricted により bypassPermissions は使えません', 'bypassPermissions is refused because the same launch uses --restricted');
      }
    }
  }
  const locks: Array<[string, PermissionSetting | undefined]> = [
    ['bypassPermissions', lock('disableBypassPermissionsMode')],
    ['auto', lock('disableAutoMode')],
  ];
  for (const [mode, by] of locks) {
    if (!by) continue;
    for (const s of settings) {
      if (s.key === 'permissions.defaultMode' && s.value === mode && s.status === 'active') {
        s.status = 'ignored';
        s.statusNote = tx(
          `${by.source.file} の ${by.key} により ${mode} モードは使えません`,
          `${mode} mode is disabled by ${by.key} in ${by.source.file}`,
        );
      }
    }
  }
}

/** 実際に効いている enableAllProjectMcpServers（MCP サーバーの承認状態の判定に使う） */
export function effectiveEnableAll(settings: PermissionSetting[]): { value: boolean; file: string } | undefined {
  const s = settings
    .filter((x) => x.agent === 'claude-code' && x.key === 'enableAllProjectMcpServers' && x.status === 'active')
    .sort((a, b) => SCOPE_PRECEDENCE[a.scope] - SCOPE_PRECEDENCE[b.scope] || (b.mergeOrder ?? 0) - (a.mergeOrder ?? 0))[0];
  return s ? { value: s.value === 'true', file: s.source.file } : undefined;
}
