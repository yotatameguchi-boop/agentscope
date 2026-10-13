import { tx, type Text } from '../i18n.js';
import type { ConfigScope, PermissionSetting, SecretHit, SourceRef } from '../types.js';
import { classifySecret, parseVarRef, redactIfSecret } from '../util/secrets.js';
import { ENV_CATALOG, READ_ONLY_ENV } from './catalog.js';

/** 環境変数がどこから来たか。効く・効かないの判定に使う */
export type EnvOrigin =
  | 'settings' // 設定ファイルの env ブロック
  | 'process'; // 実際のプロセス環境（シェル、起動コマンドの VAR=値、CI、コンテナ）

export interface EnvInput {
  name: string;
  value: string;
  scope: ConfigScope;
  origin: EnvOrigin;
  source: SourceRef;
  launchId?: string;
  /** ファイルに書かれた値か（書かれていれば秘密情報の直書きとして R004 の対象にする） */
  writtenInFile: boolean;
}

/**
 * $VAR や ${{ secrets.X }} のような参照なら true。値そのものではないので評価しない。
 * ${VAR:-既定値} は既定値が直接書かれているため参照とはみなさない（既定値を値として評価する）
 */
function isReference(v: string): boolean {
  const ref = parseVarRef(v);
  if (ref) return ref.fallback === undefined;
  return /^\$\{\{.*\}\}$/s.test(v.trim()) || /^\$\{(?:env|input):[^}]+\}$/.test(v.trim());
}

/** 評価に使う値。${VAR:-既定値} なら既定値 */
function effectiveValue(v: string): string {
  return parseVarRef(v)?.fallback ?? v;
}

function urlForDisplay(v: string): string | undefined {
  try {
    const u = new URL(v);
    return `${u.protocol}//${u.host}`;
  } catch {
    return undefined;
  }
}

/**
 * 環境変数1つを、一覧にある変数なら PermissionSetting（key = "env.NAME"）に変換する。
 * 値は表示しても安全な形にしてから入れる。
 */
export function envToSetting(input: EnvInput): { setting?: PermissionSetting; secret?: SecretHit } {
  const spec = ENV_CATALOG[input.name];
  if (!spec || READ_ONLY_ENV.has(input.name)) return {};

  const raw = effectiveValue(input.value);
  let value: string | Text;
  if (isReference(input.value)) value = tx('参照（値は不明）', 'reference (value unknown)');
  else if (spec.display === 'secret') value = tx('設定あり（値は表示しません）', 'set (value not shown)');
  else if (spec.display === 'url') value = urlForDisplay(raw) ?? tx('URL として解析できません', 'not a valid URL');
  else value = redactIfSecret(raw.trim());

  const setting: PermissionSetting = {
    agent: spec.agent,
    scope: input.scope,
    key: `env.${input.name}`,
    value,
    source: input.source,
    status: 'active',
    launchId: input.launchId,
  };
  if (input.origin === 'settings' && spec.ignoredInSettingsEnv) {
    setting.status = 'ignored';
    setting.statusNote = tx(
      `${input.name} は設定ファイルの env では無視されます（Claude Code を起動する環境で設定したときだけ効きます）`,
      `${input.name} is ignored in a settings env block (it only takes effect when set in the environment that launches Claude Code)`,
    );
  } else if (input.origin === 'settings' && spec.ignoredInProjectEnv && (input.scope === 'project' || input.scope === 'project-local')) {
    setting.status = 'ignored';
    setting.statusNote = tx(`${input.name} はプロジェクト・ローカル設定の env では無視されます`, `${input.name} is ignored in the env block of project or local settings`);
  }

  // ファイルに直接書かれた資格情報は、変数名やURLの形から R004 で検出する
  let secret: SecretHit | undefined;
  if (input.writtenInFile && !isReference(input.value)) {
    // 既知の形式（sk-ant- など）なら value-pattern、そうでなくても資格情報の変数なら key-name として扱う
    const hit =
      classifySecret(input.name, input.value) ??
      (spec.display === 'secret' && raw.trim().length >= 8 ? { kind: 'key-name' as const, label: tx(`「${input.name}」`, `Key "${input.name}"`) } : undefined);
    if (hit) secret = { agent: spec.agent, file: input.source.file, pointer: input.source.pointer, ...hit };
  }
  return { setting, secret };
}

/** 一覧にある変数だけを取り出す（実際の環境変数を読むとき用） */
export function knownEnv(env: NodeJS.ProcessEnv): Array<[string, string]> {
  return Object.entries(env)
    .filter((e): e is [string, string] => typeof e[1] === 'string' && e[0] in ENV_CATALOG && !READ_ONLY_ENV.has(e[0]))
    .sort(([a], [b]) => a.localeCompare(b));
}
