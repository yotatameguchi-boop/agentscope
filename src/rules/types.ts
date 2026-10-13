import type { Text } from '../i18n.js';
import type { AgentId, ConfigFile, Finding, McpServer, PermissionRule, PermissionSetting, SecretHit } from '../types.js';

export interface RuleContext {
  agents: AgentId[];
  files: ConfigFile[];
  rules: PermissionRule[];
  settings: PermissionSetting[];
  mcpServers: McpServer[];
  secretHits: SecretHit[];
  /** ホームディレクトリ（additionalDirectories がホーム全体かの判定に使う） */
  home?: string;
  /** ユーザー単位・組織の管理設定まで読んだか（-g） */
  includeGlobal?: boolean;
  /** 実行中の OS（読めない管理設定の配布元を伝えるため） */
  platform?: NodeJS.Platform;
}

/** 検査ルール。外部コントリビューターはこの形のオブジェクトを追加し、rules/index.ts に登録する */
export interface SecurityRule {
  id: string;
  title: Text;
  description: Text;
  check(ctx: RuleContext): Finding[];
}

export function finding(
  base: Pick<SecurityRule, 'id' | 'title'>,
  f: Omit<Finding, 'ruleId' | 'title'>,
): Finding {
  return { ruleId: base.id, title: base.title, ...f };
}
