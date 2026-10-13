import type { AgentId, ConfigFile, Finding, McpServer, PermissionRule, PermissionSetting, SecretHit } from '../types.js';

export interface RuleContext {
  agents: AgentId[];
  files: ConfigFile[];
  rules: PermissionRule[];
  settings: PermissionSetting[];
  mcpServers: McpServer[];
  secretHits: SecretHit[];
}

/** 検査ルール。外部コントリビューターはこの形のオブジェクトを追加し、rules/index.ts に登録する */
export interface SecurityRule {
  id: string;
  title: string;
  description: string;
  check(ctx: RuleContext): Finding[];
}

export function finding(
  base: Pick<SecurityRule, 'id' | 'title'>,
  f: Omit<Finding, 'ruleId' | 'title'>,
): Finding {
  return { ruleId: base.id, title: base.title, ...f };
}
