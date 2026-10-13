import { RISK_ORDER, type Finding } from '../types.js';
import { i001, i002 } from './info.js';
import { r001 } from './r001-broad-command.js';
import { r002 } from './r002-mcp-auto-approve.js';
import { r003 } from './r003-relaxed-checks.js';
import { r004 } from './r004-inline-credentials.js';
import { r005 } from './r005-broad-file-access.js';
import type { RuleContext, SecurityRule } from './types.js';

export const SECURITY_RULES: SecurityRule[] = [r001, r002, r003, r004, r005, i001, i002];

export function runRules(ctx: RuleContext, rules: SecurityRule[] = SECURITY_RULES): Finding[] {
  const findings = rules.flatMap((r) => r.check(ctx));
  return findings.sort(
    (a, b) =>
      RISK_ORDER[a.level] - RISK_ORDER[b.level] ||
      a.ruleId.localeCompare(b.ruleId) ||
      a.file.localeCompare(b.file) ||
      a.pointer.localeCompare(b.pointer),
  );
}

export type { RuleContext, SecurityRule } from './types.js';
