import { tx } from '../i18n.js';
import { RISK_ORDER, type Finding } from '../types.js';
import { i001, i002, i003, i004 } from './info.js';
import { r001 } from './r001-broad-command.js';
import { r002 } from './r002-mcp-auto-approve.js';
import { r003 } from './r003-relaxed-checks.js';
import { r004 } from './r004-inline-credentials.js';
import { r005 } from './r005-broad-file-access.js';
import { r006 } from './r006-broad-network.js';
import { r007 } from './r007-risky-env.js';
import { r008 } from './r008-managed-integrity.js';
import type { RuleContext, SecurityRule } from './types.js';

export const SECURITY_RULES: SecurityRule[] = [r001, r002, r003, r004, r005, r006, r007, r008, i001, i002, i003, i004];

export function runRules(ctx: RuleContext, rules: SecurityRule[] = SECURITY_RULES): Finding[] {
  const findings = rules.flatMap((r) => r.check(ctx)).map((f) => applyEffect(f, ctx));
  return findings.sort(
    (a, b) =>
      RISK_ORDER[a.level] - RISK_ORDER[b.level] ||
      a.ruleId.localeCompare(b.ruleId) ||
      a.file.localeCompare(b.file) ||
      a.pointer.localeCompare(b.pointer),
  );
}

export type { RuleContext, SecurityRule } from './types.js';

/**
 * 根拠の設定が実際には効かない（無視される・打ち消される）場合、検出を INFO に下げて理由を添える。
 * 消さずに残すのは、条件が変わる（deny を消す、バージョンが変わるなど）と再び有効になりうるため。
 */
function applyEffect(f: Finding, ctx: RuleContext): Finding {
  if (f.level === 'INFO') return f;
  const subject =
    ctx.rules.find((r) => r.source.file === f.file && r.source.pointer === f.pointer) ??
    ctx.settings.find((s) => s.source.file === f.file && s.source.pointer === f.pointer);
  if (!subject || subject.status === 'active') return f;
  const label =
    subject.status === 'ignored'
      ? tx('この設定は実際には読み込まれません', 'This setting is not actually applied')
      : tx('この設定は他の設定に打ち消されています', 'This setting is neutralized by another setting');
  return {
    ...f,
    originalLevel: f.level,
    level: 'INFO',
    effectNote: subject.statusNote ? tx(`${label.ja}: ${subject.statusNote.ja}`, `${label.en}: ${subject.statusNote.en}`) : label,
  };
}
