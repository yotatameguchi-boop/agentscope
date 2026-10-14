import { maskSecrets } from '../../src/util/protect.js';
import { PLACEMENTS, secrets } from './corpus.js';
import { negativeSet, type Tier } from './negatives.js';

export interface EvalResult {
  /** 秘密情報のうち、出力から消えた割合（置き場所ごと・形式ごと） */
  recall: { total: number; masked: number; byKind: Map<string, [number, number]>; byPlacement: Map<string, [number, number]>; misses: string[] };
  /** 無害な文字列のうち、変更されなかった割合（tier ごと・グループごと） */
  precision: {
    total: number;
    kept: number;
    byTier: Map<Tier, [number, number]>;
    byGroup: Map<string, [number, number]>;
    falsePositives: Array<{ kind: string; tier: Tier; before: string; after: string }>;
  };
}

/** 秘密情報が「漏れた」とみなす条件: 値そのもの、または値の 8 文字以上の断片が出力に残っている */
function leaked(rawOutput: string, value: string): boolean {
  // 見えない文字を取り除いた形で判定する（見えない文字を挟んでも、読めば値が分かるため）
  const output = rawOutput.replace(/[\u200b-\u200d\u2060\ufeff]/g, '');
  if (output.includes(value)) return true;
  if (value.length < 16) return false;
  // 一部だけ伏せても、残りの断片から値を推測できるなら漏れとみなす（半分以上が残っている）
  const half = Math.ceil(value.length / 2);
  for (let i = 0; i + half <= value.length; i++) if (output.includes(value.slice(i, i + half))) return true;
  return false;
}

export function evaluate(mask: (s: string) => string = maskSecrets): EvalResult {
  const byKind = new Map<string, [number, number]>();
  const byPlacement = new Map<string, [number, number]>();
  const misses: string[] = [];
  let total = 0;
  let masked = 0;
  for (const seed of [1, 7, 42]) {
    for (const secret of secrets(seed)) {
      for (const p of PLACEMENTS) {
        const input = p.render(secret);
        const out = mask(input);
        const ok = !leaked(out, secret.value);
        total++;
        if (ok) masked++;
        const k = byKind.get(secret.kind) ?? [0, 0];
        byKind.set(secret.kind, [k[0] + (ok ? 1 : 0), k[1] + 1]);
        const q = byPlacement.get(p.name) ?? [0, 0];
        byPlacement.set(p.name, [q[0] + (ok ? 1 : 0), q[1] + 1]);
        if (!ok && seed === 1) misses.push(`${secret.kind} @ ${p.name}`);
      }
    }
  }
  const falsePositives: Array<{ kind: string; tier: Tier; before: string; after: string }> = [];
  const byTier = new Map<Tier, [number, number]>();
  const byGroup = new Map<string, [number, number]>();
  let ntotal = 0;
  let kept = 0;
  const seen = new Set<string>();
  for (let seed = 1; seed <= 20; seed++) {
    for (const neg of negativeSet(seed)) {
      const out = mask(neg.text);
      const ok = out === neg.text;
      ntotal++;
      if (ok) kept++;
      const t = byTier.get(neg.tier) ?? [0, 0];
      byTier.set(neg.tier, [t[0] + (ok ? 1 : 0), t[1] + 1]);
      const g = byGroup.get(neg.group) ?? [0, 0];
      byGroup.set(neg.group, [g[0] + (ok ? 1 : 0), g[1] + 1]);
      if (!ok && !seen.has(neg.kind)) {
        seen.add(neg.kind);
        falsePositives.push({ kind: neg.kind, tier: neg.tier, before: neg.text, after: out });
      }
    }
  }
  return { recall: { total, masked, byKind, byPlacement, misses }, precision: { total: ntotal, kept, byTier, byGroup, falsePositives } };
}

export function report(r: EvalResult): string {
  const pct = (a: number, b: number) => `${((a / b) * 100).toFixed(1)}%`;
  const lines = [
    `recall    ${pct(r.recall.masked, r.recall.total)} (${r.recall.masked}/${r.recall.total})`,
    `precision ${pct(r.precision.kept, r.precision.total)} (${r.precision.kept}/${r.precision.total} benign strings unchanged)`,
    ...[...r.precision.byTier].map(([t, [k, n]]) => `  ${t.padEnd(10)} ${pct(k, n)} (${k}/${n})`),
    '',
    'precision by group:',
    ...[...r.precision.byGroup].map(([g, [k, n]]) => `  ${g.padEnd(24)} ${pct(k, n).padStart(6)}`),
    '',
    'recall by kind:',
    ...[...r.recall.byKind].map(([k, [m, t]]) => `  ${k.padEnd(24)} ${pct(m, t).padStart(6)}`),
    '',
    'recall by placement:',
    ...[...r.recall.byPlacement].map(([k, [m, t]]) => `  ${k.padEnd(24)} ${pct(m, t).padStart(6)}`),
    '',
    `false positives (${r.precision.falsePositives.length}):`,
    ...r.precision.falsePositives.map((f) => `  [${f.tier}] ${f.kind}: ${f.before.slice(0, 160)}  ->  ${f.after.slice(0, 160)}`),
  ];
  return lines.join('\n');
}
