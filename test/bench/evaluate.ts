import { maskSecrets } from '../../src/util/protect.js';
import { negatives, PLACEMENTS, secrets } from './corpus.js';

export interface EvalResult {
  /** 秘密情報のうち、出力から消えた割合（置き場所ごと・形式ごと） */
  recall: { total: number; masked: number; byKind: Map<string, [number, number]>; byPlacement: Map<string, [number, number]>; misses: string[] };
  /** 無害な文字列のうち、変更されなかった割合 */
  precision: { total: number; kept: number; falsePositives: Array<{ kind: string; before: string; after: string }> };
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
  const falsePositives: Array<{ kind: string; before: string; after: string }> = [];
  let ntotal = 0;
  let kept = 0;
  for (const seed of [2, 9, 77]) {
    for (const neg of negatives(seed)) {
      const out = mask(neg.text);
      ntotal++;
      if (out === neg.text) kept++;
      else if (seed === 2) falsePositives.push({ kind: neg.kind, before: neg.text, after: out });
    }
  }
  return { recall: { total, masked, byKind, byPlacement, misses }, precision: { total: ntotal, kept, falsePositives } };
}

export function report(r: EvalResult): string {
  const pct = (a: number, b: number) => `${((a / b) * 100).toFixed(1)}%`;
  const lines = [
    `recall    ${pct(r.recall.masked, r.recall.total)} (${r.recall.masked}/${r.recall.total})`,
    `precision ${pct(r.precision.kept, r.precision.total)} (${r.precision.kept}/${r.precision.total} benign strings unchanged)`,
    '',
    'recall by kind:',
    ...[...r.recall.byKind].map(([k, [m, t]]) => `  ${k.padEnd(24)} ${pct(m, t).padStart(6)}`),
    '',
    'recall by placement:',
    ...[...r.recall.byPlacement].map(([k, [m, t]]) => `  ${k.padEnd(24)} ${pct(m, t).padStart(6)}`),
    '',
    `false positives (${r.precision.falsePositives.length}):`,
    ...r.precision.falsePositives.map((f) => `  ${f.kind}: ${f.before}  ->  ${f.after}`),
  ];
  return lines.join('\n');
}
