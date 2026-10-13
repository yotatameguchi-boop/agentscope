import { writeFileSync } from 'node:fs';
import { it } from 'vitest';
import { evaluate, report } from './evaluate.js';

// 評価結果を出力するだけのテスト（npm run eval:protect で実行。EVAL_OUT を指定するとファイルにも書く）
it('出力保護の評価', () => {
  const text = report(evaluate());
  if (process.env.EVAL_OUT) writeFileSync(process.env.EVAL_OUT, text + '\n');
  process.stdout.write('\n' + text + '\n');
});
