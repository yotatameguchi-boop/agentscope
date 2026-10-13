#!/usr/bin/env node
import { CommanderError } from 'commander';
import { tx } from './i18n.js';
import { buildProgram, pickLang } from './program.js';
import { AgentScopeError } from './scan.js';
import { maskSecrets } from './util/protect.js';

/** 終了コード: 0 = 分析完了（検出の有無によらない）、2 = エラー */
const EXIT_ERROR = 2;

// `agentscope scan | head` のように読み手が先に終わっても、スタックトレースを出さずに終える
process.stdout.on('error', (err: NodeJS.ErrnoException) => {
  if (err.code === 'EPIPE') process.exit(0);
  throw err;
});

async function main() {
  const lang = pickLang(process.argv.slice(2));
  const program = buildProgram(undefined, lang);
  // Commander の既定（process.exit(1)）ではなく、終了コードをここでそろえる
  program.exitOverride();
  for (const c of program.commands) c.exitOverride();
  try {
    await program.parseAsync(process.argv);
  } catch (err) {
    if (err instanceof CommanderError) {
      // ヘルプ・バージョン表示は正常終了。それ以外（不正なオプションなど）はメッセージ表示済み
      const ok = err.code === 'commander.helpDisplayed' || err.code === 'commander.version' || err.code === 'commander.help';
      process.exitCode = ok ? 0 : EXIT_ERROR;
      return;
    }
    // スタックトレースや設定値を出さず、メッセージだけを表示する
    const message =
      err instanceof AgentScopeError
        ? err.text[lang]
        : tx('予期しないエラーが発生しました', 'An unexpected error occurred')[lang] + (err instanceof Error ? `: ${err.message}` : '');
    process.stderr.write(`agentscope: ${maskSecrets(message)}\n`);
    process.exitCode = EXIT_ERROR;
  }
}

void main();
