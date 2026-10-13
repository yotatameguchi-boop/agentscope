#!/usr/bin/env node
import { buildProgram, pickLang } from './program.js';
import { AgentScopeError } from './scan.js';

async function main() {
  const lang = pickLang(process.argv.slice(2));
  try {
    await buildProgram(undefined, lang).parseAsync(process.argv);
  } catch (err) {
    // スタックトレースや設定値を出さず、メッセージだけを表示する
    const message = err instanceof AgentScopeError ? err.text[lang] : err instanceof Error ? err.message : String(err);
    process.stderr.write(`agentscope: ${message}\n`);
    process.exitCode = 2;
  }
}

void main();
