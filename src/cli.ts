#!/usr/bin/env node
import { buildProgram } from './program.js';

async function main() {
  try {
    await buildProgram().parseAsync(process.argv);
  } catch (err) {
    // スタックトレースや設定値を出さず、メッセージだけを表示する
    process.stderr.write(`agentscope: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 2;
  }
}

void main();
