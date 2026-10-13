import { Command, Option } from 'commander';
import { z } from 'zod';
import { renderJson } from './report/json.js';
import { renderTerminal } from './report/terminal.js';
import { scan } from './scan.js';
import type { AgentId } from './types.js';
import { VERSION } from './version.js';

const AGENT_MAP: Record<'claude' | 'cursor' | 'all', AgentId[]> = {
  claude: ['claude-code'],
  cursor: ['cursor'],
  all: ['claude-code', 'cursor'],
};

const ScanCliOptions = z.object({
  agent: z.enum(['claude', 'cursor', 'all']),
  format: z.enum(['text', 'json']),
  includeGlobal: z.boolean(),
  color: z.boolean(),
});

export interface ProgramIO {
  write: (s: string) => void;
  isTTY: boolean;
}

const defaultIO: ProgramIO = {
  write: (s) => void process.stdout.write(s),
  isTTY: process.stdout.isTTY === true,
};

export function buildProgram(io: ProgramIO = defaultIO): Command {
  const program = new Command();
  program
    .name('agentscope')
    .description('AIエージェント（Claude Code / Cursor）の権限設定を静的に分析し、リスクを表示します。\n設定ファイルは読み取るだけで、変更・実行・外部送信は行いません。')
    .version(VERSION, '-v, --version', 'バージョンを表示する')
    .helpOption('-h, --help', 'ヘルプを表示する')
    .helpCommand('help [command]', 'コマンドのヘルプを表示する')
    .showHelpAfterError();

  program
    .command('scan')
    .description('設定ファイルを分析する')
    .argument('[dir]', '分析するディレクトリ', '.')
    .addOption(new Option('-a, --agent <agent>', '対象エージェント').choices(['claude', 'cursor', 'all']).default('all'))
    .addOption(new Option('-f, --format <format>', '出力形式').choices(['text', 'json']).default('text'))
    .option('-g, --include-global', 'ユーザー単位の設定（~/.claude, ~/.claude.json の MCP 設定, ~/.cursor）も分析する', false)
    .option('--no-color', '色を付けずに表示する')
    .helpOption('-h, --help', 'ヘルプを表示する')
    .action(async (dir: string, raw: unknown) => {
      const opts = ScanCliOptions.parse(raw);
      const result = await scan({ root: dir, agents: AGENT_MAP[opts.agent], includeGlobal: opts.includeGlobal });
      if (opts.format === 'json') {
        io.write(renderJson(result));
      } else {
        const color = opts.color && io.isTTY && !process.env.NO_COLOR;
        io.write(renderTerminal(result, { color }));
      }
    });

  return program;
}
