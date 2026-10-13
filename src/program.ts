import { Command, Option } from 'commander';
import { z } from 'zod';
import { detectLang, LANGS, type Lang } from './i18n.js';
import { renderJson } from './report/json.js';
import { renderTerminal } from './report/terminal.js';
import { localizeResult, scan } from './scan.js';
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
  lang: z.enum(LANGS).optional(),
  launch: z.array(z.string()),
  launchFiles: z.boolean(),
});

const HELP = {
  ja: {
    program:
      'AIエージェント（Claude Code / Cursor）の権限設定を静的に分析し、リスクを表示します。\n設定ファイルは読み取るだけで、変更・実行・外部送信は行いません。',
    version: 'バージョンを表示する',
    help: 'ヘルプを表示する',
    helpCommand: 'コマンドのヘルプを表示する',
    scan: '設定ファイルを分析する',
    dir: '分析するディレクトリ',
    agent: '対象エージェント',
    format: '出力形式',
    global: 'ユーザー単位の設定（~/.claude, ~/.claude.json の MCP 設定, ~/.cursor）も分析する',
    noColor: '色を付けずに表示する',
    lang: '表示言語（既定: 環境の言語設定から判定）',
    launch: '起動コマンドを文字列で渡して、起動時のオプションも分析する（実行はしない。複数指定可）',
    noLaunchFiles: 'package.json の scripts などから起動コマンドを探さない',
  },
  en: {
    program:
      'Statically analyzes the permission settings of AI agents (Claude Code / Cursor) and reports risks.\nConfiguration files are only read: nothing is modified, executed, or sent anywhere.',
    version: 'show the version',
    help: 'show help',
    helpCommand: 'show help for a command',
    scan: 'analyze configuration files',
    dir: 'directory to analyze',
    agent: 'agent to analyze',
    format: 'output format',
    global: 'also analyze user-level settings (~/.claude, MCP settings in ~/.claude.json, ~/.cursor)',
    noColor: 'disable colors',
    lang: 'output language (default: detected from the environment locale)',
    launch: 'also analyze launch options by passing a launch command as a string (never executed; repeatable)',
    noLaunchFiles: 'do not look for launch commands in package.json scripts and similar files',
  },
} satisfies Record<Lang, Record<string, string>>;

export interface ProgramIO {
  write: (s: string) => void;
  isTTY: boolean;
}

const defaultIO: ProgramIO = {
  write: (s) => void process.stdout.write(s),
  isTTY: process.stdout.isTTY === true,
};

/**
 * ヘルプ文も選んだ言語で出すため、コマンド定義より前に argv から --lang を拾う。
 * 指定がなければ環境変数のロケールから判定する。
 */
export function pickLang(argv: readonly string[], env: NodeJS.ProcessEnv = process.env): Lang {
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const v = a.startsWith('--lang=') ? a.slice('--lang='.length) : a === '--lang' ? argv[i + 1] : undefined;
    if (v === 'ja' || v === 'en') return v;
  }
  return detectLang(env);
}

export function buildProgram(io: ProgramIO = defaultIO, lang: Lang = detectLang()): Command {
  const t = HELP[lang];
  const langOption = () => new Option('--lang <lang>', t.lang).choices([...LANGS]);
  const program = new Command();
  program
    .name('agentscope')
    .description(t.program)
    .version(VERSION, '-v, --version', t.version)
    .helpOption('-h, --help', t.help)
    .helpCommand('help [command]', t.helpCommand)
    .addOption(langOption())
    .showHelpAfterError();

  program
    .command('scan')
    .description(t.scan)
    .argument('[dir]', t.dir, '.')
    .addOption(new Option('-a, --agent <agent>', t.agent).choices(['claude', 'cursor', 'all']).default('all'))
    .addOption(new Option('-f, --format <format>', t.format).choices(['text', 'json']).default('text'))
    .option('-g, --include-global', t.global, false)
    .option('--launch <command>', t.launch, (v: string, prev: string[]) => [...prev, v], [] as string[])
    .option('--no-launch-files', t.noLaunchFiles)
    .option('--no-color', t.noColor)
    .addOption(langOption())
    .helpOption('-h, --help', t.help)
    .action(async (dir: string, raw: unknown) => {
      const opts = ScanCliOptions.parse(raw);
      const outLang = opts.lang ?? (program.opts().lang as Lang | undefined) ?? lang;
      const result = localizeResult(
        await scan({
          root: dir,
          agents: AGENT_MAP[opts.agent],
          includeGlobal: opts.includeGlobal,
          launch: opts.launch,
          launchFiles: opts.launchFiles,
        }),
        outLang,
      );
      if (opts.format === 'json') {
        io.write(renderJson(result));
      } else {
        const color = opts.color && io.isTTY && !process.env.NO_COLOR;
        io.write(renderTerminal(result, { color }));
      }
    });

  return program;
}
