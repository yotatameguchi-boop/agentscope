import { tx, type Text } from '../i18n.js';
import type { Finding, PermissionRule, RiskLevel } from '../types.js';
import { redactIfSecret } from '../util/secrets.js';
import { finding, type SecurityRule } from './types.js';

/** 引数次第で任意のコードを実行できるコマンド。許可すると実質的に全コマンドの許可に近い */
const ARBITRARY_EXEC = new Set([
  'bash', 'sh', 'zsh', 'fish', 'dash', 'ksh', 'csh', 'tcsh', 'pwsh', 'powershell', 'cmd', 'cmd.exe',
  'python', 'python3', 'python2', 'node', 'deno', 'bun', 'ruby', 'perl', 'php', 'lua', 'osascript',
  'npx', 'bunx', 'pnpx', 'uvx', 'pipx', 'eval', 'exec', 'sudo', 'su', 'doas', 'env', 'xargs', 'nohup',
  'ssh', 'docker', 'podman', 'kubectl', 'make', 'source', '.',
]);

/** 単体でも影響が大きく、引数を限定せずに許可すると広範囲になるコマンド */
const BROAD_IMPACT = new Set([
  'git', 'npm', 'pnpm', 'yarn', 'pip', 'pip3', 'uv', 'cargo', 'go', 'gh', 'curl', 'wget', 'rm', 'mv', 'cp', 'chmod',
  'chown', 'dd', 'find', 'rsync', 'scp', 'aws', 'gcloud', 'az', 'terraform', 'brew', 'apt', 'apt-get', 'dnf', 'yum',
]);

const rule = { id: 'R001', title: tx('広範囲のコマンド実行を自動承認する設定', 'Broad command execution is auto-approved') };

/** Claude Code の Bash 指定子が「プログラム名 + 何でも」かどうか */
function claudeProgramWildcard(spec: string): string | undefined {
  const m = /^(\S+?)(?:\s+\*|:\*|\*)$/.exec(spec.trim());
  return m?.[1];
}

/** Cursor の terminalAllowlist は前方一致。"git" なら git の全サブコマンド、"npm:install*" は npm install* */
function cursorProgramWildcard(entry: string): string | undefined {
  const s = entry.trim();
  const colon = /^([^\s:]+):(.*)$/.exec(s);
  if (colon) return /^\*?$/.test(colon[2]!.trim()) ? colon[1] : undefined;
  return /^\S+$/.test(s) ? s : undefined;
}

function classify(program: string): RiskLevel | undefined {
  const p = program.toLowerCase();
  if (ARBITRARY_EXEC.has(p)) return 'HIGH';
  if (BROAD_IMPACT.has(p)) return 'MEDIUM';
  return undefined;
}

function check(r: PermissionRule): { level: RiskLevel; reason: Text } | undefined {
  if (r.effect !== 'allow' || r.category !== 'command') return undefined;
  const spec = r.specifier?.trim();

  if (r.agent === 'claude-code') {
    if (spec === undefined || spec === '' || spec === '*') {
      return {
        level: 'HIGH',
        reason: tx(`${r.tool} のすべてのコマンドが承認なしで実行できます`, `Every ${r.tool} command can run without approval`),
      };
    }
    if (spec.startsWith('*')) {
      return {
        level: 'HIGH',
        reason: tx('先頭がワイルドカードのため、任意のプログラムに一致します', 'The leading wildcard matches any program'),
      };
    }
    const program = claudeProgramWildcard(spec);
    const level = program ? classify(program) : undefined;
    if (program && level) {
      return {
        level,
        reason:
          level === 'HIGH'
            ? tx(
                `「${program}」は引数次第で任意のコードを実行できるため、実質的に広範囲のコマンド実行を許可しています`,
                `"${program}" can run arbitrary code depending on its arguments, so this effectively allows broad command execution`,
              )
            : tx(`「${program}」のすべてのサブコマンド・引数を承認なしで実行できます`, `Every subcommand and argument of "${program}" can run without approval`),
      };
    }
    return undefined;
  }

  // Cursor terminalAllowlist
  if (spec === undefined || spec === '' || spec === '*') {
    return {
      level: 'HIGH',
      reason: tx('すべてのターミナルコマンドに一致する可能性があります（前方一致）', 'May match every terminal command (prefix match)'),
    };
  }
  const program = cursorProgramWildcard(spec);
  const level = program ? classify(program) : undefined;
  if (program && level) {
    return {
      level,
      reason:
        level === 'HIGH'
          ? tx(
              `前方一致で「${program}」から始まるすべてのコマンドを許可しています。${program} は任意のコードを実行できます`,
              `Every command starting with "${program}" is allowed by prefix match. ${program} can run arbitrary code`,
            )
          : tx(
              `前方一致で「${program}」から始まるすべてのコマンドを承認なしで実行できます`,
              `Every command starting with "${program}" can run without approval (prefix match)`,
            ),
    };
  }
  return undefined;
}

export const r001: SecurityRule = {
  ...rule,
  description: tx(
    'シェル全体、インタプリタ、パッケージランナーなど、任意コード実行につながるコマンドの自動承認を検出します。',
    'Detects auto-approval of commands that lead to arbitrary code execution, such as whole shells, interpreters, and package runners.',
  ),
  check(ctx) {
    const out: Finding[] = [];
    for (const r of ctx.rules) {
      const hit = check(r);
      if (!hit) continue;
      out.push(
        finding(rule, {
          level: hit.level,
          agent: r.agent,
          reason: hit.reason,
          file: r.source.file,
          pointer: r.source.pointer,
          evidence: redactIfSecret(r.raw),
          recommendation:
            r.agent === 'claude-code'
              ? tx(
                  '「Bash(npm run test *)」のようにサブコマンドまで含めた具体的なルールに置き換え、破壊的な操作は ask か deny に入れてください。',
                  'Replace it with specific rules that include the subcommand, such as "Bash(npm run test *)", and put destructive operations in ask or deny.',
                )
              : tx(
                  'terminalAllowlist には「git status」のようにサブコマンドまで含めた具体的な前方一致を指定してください。',
                  'Use specific prefixes that include the subcommand in terminalAllowlist, such as "git status".',
                ),
        }),
      );
    }
    return out;
  },
};
