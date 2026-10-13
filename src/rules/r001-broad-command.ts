import { tx, type Text } from '../i18n.js';
import type { Finding, PermissionRule, RiskLevel } from '../types.js';
import { redactIfSecret } from '../util/secrets.js';
import { finding, type SecurityRule } from './types.js';

/** 引数次第で任意のコードを実行できるコマンド。許可すると実質的に全コマンドの許可に近い */
const ARBITRARY_EXEC = new Set([
  'bash', 'sh', 'zsh', 'fish', 'dash', 'ksh', 'csh', 'tcsh', 'pwsh', 'powershell', 'cmd', 'cmd.exe',
  'python', 'python3', 'python2', 'node', 'deno', 'bun', 'ruby', 'perl', 'php', 'lua', 'osascript', 'awk', 'gawk',
  'npx', 'bunx', 'pnpx', 'uvx', 'pipx', 'eval', 'exec', 'sudo', 'su', 'doas', 'env', 'xargs', 'nohup',
  'ssh', 'docker', 'podman', 'kubectl', 'make', 'source', '.',
  // 引数のコマンドをそのまま実行するラッパー
  'timeout', 'time', 'nice', 'stdbuf', 'command', 'builtin', 'noglob', 'watch', 'nix-shell',
]);

/** 2語目までで「任意のコマンド・コードを実行する」意味になる組み合わせ */
const ARBITRARY_EXEC_PAIRS = new Set([
  'npm exec', 'npm x', 'pnpm exec', 'pnpm dlx', 'yarn dlx', 'yarn exec', 'bun x', 'uv run', 'poetry run', 'pipenv run',
  'bundle exec', 'docker run', 'docker exec', 'podman run', 'podman exec', 'kubectl exec', 'kubectl run', 'devbox run',
  'direnv exec', 'mise exec', 'mise x', 'asdf exec', 'nix run', 'go run', 'cargo run', 'deno run', 'deno eval', 'git -c',
  'find -exec',
]);

/** 2語目までで、影響の大きい操作を何でも行える組み合わせ（コード実行ではない） */
const BROAD_IMPACT_PAIRS = new Set(['gh api', 'aws s3', 'kubectl delete', 'git push', 'npm publish', 'terraform apply', 'terraform destroy']);

/** 単体でも影響が大きく、引数を限定せずに許可すると広範囲になるコマンド */
const BROAD_IMPACT = new Set([
  'git', 'npm', 'pnpm', 'yarn', 'pip', 'pip3', 'uv', 'cargo', 'go', 'gh', 'curl', 'wget', 'rm', 'mv', 'cp', 'chmod',
  'chown', 'dd', 'find', 'rsync', 'scp', 'aws', 'gcloud', 'az', 'terraform', 'brew', 'apt', 'apt-get', 'dnf', 'yum',
]);

const rule = { id: 'R001', title: tx('広範囲のコマンド実行を自動承認する設定', 'Broad command execution is auto-approved') };

/**
 * 許可の「固定部分」（ワイルドカードより前の語）を取り出す。
 * - Claude Code: "npm run *" → [npm, run]、"git * main" → [git]、"ls:*" → [ls]
 * - Cursor（前方一致）: "git" → [git]、"npm:install*" → [npm, install]
 */
function fixedWords(spec: string, prefixMatch: boolean): { words: string[]; open: boolean } {
  let s = spec.trim();
  let open = prefixMatch; // 前方一致なら、書かれた語の後ろに何でも続けられる
  const colon = prefixMatch ? /^([^\s:]+):(.*)$/.exec(s) : null;
  if (colon) s = `${colon[1]} ${colon[2]}`; // Cursor の "base:args-glob" 形式
  s = s.replace(/:\*$/, ' *');
  const star = s.indexOf('*');
  if (star !== -1) {
    open = true;
    // * より前の文字は固定部分。"curl*" は [curl]、"npm install*" は [npm, install]、"python3 *.py" は [python3]
    s = s.slice(0, star);
  }
  const words = s.trim().split(/\s+/).filter(Boolean);
  if (words[0]) words[0] = words[0].replace(/\\/g, '/').split('/').pop()!.replace(/\.exe$/i, '');
  return { words, open };
}

export function classifyCommand(spec: string | undefined, prefixMatch: boolean): { level: RiskLevel; reason: Text } | undefined {
  if (spec === undefined || spec.trim() === '' || spec.trim() === '*') {
    return { level: 'HIGH', reason: tx('すべてのコマンドに一致します', 'Matches every command') };
  }
  const { words, open } = fixedWords(spec, prefixMatch);
  if (!open) return undefined; // ワイルドカードのない完全一致
  if (words.length === 0) {
    return { level: 'HIGH', reason: tx('先頭がワイルドカードのため、任意のプログラムに一致します', 'The leading wildcard matches any program') };
  }
  const program = words[0]!.toLowerCase();
  const rest = words.slice(1);
  const pair = rest[0] ? `${program} ${rest[0].toLowerCase()}` : '';

  if (ARBITRARY_EXEC.has(program) && rest.every((w) => w.startsWith('-'))) {
    return {
      level: 'HIGH',
      reason: tx(
        `「${words.join(' ')}」に続けて任意の引数を渡せるため、任意のコードを実行できます`,
        `Any arguments can follow "${words.join(' ')}", so arbitrary code can be run`,
      ),
    };
  }
  if (rest.length === 1 && ARBITRARY_EXEC_PAIRS.has(pair)) {
    return {
      level: 'HIGH',
      reason: tx(
        `「${words.join(' ')}」は引数のコマンドやパッケージをそのまま実行するため、任意のコードを実行できます`,
        `"${words.join(' ')}" runs whatever command or package follows, so arbitrary code can be run`,
      ),
    };
  }
  if (rest.length === 1 && BROAD_IMPACT_PAIRS.has(pair)) {
    return {
      level: 'MEDIUM',
      reason: tx(`「${words.join(' ')}」に続く操作を何でも承認なしで実行できます`, `Any operation following "${words.join(' ')}" can run without approval`),
    };
  }
  if (rest.length === 0 && BROAD_IMPACT.has(program)) {
    return {
      level: 'MEDIUM',
      reason: tx(`「${program}」のすべてのサブコマンド・引数を承認なしで実行できます`, `Every subcommand and argument of "${program}" can run without approval`),
    };
  }
  return undefined;
}

function check(r: PermissionRule): { level: RiskLevel; reason: Text } | undefined {
  if (r.effect !== 'allow' || r.category !== 'command') return undefined;
  // Claude Code はワイルドカードの位置で判定し、Cursor（terminalAllowlist / CLI の Shell）は前方一致で判定する
  return classifyCommand(r.specifier, r.agent === 'cursor');
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
                  '許可リストには「git status」のようにサブコマンドまで含めた具体的なコマンドを指定してください。',
                  'Allow specific commands that include the subcommand, such as "git status".',
                ),
        }),
      );
    }
    return out;
  },
};
