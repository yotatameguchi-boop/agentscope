# AgentScope

English | [日本語](README.ja.md)

A CLI that **statically analyzes the permission settings of AI coding agents (Claude Code / Cursor) and surfaces security risks**.

It only reads configuration files. It never starts the agent or any MCP server, never runs configured commands, and never sends anything over the network.

- What is allowed, denied, or requires approval
- Configured MCP servers (name, transport, command name, host, environment variable names)
- Risky permission settings (five rule-based checks)
- An explicit list of what could not be analyzed

> v0.1 is an MVP. It shows the permissions **written** in configuration files, not the permissions that can **actually be exercised** (see [Limitations](#limitations)).

## Requirements

- Node.js 22.12 or later
- macOS / Linux / Windows

## Installation

AgentScope is not published to npm yet. Build it from source:

```bash
git clone https://github.com/yotatameguchi-boop/agentscope.git
cd agentscope
npm install
npm run build
npm link   # optional: makes the agentscope command available
```

Without `npm link`, run it with `node dist/cli.js`.

## Usage

```bash
agentscope scan                    # analyze the current directory
agentscope scan path/to/project    # analyze another directory
agentscope scan --agent claude     # Claude Code settings only
agentscope scan --agent cursor     # Cursor settings only
agentscope scan --format json      # JSON output
agentscope scan --include-global   # also analyze user-level settings
agentscope scan --lang en          # English output
agentscope scan --launch "claude -p --dangerously-skip-permissions"   # also analyze a launch command (never executed)
agentscope scan --include-env      # also analyze environment variables of the current shell
agentscope --help
```

| Option | Description | Default |
| --- | --- | --- |
| `-a, --agent <claude\|cursor\|all>` | Agent to analyze | `all` |
| `-f, --format <text\|json>` | Output format | `text` |
| `-g, --include-global` | Also read user-level settings in the home directory | off |
| `--no-color` | Disable colors (`NO_COLOR` also works) | colored on a TTY |
| `--lang <ja\|en>` | Language of the report, JSON, and help | detected |
| `--launch <command>` | A launch command to analyze for launch options. It is parsed as a string and never executed. Repeatable | none |
| `--no-launch-files` | Do not look for launch commands and environment variables in project files (see [Launch options](#launch-options)) | look |
| `-e, --include-env` | Also analyze environment variables of the current shell (see [Environment variables](#environment-variables)) | off |

The output language is chosen from `--lang`, then `AGENTSCOPE_LANG`, then `LC_ALL` / `LC_MESSAGES` / `LANG`. A Japanese locale selects Japanese; anything else selects English.

The exit code is `0` when the analysis completes (whether or not anything was found, and also for `--help` / `--version`) and `2` on errors such as an invalid option, a missing target directory, or a target that is not a directory.

### Example output

An excerpt from analyzing `test/fixtures/risky-project` (dummy settings used by the tests):

```text
AgentScope Security Report (v0.1.0)
Agents: Claude Code, Cursor
Config files: 6  Permission rules: 29  MCP servers: 4  Launch commands: 0  Findings: HIGH 6 / MEDIUM 13 / LOW 0 / INFO 5

■ Security findings
  [HIGH] R001 Broad command execution is auto-approved  (Claude Code)
      Reason: "python3" can run arbitrary code depending on its arguments, so this effectively allows broad command execution
      Location: .claude/settings.json  permissions.allow[1]
      Setting: Bash(python3 *)
      Fix: Replace it with specific rules that include the subcommand, such as "Bash(npm run test *)", and put destructive operations in ask or deny.
  [MEDIUM] R004 Credential-like strings are written directly in a config file  (Claude Code)
      Reason: Key "MY_SERVICE_PASSWORD" holds a literal value rather than a reference such as ${VAR}; it may be a credential (value not shown).
      Location: .claude/settings.local.json  env.MY_SERVICE_PASSWORD
      Setting: env.MY_SERVICE_PASSWORD: [REDACTED]
  [INFO] I001 The actual tool list of MCP servers is not verified  (Claude Code)
  ...
```

## What is analyzed

Missing files are skipped without error. AgentScope does not walk directories; it only looks at the locations below.

| Agent | File | Scope | Default | Contents |
| --- | --- | --- | --- | --- |
| Claude Code | `.claude/settings.json` | project, shared | yes | permission rules, permission mode, MCP approval, sandbox, etc. |
| Claude Code | `.claude/settings.local.json` | project, personal | yes | same as above |
| Claude Code | `.mcp.json` | project, shared | yes | MCP server definitions |
| Claude Code | `~/.claude/settings.json` | user-wide | `-g` | permission rules, etc. |
| Claude Code | `~/.claude.json` | user-wide / project, personal | `-g` | **MCP-related parts only**: top-level `mcpServers`, and `mcpServers` / `enabledMcpjsonServers` / `disabledMcpjsonServers` in the `projects[...]` entry for the target directory. Other keys are skipped and never listed |
| Cursor | `.cursor/mcp.json` | project, shared | yes | MCP server definitions |
| Cursor | `.cursor/permissions.json` | project, shared | yes | `mcpAllowlist` / `terminalAllowlist` / `autoRun` |
| Cursor | `~/.cursor/mcp.json` | user-wide | `-g` | MCP server definitions |
| Cursor | `~/.cursor/permissions.json` | user-wide | `-g` | same as above |
| Cursor | `.cursor/cli.json` | project, shared | yes | Cursor CLI `permissions.allow` / `deny` (`Shell` / `Read` / `Write` / `WebFetch` / `Mcp`) |
| Cursor | `~/.cursor/cli-config.json` | user-wide | `-g` | same as above (other CLI preferences are skipped) |
| Claude Code | `~/.claude/remote-settings.json` (local cache of server-managed settings), the macOS configuration profile `/Library/Managed Preferences/[<user>/]com.anthropic.claudecode.plist` (XML or binary, read without `plutil`) | organization-managed | `-g` | see [Organization-managed settings](#organization-managed-settings) |
| Claude Code | `managed-settings.json`, `managed-settings.d/*.json`, `managed-mcp.json` | organization-managed | `-g` | in `/Library/Application Support/ClaudeCode/` (macOS), `/etc/claude-code/` (Linux / WSL), `C:\Program Files\ClaudeCode\` (Windows). Highest precedence. As in Claude Code, `managed-settings.json` is merged first and then `managed-settings.d/*.json` in name order (hidden files skipped): single values from a later file win, lists are combined, and `env` / `sandbox` merge key by key |

Both JSON and JSONC (comments, trailing commas) are supported.

### Launch options

Launch options such as `claude --dangerously-skip-permissions` or `agent --force` change permissions for that run only. AgentScope reads launch commands as text (it never runs them) from:

| Where | When |
| --- | --- |
| `--launch "<command>"` | always |
| `package.json` `scripts` | by default (`--no-launch-files` turns this off) |
| `.vscode/tasks.json`, `.devcontainer/devcontainer.json` / `.devcontainer.json` lifecycle commands | by default |
| `Makefile`, `justfile` | by default |
| `.github/workflows/*.yml` `run:` lines and the `claude_args:` input of `anthropics/claude-code-action` | by default |
| `~/.zshrc`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zprofile`, `~/.config/fish/config.fish` (aliases and commands) | with `-g` |

Option parsing stops at `--`; anything after it is treated as a positional argument. Recognized invocations are `claude`, `npx @anthropic-ai/claude-code`, `agent`, and `cursor-agent`, also behind `env`, `exec`, `timeout`, and leading `VAR=value` assignments.

| Agent | Options analyzed |
| --- | --- |
| Claude Code | `--permission-mode`, `--dangerously-skip-permissions`, `--allow-dangerously-skip-permissions`, `--allowedTools`, `--disallowedTools`, `--add-dir`, `--settings` (inline JSON or a file inside the target directory), `--mcp-config` (same), `--tools`, `--setting-sources`, `--strict-mcp-config`, `--bare`, `--safe-mode`, `--restricted` |
| Cursor (`agent`) | `--force` / `--yolo`, `--approve-mcps`, `--sandbox`, `--trust`, `--api-key` (value never shown) |

Launch options are treated as a separate scope, `cli`:

- They apply only to that launch, so they never mark values in settings files as overridden
- Deny and ask rules in settings files still neutralize `--allowedTools`; `--disallowedTools` neutralizes only rules of the same launch
- `disableBypassPermissionsMode: "disable"` in settings, or `--restricted` in the same launch, makes `--dangerously-skip-permissions` ineffective
- Secrets in launch commands (`ANTHROPIC_API_KEY=...`, `--api-key ...`) are reported by R004 and never printed

### Environment variables

Some environment variables turn off safety checks or change where data is sent. AgentScope looks only at the variables in [src/env/catalog.ts](src/env/catalog.ts) and ignores all others.

| Where | When |
| --- | --- |
| `env` block of Claude Code settings files | always |
| `VAR=value` in front of a launch command | always |
| `containerEnv` / `remoteEnv` in `.devcontainer`, `env:` in `.github/workflows/*.yml` | by default (`--no-launch-files` turns this off) |
| `export` / `set -x` in shell startup files (`~/.zshrc`, etc.) | with `-g` |
| the environment of the shell running AgentScope | with `-e` / `--include-env` |

| Variables | What is checked |
| --- | --- |
| `NODE_TLS_REJECT_UNAUTHORIZED=0` | TLS certificate verification turned off (HIGH) |
| `CLAUDE_CODE_DISABLE_INLINE_SHELL_RM_PROMPT`, `CLAUDE_CODE_DISABLE_SUBSTITUTION_RM_PROMPT`, `CLAUDE_CODE_DISABLE_POWERSHELL_CMD_RM_DENY`, `CLAUDE_CODE_DISABLE_DANGEROUS_RM_TIMEOUT` | removal safety checks turned off (MEDIUM / LOW) |
| `NODE_OPTIONS` with `--require` / `--import` | extra code loaded into every Node.js process (MEDIUM) |
| `ANTHROPIC_BASE_URL` and the other `*_BASE_URL` variables | endpoint changed in a shared file, or plain http (MEDIUM); otherwise INFO. The official `https://api.anthropic.com` is not reported |
| `CLAUDE_CONFIG_DIR`, `NODE_EXTRA_CA_CERTS` | INFO |
| `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CURSOR_API_KEY`, and other credentials | only whether they are set. A literal value written in a file is reported by R004 |

- Values are never shown for credentials, and only the scheme and host are kept for URLs
- Following the official docs, variables that Claude Code ignores in a settings `env` block (such as `CLAUDE_CODE_DISABLE_INLINE_SHELL_RM_PROMPT`) or in project / local settings (such as `CLAUDE_CONFIG_DIR`) are marked `ignored`
- Across settings files, each `env` key follows the usual precedence (managed > local > project > user). Values from the shell are not treated as overridden, because whether the settings value wins depends on the session
- Values from the running environment are not reported by R004, because they are not written in a file

### How the two permission models are handled

Both agents' settings are converted into a common format (`PermissionRule`), while the differences are kept in `nativeKind` and `note`.

| | Claude Code | Cursor (IDE) | Cursor CLI |
| --- | --- | --- | --- |
| Allow | `permissions.allow` | `mcpAllowlist`, `terminalAllowlist` (prefix match; replaces the IDE allowlist) | `permissions.allow` |
| Ask | `permissions.ask` | (none) | (none) |
| Deny | `permissions.deny` | (none) | `permissions.deny` (wins over allow) |
| Hints | (none) | `autoRun.allow_instructions` / `block_instructions` (non-binding hints for a classifier; kept apart as `guidance-allow` / `guidance-block`) | (none) |

### Organization-managed settings

Claude Code reads managed settings from several sources, ranked server-managed > MDM (macOS configuration profile / Windows HKLM registry) > files. By default (`"first-wins"`), only the highest-ranked source that has a policy key is used; with `managedSourcesBehavior: "merge"` in the top source, every source is used and higher-ranked values win. AgentScope follows the same rules:

- Rules and settings from sources that are not used are marked `ignored`. Keys that Claude Code reads from every admin source (`env` per variable, `allowManagedMcpServersOnly`, `deniedMcpServers`, `disableClaudeAiConnectors`, `sandbox.filesystem.disabled`, `forceRemoteSettingsRefresh`) are kept
- R008 reports a managed file that is not strict JSON (comments, trailing commas, syntax errors, a non-object top level) or a malformed profile, because Claude Code refuses to start in that state (LOW). An empty file counts as `{}`. A managed file that the OS does not let the current user read is reported as MEDIUM, because sessions of that user start without the policy
- I004 lists the sources found, the one in effect, and what could not be checked

### Precedence and effectiveness

A rule written in a file is not always in effect. Every rule and setting carries a `status`:

| status | Meaning | Examples |
| --- | --- | --- |
| `active` | in effect | |
| `ignored` | the agent does not load it | `mcp__x(...)` with parentheses, an allow rule with a wildcard in the tool name (`B*`), `Write(path)`, `Bash(command:...)`, a key placed where it cannot be set (`skipDangerousModePermissionPrompt` in project settings), a mode disabled by `disableBypassPermissionsMode: "disable"`, non-managed rules under `allowManagedPermissionRulesOnly` |
| `overridden` | neutralized by another setting | an allow rule fully covered by a deny / ask rule (deny → ask → allow), a single-value key overridden by a higher scope (managed > local > project > user) |

Findings whose underlying setting is not `active` are lowered to INFO, with the original level (`originalLevel`) and the reason (`effectNote`). They are kept rather than dropped because they become effective again if the other setting changes.

Only cases that are certain are treated as neutralized. When a deny rule covers just part of an allow rule (for example allow `Bash` and deny `Bash(rm *)`), the allow rule stays `active`, so AgentScope never under-reports by guessing.

## Checks

| ID | What it detects | Main levels |
| --- | --- | --- |
| R001 | Broad command execution is auto-approved (`Bash`, `Bash(python3 *)`, `Bash(python3 -c *)`, `Bash(npm exec *)`, `Bash(timeout *)`, `bash` in Cursor, Cursor CLI `Shell(*)`, etc.) | HIGH / MEDIUM |
| R002 | All MCP tools are auto-approved (`mcp__server`, `*:*`, `enableAllProjectMcpServers`, etc.) | HIGH / MEDIUM / INFO |
| R003 | Permission checks are significantly relaxed (`defaultMode: bypassPermissions`, `skipDangerousModePermissionPrompt`, etc.) | HIGH / MEDIUM / LOW |
| R004 | Credential-like strings written directly (known token formats, key names, credentials in URLs) | HIGH / MEDIUM |
| R005 | Broad file access is allowed (`Edit` without a path, `Read(~/**)`, edits to `.claude/**`, `.github/workflows/**`, reading `~/.aws`, etc.) | HIGH / MEDIUM / LOW |
| R006 | Network access to any destination is allowed (`WebFetch`, `WebFetch(domain:*)`, `"*"` in `sandbox.network.allowedDomains`, Cursor CLI `WebFetch(*)`) | MEDIUM |
| R007 | Environment variables that turn off safety checks or change the API endpoint (see [Environment variables](#environment-variables)) | HIGH / MEDIUM / LOW / INFO |
| R008 | Organization-managed settings are not applied correctly (Claude Code refuses to start, or the policy cannot be read) | MEDIUM / LOW |
| I001 | States that the actual tool list of MCP servers is not verified | INFO |
| I002 | States that Cursor IDE settings (such as Run Mode) are not verified | INFO |
| I003 | States that automatically executed commands are configured (hooks, `statusLine`, `apiKeyHelper`, etc.); their contents are not shown | INFO |
| I004 | Lists organization-managed settings sources found and in effect, and what could not be checked (with `-g`) | INFO |

Every finding has a rule ID, risk level, reason, source file, setting location (a JSON path), and a recommended fix. Levels come from fixed rules, never from guesses.

## Safety

- Read-only. Files are opened with `O_RDONLY`, and the source never calls write APIs (enforced by a test)
- Never starts or runs agents, MCP servers, or configured commands
- No network access (a test checks that modules such as `http`, `net`, and `child_process` are never imported)
- Never prints credential values, any part of them, or their length. For MCP servers, only the executable name, the URL host name, and the **names** of environment variables and headers are kept; arguments and values are dropped. Permission rules that contain secrets (including `API_KEY=...`, `--token ...`, `curl -u user:pass`) are replaced with `[REDACTED]`, and so are key names, server names, and other names that look like secrets
- Detection and output protection are separate. Whatever path a value came in through (settings, launch options, environment variables, findings, notes), the whole result goes through a final masking step right before it is returned, which replaces known secret formats, URL credentials, and secret-looking `key=value` / `--flag value` pairs with `[REDACTED]`
- Values that detection judged to be secrets (including values without a known format, such as an env value under a `*_TOKEN` key) are kept in memory for the duration of one scan only, and any other occurrence of the same value anywhere in the output is masked too. Long, high-entropy tokens that mix upper case, lower case, and digits are also masked; hex hashes, UUIDs, and human-made names (camelCase or hyphenated words) are left alone
- How output protection was measured and tuned (recall and precision on a test corpus, real-world false positives, ReDoS checks) is recorded in [docs/output-protection.md](docs/output-protection.md) (Japanese)
- `${VAR}` is treated as a reference, but `${VAR:-value}` contains a literal default value, so the default is checked like a value written directly
- Before printing to the terminal, control characters (ANSI escapes, newlines) and bidirectional / invisible characters from config files are escaped, so a config file cannot rewrite or disguise the report
- Symbolic links are resolved first, and project settings that point outside the target directory are not read. Non-regular files (FIFOs, etc.), files over 20 MB, and JSON nested deeper than 256 levels are not read either
- Objects are built without a prototype, so a `"__proto__"` key cannot make unwritten keys appear. If parsing one file fails unexpectedly, the other files are still analyzed
- The home directory is never walked. Even with `--include-global`, only the fixed files listed above are read

## Limitations

- **Permissions written in configuration files are not the same as the permissions that can actually be exercised.** The following are not analyzed:
  - The Windows registry (`HKLM` / `HKCU` `SOFTWARE\Policies\ClaudeCode`), because reading it requires running an external command or a native module; the latest server-managed payload (only the local cache is read, and AgentScope never uses the network); Cursor team admin settings
  - Launch options and environment variables that are not found in the locations above (for example typed directly in a terminal) unless you pass them with `--launch` or `--include-env`; environment variables outside the catalog
  - Cursor IDE settings (Run Mode, allowlists registered in the settings UI)
  - The tools MCP servers actually provide, and what they can reach
  - The contents of plugins, hooks, `apiKeyHelper`, and other commands
- Precedence is resolved only for certain cases (see [Precedence and effectiveness](#precedence-and-effectiveness)). Partial overlaps between rules, and command-line flags, are not taken into account
- No findings does not mean the setup is safe. Unknown settings and items that could not be analyzed are listed under "Items not analyzed"
- Credential detection is based on patterns and key names, so it can miss things and report false positives
- The rules follow each agent's official documentation as of October 2026:
  - Claude Code: [Settings](https://code.claude.com/docs/en/settings) / [Permissions](https://code.claude.com/docs/en/permissions)
  - Cursor: [permissions.json Reference](https://cursor.com/docs/reference/permissions) / [MCP](https://cursor.com/docs/context/mcp)

## JSON output

`--format json` prints the following structure (types are in [src/types.ts](src/types.ts)). Human-readable strings are in the language chosen by `--lang`, which is recorded in `lang`.

```jsonc
{
  "tool": { "name": "agentscope", "version": "0.1.0" },
  "lang": "en",
  "target": "/path/to/project",
  "agents": ["claude-code", "cursor"],
  "includeGlobal": false,
  "files": [{ "agent": "claude-code", "kind": "claude-settings", "scope": "project", "displayPath": ".claude/settings.json", "status": "parsed", ... }],
  "rules": [{ "agent": "claude-code", "effect": "allow", "category": "command", "tool": "Bash", "specifier": "python3 *", "nativeKind": "claude.permissions.allow", "source": { "file": ".claude/settings.json", "pointer": "permissions.allow[1]" }, "status": "active", ... }],
  "settings": [{ "key": "permissions.defaultMode", "value": "bypassPermissions", ... }],
  "mcpServers": [{ "name": "github", "transport": "stdio", "commandName": "npx", "envNames": ["GITHUB_TOKEN"], "approval": "approved", "toolPermissions": "unknown", ... }],
  "launches": [{ "agent": "claude-code", "executable": "claude", "source": { "file": "package.json", "pointer": "scripts.ai" }, "options": [{ "flag": "--dangerously-skip-permissions" }], ... }],
  "findings": [{ "ruleId": "R001", "level": "HIGH", "title": "...", "reason": "...", "file": "...", "pointer": "...", "evidence": "...", "recommendation": "...", "originalLevel": "HIGH (only when lowered)", "effectNote": "..." }],
  "unparsed": [{ "file": ".claude/settings.json", "pointer": "hooks", "reason": "..." }],
  "summary": { "files": 3, "rules": 12, "mcpServers": 3, "launches": 1, "findings": { "HIGH": 1, "MEDIUM": 2, "LOW": 0, "INFO": 1 } },
  "disclaimer": "..."
}
```

## Development

```bash
npm install
npm test           # Vitest
npm run typecheck
npm run build      # outputs to dist/
npm run e2e        # runs the built CLI: exit codes and closed pipes
node dist/cli.js scan test/fixtures/risky-project --lang en
```

Tests use only fake settings. Token-shaped dummy values are assembled at runtime so that repository secret scanners do not flag them ([test/helpers.ts](test/helpers.ts)).

### Layout

```
src/
  cli.ts / program.ts      CLI (Commander.js)
  scan.ts                  discovery → parsing → normalization → checks
  discovery/discover.ts    Config Discovery: lists candidate locations
  parsers/claude.ts        Claude Code parser
  parsers/cursor.ts        Cursor parser
  parsers/common.ts        shared logic such as MCP server definitions
  rules/r00x-*.ts          Security Rule Engine: one check per file
  report/terminal.ts|json.ts  Report Generator
  util/safeRead.ts         read-only file access with symlink protection
  precedence.ts            precedence across files and rule effectiveness
  util/secrets.ts          credential detection and redaction
  util/pointer.ts          JSON paths for display (redacts secret-looking keys)
  types.ts                 common data model
  i18n.ts                  Japanese / English messages
```

### Adding a check

1. Add a file under `src/rules/` that implements `SecurityRule` (`id` / `title` / `description` / `check`)
2. Register it in `SECURITY_RULES` in `src/rules/index.ts`
3. Add examples that should and should not match to `test/rules.test.ts`

`check` receives the rules, settings, and MCP servers of every agent in the common format. Never put secrets in `evidence`.

User-facing strings (`title` / `description` / `reason` / `recommendation`) are written in both languages with `tx('日本語', 'English')`; the language is chosen right before output. `test/i18n.test.ts` catches missing English translations and Japanese leaking into English output.

### Adding an agent

1. Add it to `AgentId` in `src/types.ts`
2. Add its config locations to `src/discovery/discover.ts`
3. Add a parser under `src/parsers/` and call it from `parseByKind` in `src/scan.ts`. Put unknown keys in `unparsed`; never fill in permissions by guessing

## License

[Apache License 2.0](LICENSE)
