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
agentscope --help
```

| Option | Description | Default |
| --- | --- | --- |
| `-a, --agent <claude\|cursor\|all>` | Agent to analyze | `all` |
| `-f, --format <text\|json>` | Output format | `text` |
| `-g, --include-global` | Also read user-level settings in the home directory | off |
| `--no-color` | Disable colors (`NO_COLOR` also works) | colored on a TTY |
| `--lang <ja\|en>` | Language of the report, JSON, and help | detected |

The output language is chosen from `--lang`, then `AGENTSCOPE_LANG`, then `LC_ALL` / `LC_MESSAGES` / `LANG`. A Japanese locale selects Japanese; anything else selects English.

The exit code is `0` when the analysis completes (whether or not anything was found, and also for `--help` / `--version`) and `2` on errors such as an invalid option, a missing target directory, or a target that is not a directory.

### Example output

An excerpt from analyzing `test/fixtures/risky-project` (dummy settings used by the tests):

```text
AgentScope Security Report (v0.1.0)
Agents: Claude Code, Cursor
Config files: 6  Permission rules: 29  MCP servers: 4  Findings: HIGH 6 / MEDIUM 13 / LOW 0 / INFO 5

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
| Claude Code | `managed-settings.json`, `managed-settings.d/*.json`, `managed-mcp.json` | organization-managed | `-g` | in `/Library/Application Support/ClaudeCode/` (macOS), `/etc/claude-code/` (Linux / WSL), `C:\Program Files\ClaudeCode\` (Windows). Highest precedence |

Both JSON and JSONC (comments, trailing commas) are supported.

### How the two permission models are handled

Both agents' settings are converted into a common format (`PermissionRule`), while the differences are kept in `nativeKind` and `note`.

| | Claude Code | Cursor (IDE) | Cursor CLI |
| --- | --- | --- | --- |
| Allow | `permissions.allow` | `mcpAllowlist`, `terminalAllowlist` (prefix match; replaces the IDE allowlist) | `permissions.allow` |
| Ask | `permissions.ask` | (none) | (none) |
| Deny | `permissions.deny` | (none) | `permissions.deny` (wins over allow) |
| Hints | (none) | `autoRun.allow_instructions` / `block_instructions` (non-binding hints for a classifier; kept apart as `guidance-allow` / `guidance-block`) | (none) |

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
| I001 | States that the actual tool list of MCP servers is not verified | INFO |
| I002 | States that Cursor IDE settings (such as Run Mode) are not verified | INFO |
| I003 | States that automatically executed commands are configured (hooks, `statusLine`, `apiKeyHelper`, etc.); their contents are not shown | INFO |

Every finding has a rule ID, risk level, reason, source file, setting location (a JSON path), and a recommended fix. Levels come from fixed rules, never from guesses.

## Safety

- Read-only. Files are opened with `O_RDONLY`, and the source never calls write APIs (enforced by a test)
- Never starts or runs agents, MCP servers, or configured commands
- No network access (a test checks that modules such as `http`, `net`, and `child_process` are never imported)
- Never prints credential values, any part of them, or their length. For MCP servers, only the executable name, the URL host name, and the **names** of environment variables and headers are kept; arguments and values are dropped. Permission rules that contain secrets (including `API_KEY=...`, `--token ...`, `curl -u user:pass`) are replaced with `[REDACTED]`, and so are key names, server names, and other names that look like secrets
- Before printing to the terminal, control characters (ANSI escapes, newlines) and bidirectional / invisible characters from config files are escaped, so a config file cannot rewrite or disguise the report
- Symbolic links are resolved first, and project settings that point outside the target directory are not read. Non-regular files (FIFOs, etc.), files over 20 MB, and JSON nested deeper than 256 levels are not read either
- Objects are built without a prototype, so a `"__proto__"` key cannot make unwritten keys appear. If parsing one file fails unexpectedly, the other files are still analyzed
- The home directory is never walked. Even with `--include-global`, only the fixed files listed above are read

## Limitations

- **Permissions written in configuration files are not the same as the permissions that can actually be exercised.** The following are not analyzed:
  - Organization-managed settings (Claude Code managed settings, Cursor team admin settings)
  - Launch options (`--permission-mode`, `--allowedTools`, etc.)
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
  "findings": [{ "ruleId": "R001", "level": "HIGH", "title": "...", "reason": "...", "file": "...", "pointer": "...", "evidence": "...", "recommendation": "...", "originalLevel": "HIGH (only when lowered)", "effectNote": "..." }],
  "unparsed": [{ "file": ".claude/settings.json", "pointer": "hooks", "reason": "..." }],
  "summary": { "files": 3, "rules": 12, "mcpServers": 3, "findings": { "HIGH": 1, "MEDIUM": 2, "LOW": 0, "INFO": 1 } },
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
