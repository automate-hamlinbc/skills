# Design: Agent Configuration File Audit (Step 4D)

**Date:** 2026-05-16  
**Status:** Implemented  
**File changed:** `skills/lint-baseline/SKILL.md`

## Problem

The lint-baseline skill audited application code (FastAPI, Next.js, Supabase, MCP library usage) but had no checks for agent configuration files committed alongside the codebase — `.claude/settings.json`, `.mcp.json`, and equivalents. These files can grant wildcard permissions, disable safety prompts, define MCP servers that run arbitrary commands, and configure hooks that perform network I/O or read credential files. A shipped repo with a misconfigured agent config has an exploitable attack surface the baseline previously ignored.

Source: patterns from the Sketchy scanner (`patterns_agent.go`) identified three families worth porting: permission grants, MCP server definitions, and hook commands.

## Design

### Stack detection (Step 1)

Added detection for agent config files:
- Claude Code: `.claude/settings.json`, `.claude/settings.local.json`
- Cursor / generic MCP: `.mcp.json`, `.cursor/mcp.json`
- Windsurf: `.windsurf/mcp_config.json`
- Codex: `.codex/config.toml`
- Aider: `.aider.conf.yml`, `.aider.conf.yaml`

New row in the stack detection output: `Agent config: [Claude Code / Cursor / Windsurf / Codex / Aider / none]`

### Step 4D: Agent configuration files

Runs only when agent config is detected. Skips files that lack `hooks`, `mcpServers`, or `permissions` keys. Suppresses test/fixture/example paths.

**Permission grants**
| Pattern | Verdict |
|---------|---------|
| Wildcard grants: `"Bash(*)"`, `"WebFetch(*)"`, etc. | OBSERVATION |
| `bypassPermissions: true`, `approvalMode: "never"`, `autoApprove: true` | FINDING |
| `allowUnsandboxedCommands: true`, `dangerouslyDisableSandbox: true` | FINDING |
| `denyRead` without matching `Read(<path>)` deny | OBSERVATION |

**MCP server definitions**
| Pattern | Verdict |
|---------|---------|
| `"command"` = `curl`, `wget`, `sh`, `bash`, `zsh`, `eval` | FINDING |
| `npx`/`uvx`/`bunx`/`pnpm dlx` with `https://` or `github:` URL | OBSERVATION |

**Hook commands**
| Pattern | Verdict |
|---------|---------|
| `curl`, `wget`, `nc`, `ncat`, `scp`, `rsync` in hook command | FINDING |
| `~/.ssh/`, `~/.aws/credentials`, `~/.kube/`, `.env` in hook command | FINDING |
| `$(env)`, `$(printenv)`, `$*TOKEN*`, `$*SECRET*`, `$*KEY*` in hook command | FINDING |
| Hook referencing `.claude/hooks/*.sh` / `$CLAUDE_PROJECT_DIR/.claude/hooks/` | OBSERVATION |

## Scope decisions

- **Config files only, not instruction files.** CLAUDE.md / AGENTS.md prompt injection checks were considered but left out — those are "worth examining" territory and would require a different suppression model (the patterns are prose-level, not structural).
- **Framework depth section, not baseline item.** These checks are additive observations, not ship-blocking criteria. No change to `docs/v0-baseline.md` or the 8-item summary table.
- **Sketchy patterns not ported:** supply chain / malware patterns (reverse shells, base64 decode chains, crypto miners) — out of scope for auditing your own codebase.
