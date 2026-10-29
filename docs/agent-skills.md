# Agent skill folders

An agent skill is a folder with a `SKILL.md` file. AI coding tools load skills from
fixed folders in the project and offer them to the model, which can then follow their
instructions. repovet counts a `SKILL.md` as a file agents load (rule `RC-AGENT-001` and
the "AI agent files" list in the provenance profile) only when it is in one of the
project folders below. Other `SKILL.md` files, such as test fixtures or skills shipped
inside a plugin, are still checked for hidden text and dangerous instructions, and the
provenance profile lists them as "agent skills outside the folders agents load them
from".

Checked against the official documentation on **2026-10-30**.

| Tool | Project folders | Where in the repository | Documentation |
|------|-----------------|-------------------------|---------------|
| Claude Code | `.claude/skills/` | the start folder and every parent up to the repository root; `.claude/skills/` in subfolders load once a file there is read | [Skills](https://code.claude.com/docs/en/skills) |
| Codex | `.agents/skills/` | every folder from the working directory up to the repository root | [Build skills](https://learn.chatgpt.com/docs/build-skills) |
| GitHub Copilot | `.github/skills/`, `.claude/skills/`, `.agents/skills/` | repository root | [About agent skills](https://docs.github.com/en/copilot/concepts/customizations/agent-skills), [VS Code](https://code.visualstudio.com/docs/copilot/customization/agent-skills) |
| Cursor | `.cursor/skills/`, `.agents/skills/`; for compatibility `.claude/skills/`, `.codex/skills/` | `.cursor/skills/` and `.agents/skills/` anywhere in the repository | [Skills](https://cursor.com/docs/skills) |
| Gemini CLI | `.gemini/skills/`, `.agents/skills/` | workspace root | [Agent skills](https://geminicli.com/docs/cli/skills/) |
| OpenCode | `.opencode/skills/`, `.claude/skills/`, `.agents/skills/` | every folder from the working directory up to the Git worktree root | [Skills](https://opencode.ai/docs/skills/) |
| Cline | `.cline/skills/`, `.clinerules/skills/`, `.claude/skills/` | workspace root | [Skills](https://docs.cline.bot/customization/skills) |
| Windsurf (Cascade, now in Devin Desktop) | `.devin/skills/`, `.windsurf/skills/` (legacy), `.agents/skills/`; `.claude/skills/` only when reading Claude Code configuration is turned on | workspace root | [Skills](https://docs.devin.ai/desktop/cascade/skills) |
| Kiro | `.kiro/skills/` | workspace root | [Skills](https://kiro.dev/docs/skills/) |
| Roo Code | `.roo/skills/`, `.roo/skills-<mode>/`, `.agents/skills/`, `.agents/skills-<mode>/` | project root | [Skills](https://roocodeinc.github.io/Roo-Code/features/skills) |
| Junie | `.junie/skills/`, `.agents/skills/` (trusted projects) | project root | [Agent skills](https://junie.jetbrains.com/docs/agent-skills.html) |

## What repovet matches

From the table, these paths count as agent files (matched without regard to case, like
all repovet file patterns):

- at any depth: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`,
  `.opencode/skills/`
- at the repository root: `.github/skills/`, `.agents/skills-*/`, `.cline/skills/`,
  `.windsurf/skills/`, `.devin/skills/`, `.kiro/skills/`, and the whole `.claude/`,
  `.codex/`, `.gemini/`, `.clinerules/`, `.roo/` and `.junie/` folders

A match means an agent may read the file when it works in the repository. It does not
mean that the skill is enabled, trusted or used.

## Not covered

repovet looks only at the repository. These skill sources are outside it and not
checked:

- personal, user-wide, enterprise and system folders (for example `~/.claude/skills/`,
  `~/.agents/skills/`, `/etc/codex/skills/`)
- skills from installed plugins and extensions, and skills synced from an account
- extra folders configured in the tool, such as Claude Code's `--add-dir` or VS Code's
  `chat.agentSkillsLocations`
