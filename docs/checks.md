# What repovet checks

- [Why?](#why)
- [What it looks for](#what-it-looks-for)
- [What works today](#what-works-today)
- [What is checked](#what-is-checked)

What is not checked is in [limits.md](limits.md).

## Why?

A repository can run code on your machine long before you think you have "run" it:

- **Opening it** in an editor can run code: VS Code tasks set to start on folder open,
  dev containers, workspace settings that point tools into the repository.
- **Installing or building it** can run code: npm `postinstall` scripts, `setup.py`,
  Python build hooks, Makefiles, Git hooks.
- **Letting an AI agent read it** can act on hidden instructions: a `CLAUDE.md` or
  `AGENTS.md` can carry prompts hidden in HTML comments or invisible Unicode.

repovet looks for exactly these things, reading the files only as data.

## What it looks for

Eight areas, with one plain example each:

| Area | One example it catches |
|------|------------------------|
| **autorun** | a VS Code task set to run the moment you open the folder |
| **agents** | a `CLAUDE.md` with an instruction hidden in an HTML comment |
| **obfuscation** | a Base64 blob that is decoded and executed in one step |
| **download & execute** | a script that pipes `curl …` straight into `sh` |
| **binaries** | an executable program disguised as `logo.png` |
| **dependencies** | a typosquatted package name sitting next to the real ones |
| **provenance** | a whole project committed in a single initial commit |
| **trust** | a brand-new account whose repository gained thousands of stars in a day |

## What works today

repovet is at an early stage; the changes per version are listed in
[CHANGELOG.md](../CHANGELOG.md). It is built around three questions:

| Category   | Question                                                                    |
|------------|-----------------------------------------------------------------------------|
| danger     | Does anything run automatically, or is something hidden, obfuscated or injected? |
| trust      | How do the owner, stars, contributors and maintenance look?                 |
| provenance | What is the repository made of, and how did it come about?                  |

What works today:

- **Local folders and public GitHub repositories.** A URL like
  `https://github.com/<owner>/<repo>` is fetched into a temporary folder as Git objects
  only (no checkout, nothing from the repository is written under its own file name) and
  deleted after the scan.
- **A menu** (`repovet` without arguments in a terminal) and **`repovet clone`**, which
  checks first and clones only after you agree; see [usage.md](usage.md).
- **Reports** for the terminal (a summary box, grouped findings), as one HTML page, as
  JSON ([report.schema.json](report.schema.json)) or as SARIF 2.1.0 for code-scanning
  tools; see [reports.md](reports.md).
- **Danger, six areas:** auto-run code (`autorun`), AI agent instructions and
  configuration (`agents`), obfuscated code (`obfuscation`), download-and-execute
  (`download_exec`), binaries and file-system tricks (`binaries`) and suspicious
  dependencies (`dependencies`); see [What is checked](#what-is-checked).
- **Provenance profile** (facts, not findings): languages, size, largest files,
  top-level structure, usual project files present or missing, share of generated or
  vendored files, license (file text and manifest) and notable files such as AI agent
  configuration, dev containers or editor settings. With Git history (a URL target, or a
  local folder with a `.git` folder): commits, time span, authors and e-mail domains,
  signed commits, the share of files that arrived in the first commit and AI tools named
  in commit messages.
- **Provenance indicators** (`info`/`low`, rules `RC-PROV-*`): one large initial commit,
  commit dates in the future or edited, a history rewritten or created in one go, AI tool
  trailers, "generated with" notes and committed AI session histories. They are hints
  about how a repository came about, never a verdict: commit dates and authors can be set
  by anyone.
- **Trust profile** (facts from the GitHub API, see [Trust](trust.md)):
  repository and owner age, account type, stars, forks, watchers, contributors, commits,
  last commit, releases, open issues, archived/fork/template, default-branch protection,
  the license GitHub detects, and for a local folder whether its HEAD commit exists in
  the GitHub repository its Git remote names. `--offline` turns it off.
- **Trust indicators** (`info` to `medium`, rules `RC-TRUST-*`): a very new owner account
  or a very young repository with many stars, most stars within one day, a fork of a much
  more popular repository, a release that offers programs or archives from a repository
  with hardly any code, archived or inactive repositories, a local HEAD that GitHub does
  not know, a manifest that names another owner's repository, and an older, more popular
  repository with the same name and description. They are indicators, never a verdict, and
  there is no score.
- **Comparisons between commits** (`repovet diff`): two local Git revisions scanned with
  the same rules, new and worsened findings against `--fail-on`; see [diff.md](diff.md).
- **Evidence** (see [evidence.md](evidence.md)): reconstructions of documented attacks
  with the rules that must fire and the known gaps, a false-positive benchmark on the
  most-starred GitHub repositories, and a self-scan of this repository in CI.
- Windows, macOS and Linux with Python 3.12 or 3.13; the test suite runs on all three in
  CI.

## What is checked

Severity says how bad it is if the finding means what the rule claims; confidence says how
likely that is. `critical` means code runs without any further step once the folder is
opened or used with the tool concerned (a VS Code task on folder open that downloads code,
a Git `core.fsmonitor` command, agent settings that redirect API traffic, a file name that
reverses its extension). `high` means code runs during normal use (install, build,
starting an agent) or something is clearly disguised but still has to be opened.

[RULES.md](../RULES.md) lists every rule with its ID, severity and description; it is
generated from the YAML rules in `src/repovet/rules/`. `repovet rules list` shows the same
list in the terminal (`--area` to pick one area). The rules are grouped in these areas:

| Area | IDs | Looks for |
|------|-----|-----------|
| `autorun` | `RC-AUTO` | code that runs on install, build, opening the folder or a double-click (npm, Python builds, VS Code, dev containers, Git hooks and config, Makefiles, Windows, macOS and Linux shell files, GitHub Actions, MSBuild) |
| `agents` | `RC-AGENT` | instructions and settings for AI coding agents: hidden text, plain-text instructions to run commands or send data away, broad permissions, hooks, MCP servers, imports of secrets |
| `obfuscation` | `RC-OBF` | encoded or packed code (also split into several strings), invisible characters and look-alike letters in source |
| `download_exec` | `RC-DLX` | code that downloads and runs more code, also through a variable or a command substitution |
| `binaries` | `RC-BIN` | programs, archives, disguised files and file-system tricks |
| `dependencies` | `RC-DEP` | typosquatted names and unusual package sources |
| `provenance` | `RC-PROV` | indicators from languages, structure and Git history |
| `trust` | `RC-TRUST` | indicators from the GitHub API (owner, stars, activity, copies) |

Rules are data, not code: each one is a YAML entry with an ID, severity, confidence, file
patterns, a check, and texts for message, reason and recommendation. Rule IDs are never
renamed or reused.

**Chains** (`RC-AUTO-090`): when a VS Code task that runs on folder open, a dev container
command or an npm install script starts a file of the repository (`./setup.sh`,
`node tools/x.js`, `make setup`, `npm run x`), repovet follows it for up to two files and
checks every file it reaches with the download and obfuscation rules, also files those
rules would otherwise skip. If the path reaches dangerous code, one finding reports the
whole path. Download-and-execute code reached this way gets at least the severity the
entry point's own rule gives the same code written inline (on folder open: critical).
Only paths inside the repository are followed: never absolute paths, vendored folders or
links.

Two details that keep false alarms down without hiding anything:

- **Agent skills** (`SKILL.md`) count as files agents load only in the folders the agents
  load them from, such as `.claude/skills` (Claude Code, also in subfolders),
  `.agents/skills` (Codex, Cursor, GitHub Copilot, OpenCode and others), `.github/skills`
  (Copilot) and `.cursor/skills`. The full list per tool, with links to each tool's
  documentation, is in [agent-skills.md](agent-skills.md).
  Other `SKILL.md` files (test fixtures, plugin folders) are still checked for hidden
  text and dangerous instructions and appear in the provenance profile.
- A download-and-execute or decode-and-execute match that is clearly a **regular
  expression inside a string** (security tools ship the patterns they look for, such as
  `r"curl\s+[^|]*\|\s*sh"`) is reported with confidence `low` instead of being dropped.
