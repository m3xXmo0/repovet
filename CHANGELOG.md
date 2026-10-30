# Changelog

All notable changes to repovet are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Rule IDs are never renamed or reused; the
exit codes and the JSON report (`schema_version`) are stable interfaces.

## [Unreleased]

## [0.4.1] - 2026-10-30

This release hardens plain-text instructions in agent files and GitHub Actions checks.
It ships 141 rules. Exit codes, JSON report schema 1.4 and runtime dependencies are
unchanged.

All 16 canonical reconstructions are detected. Of 64 hand-written variants, 60 reach
the original severity; the four earlier gaps remain open. The increase from 48 of 52
comes from 12 new variants, not from closing those gaps. In the existing unpublished
set, 13 of 42 variants are rated at the expected severity, 13 are detected at medium or
above but rated lower or in another area, and 16 are missed; 23 of 24 harmless look-alikes
stay below medium. The recorded 0.4.0 result was 11 / 13 / 18 and 22 of 24. Since its
technique classes informed this release, this set is now only partly independent and
serves as a regression check; workflow cases still rate 0 of 6.

The renewed 50-repository benchmark scanned 38 and skipped 12: 0 critical, 5 high,
62 medium, 58 low and 447 info findings. The previous 0.4.1 run had 63 medium; the other
area/severity counts are unchanged. The guarded default-branch checkout is no longer
reported. Repository snapshots can change between runs; these counts are not a paired
experiment on identical commits. Details are in `docs/fp-benchmark.md`.

### Added

- **RC-AUTO-023 (high):** folder-open tasks that start repository code, including
  interpreter commands, npm scripts, Make targets, task dependencies and OS overrides.
- **RC-AUTO-063 (medium):** untrusted event text passed through `env:` into a command,
  an expression in a script, or a workflow environment file.
- **RC-AUTO-064 (medium):** event text written to a file and then executed within the
  same job; constant BODY/TITLE variables are not treated as event data.
- **RC-DLX-008 (low):** a secret variable in a URL query string. Some services expect
  their key there, so this remains a hint.
- **RC-DLX-009 (high):** all secrets used by a network command in the same step,
  directly or through declared environment values. Independent local writes and
  requests do not count as a transfer.
- **RC-AGENT-029 (high):** curl uploads of a concrete file in agent instructions,
  including `-T`, `--upload-file` and data-file arguments. Downloads, literal request
  bodies and stdin without a named file do not count as file uploads.

### Changed

- **RC-AGENT-028** recognizes concrete secret material, destination URLs and German
  instructions. Actual sending of secrets to a URL and secret-reading commands in URL
  queries remain high. Secrecy or skipping confirmation alone does not raise ambiguous
  prose above medium; comparisons with documentation are excluded.
- **RC-AUTO-020** is low for the presence of a folder-open task. Repository code is
  high through RC-AUTO-023; network access or decoded payloads are critical through
  RC-AUTO-021. Labels and echo arguments are not executed files.
- **RC-AUTO-060** recognizes more pull-request checkout forms, including literal env
  indirection. Constant refs and workflow-run jobs restricted to their own repository,
  default branch and trusted event types are excluded; every OR branch must retain
  the restrictions.
- Script download checks also inspect workflow and composite-action `run` values.
  Agent code spans use the same checks for process substitution, command substitution,
  here-strings, system downloaders, executed HTTP responses and downloaded variables.
- Quoted attack examples, fenced code and warnings are reported as low. Context cue
  words also cover German. Invalid Unicode in command scalars and oversized environment
  expansions are listed under "Not checked" instead of aborting analysis.

## [0.4.0] - 2026-10-30

This release hardens detection against simple rewrites of known attacks. Every
reconstruction of a documented attack now comes with hand-written variants that use an
evasion technique (a variable, a helper script, another downloader, a split string,
plain prose); 48 of 52 variants reach the severity of the original, the other four are
listed as known gaps. On an independent, unpublished set of 42 variants written by a
third party, 11 are rated at the expected severity (0.3.1: 8), 13 are detected but rated
lower (12) and 18 are missed (22); prose in agent files and GitHub Actions workflows
remain the weakest areas. The JSON report moves to `schema_version` 1.4; exit codes are
unchanged.

### Added

- **RC-AUTO-090 (chains):** a VS Code task that runs on folder open, a dev container
  command or an npm install script that starts a file of the repository (`./setup.sh`,
  `node tools/x.js`, `make setup`, `npm run x`) is followed for up to two files. Every
  file reached is checked with the download and obfuscation rules, also files they would
  otherwise skip, and a path that reaches dangerous code is reported as one finding with
  each step. Download-and-execute code reached this way gets at least the severity the
  entry point's rule gives the same code inline (critical on folder open, high for npm
  install scripts). Only paths inside the repository are followed: no absolute paths,
  vendored folders or links; cycles end the path.
- **RC-AGENT-028:** plain-text instructions in AI agent files that combine running a
  command, sending data to an address, secrets or the environment, or keeping something
  from the user in one sentence. Medium with low confidence ("text an agent may follow,
  not enforced code"); high only when a secret or the environment is sent to a URL.
  Quoted attack examples are reported as low.
- **RC-DLX-007:** a download stored in a variable and run within the next five lines
  (`S=$(curl …); sh -c "$S"`, `eval "$STAGE"`).
- **RC-OBF-012:** Base64 or hex strings split into constants of the same file, joined,
  decoded and executed (Python, JavaScript, TypeScript).
- **RC-BIN-014:** bidirectional control characters in a file or folder name (moved out
  of RC-BIN-004, stays critical).
- JSON report: `chain` (id and steps) on a chain finding, `in_chain` on the findings on
  its path, `summary.part_of_chains`; SARIF: the steps as `relatedLocations`.
- The text and HTML reports start the summary with what not to do yet (for example "Do
  not open this folder in VS Code with trust"), based on the most severe findings.

### Changed

- Severity: **RC-BIN-002, RC-BIN-003, RC-BIN-004 and RC-AGENT-002 are now high instead
  of critical**: the file runs, or the hidden text acts, only after a further step
  (opening the file, starting an agent). Critical stays for code that runs as soon as the
  folder is opened or used (RC-AUTO-021, RC-AUTO-032, RC-AGENT-032, chains on folder open)
  and for reversed file names (RC-BIN-014).
- **RC-DLX-001** also reports a download piped into `env sh`, `sudo -E bash` or
  `/usr/bin/env bash`, a command substitution of a download given to `sh -c`, `eval`,
  `python -c`, `node -e`, `perl -e` or `ruby -e` (also with backticks), and a pipe on a
  continuation line. It no longer reports a pipe into a command whose name only starts
  like a shell (`| zsh-helper`) or into an inline script that reads the download as data
  (`| node -e "…"`, `| perl -wlne '…'`, `| python3 -c '…'`).
- **RC-OBF-003** also reports decompressed data run through `eval "$(xz -dc …)"` or
  `sh -c "$(gunzip -c …)"`; **RC-OBF-011** also the Function constructor.
- **RC-AGENT-024** also checks `.code-workspace` files and reports approval of every
  terminal command (`"chat.tools.terminal.autoApprove": {"/.*/": true}`).
- Chain parts are listed but counted once: summaries, "Look at these first" and
  `--fail-on` count the chain finding instead.
- The text report groups findings per rule (at most five places, then `+N more`) and
  shows info findings as one line per rule unless `--details` is given.
- The README lists `pip install repovet` and `pipx install repovet` first.

## [0.3.1] - 2026-10-30

This release removes the noisiest false alarms found by scanning the 50 most-starred
GitHub repositories and closes the known gaps listed in the reconstructions of
documented attacks. Exit codes, report formats and the JSON schema are unchanged.

### Added

- **RC-AUTO-062:** GitHub workflows that put untrusted event text (pull request and
  issue titles and bodies, comments, branch names, commit messages) into a `run:` step
  or github-script code under `pull_request_target`, issue, comment, discussion or
  `workflow_run` triggers, and composite actions that do the same (expression injection).
- **RC-DLX-006:** a workflow job that uses secrets and sends data to a request catcher,
  paste or file host (the Shai-Hulud persistence workflow).
- **RC-OBF-011:** Node code that decrypts data and compiles it as a module or runs it in
  `vm` (the event-stream loader).
- **RC-AGENT-027:** JavaScript, TypeScript or Python code that starts an AI coding agent
  CLI with approvals or sandbox switched off (the Nx "s1ngularity" install script).

### Changed

- **RC-OBF-003** also reports `child_process`, `subprocess` and `os.system` calls that run
  decoded data (`execSync(Buffer.from(..., "base64"))`), decompressing straight into a
  shell (`xz -d | sh`), and checks autotools files (`*.m4`, `configure`, `Makefile.in`).
- **RC-AUTO-032** also checks the config of bare repositories buried in subfolders.
- **RC-AUTO-070/071** also report pre- and post-build events in Visual Studio projects.
- Fewer false alarms:
  - **RC-AGENT-010** reports an HTML comment only if it addresses an AI tool, asks for an
    action, or contains a URL, a command, encoded data, secrets or hiding language;
    comments in code blocks and code spans are shown as text and are not reported.
  - **RC-AGENT-011** ignores HTML in code blocks and code spans and web assets (HTML, CSS)
    in skill folders.
  - **RC-AGENT-020, -021, -022, -023, -025** report a phrase that is quoted to describe
    an attack (security guidance, tables and lists of patterns) as low severity and low
    confidence instead of dropping it; an instruction stays high.
  - **RC-AGENT-022** counts the macOS keychain only as a file or through the command that
    reads it, not advice to store tokens in the Keychain.
  - **RC-AGENT-050** no longer mistakes `` `!` `` or `` `assert!` `` in code spans for an
    embedded shell command.
  - **RC-OBF-006** reports only long lines shaped like code, not long text strings, SVG
    paths, keyword lists or data tables.
  - **RC-OBF-010** checks names in code; text in comments and string literals counts only
    as part of a URL, host name or module name.
- The reconstructions of event-stream and Shai-Hulud keep only the shape the rules need;
  neither contains a working loader or sends anything if run.

## [0.3.0] - 2026-10-30

This release adds evidence for what repovet detects and how often it raises false
alarms. The rules, reports, options and exit codes are unchanged.

### Added

- **Reconstructions of documented attacks** (`tests/reconstructions/`): 16 publicly
  documented supply-chain incidents and repository attack techniques (among them
  event-stream, ua-parser-js, the xz-utils backdoor, tj-actions/changed-files, the
  Shai-Hulud worm, Nx "s1ngularity", ultralytics, PyTorch torchtriton, malicious VS Code
  tasks and dev containers, hidden instructions in AI rule files, GlassWorm, Trojan
  Source) rebuilt as inert fixtures, each with public sources, the rules that must fire,
  the rules that must not, and known gaps. A regression test scans every one offline;
  rules that should fire but do not are listed as known gaps instead of being dropped.
- **False-positive benchmark:** `scripts/fp_benchmark.py` scans the most-starred public
  GitHub repositories and writes `docs/fp-benchmark.md` (findings per rule and per
  repository, the rules that fire most often, skipped repositories).
- **Evidence** section near the top of the README with the detection results and the
  benchmark numbers, generated by `scripts/evidence.py` and checked by a test.
- **Self-scan workflow** (`.github/workflows/self-scan.yml`): repovet checks its own
  repository from source on every push and pull request, uploads the SARIF report to
  code scanning and fails only on findings that are not in
  `tests/self-scan-baseline.json`.
- `scripts/corpus_counts.py` also scans the reconstructions and compares both sets with a
  committed baseline (`scripts/corpus-baseline.json`, rewritten only with
  `--update-baseline`; `--offline-only` needs no network).
- **Design principles** in `CONTRIBUTING.md`.

## [0.2.0] - 2026-10-30

### Added

- **Menu:** `repovet` without arguments in a terminal opens a numbered menu: check a
  GitHub URL or a local folder, settings (shows whether a GitHub token is set, never its
  value; offline mode for the session). After a check: details of one finding, save the
  report (HTML, JSON, SARIF or text), check another repository. It never appears in CI,
  with piped input or output, or when arguments are given.
- **`repovet clone URL [DIR]`:** checks the repository like `repovet scan`, shows the
  summary and asks `Clone anyway? [y/N]`. The working tree is written from the checked
  Git objects with dulwich only: no hooks, filters, LFS or submodules, no symbolic links
  (they are listed), and every path is validated first (no absolute paths, `..`, `.git`
  in any spelling, Windows device names, alternate data streams, trailing dots or spaces,
  or case collisions; one bad path stops the clone). Everything is written into a private
  staging folder (`.repovet-checkout-*`) next to the target and moved into place with one
  rename; the target is checked again right before, and a target replaced by a link or
  junction is refused. On any error or interruption only the staging folder is removed,
  so the target never holds a partial clone. `--yes` skips the question only when no finding is at or above `--fail-on`; without a
  terminal, a repository with such findings is never cloned. The exit code is the result
  of the check (0 or 1).
- **HTML report** (`--format html`): one self-contained file, no JavaScript, no external
  resources, collapsible findings, severity colours, profiles, "Not checked", light and
  dark mode.
- **Compact text report:** a summary box with the counts per severity and the three
  findings to look at first; findings of the same rule and message are grouped (one
  explanation, the places, `+N more`); Why/Do only for critical and high unless
  `--details` is given.
- **Context labels** (`vendored`, `test`, `example`, `docs`) for findings in such files:
  shown in every report, never used to hide or downgrade a finding. JSON: new field
  `context` (`schema_version` 1.3); SARIF: `properties.context`.
- `scripts/corpus_counts.py` scans the false-positive corpus by URL and prints the
  findings per rule, with `--save` and `--compare` to see changes between versions. The
  corpus lists full commit ids and a ninth repository (a security scanner).
- `docs/agent-skills.md`: the folders each AI coding tool loads agent skills from, with
  links to the official documentation and the date checked.
- Issue forms for false positives and missed detections, a pull request template,
  `CONTRIBUTING.md` (how to add a rule with its rule cases) and `CODE_OF_CONDUCT.md`
  (Contributor Covenant 2.1).
- `docs/social-preview.png`, generated by `scripts/social_preview.py`.
- The terminal report honours `FORCE_COLOR`: when it is set to a non-empty value,
  colors are kept even when the output is piped, for example into `less -R`. `NO_COLOR`
  and `--no-color` still take precedence, and reports written with `-o` never contain
  colors.
- A demo GIF on the README (`docs/demo.gif`), rendered from `docs/demo.tape` with
  [VHS](https://github.com/charmbracelet/vhs). The manual workflow
  `.github/workflows/demo.yml` (trigger: `workflow_dispatch`) installs repovet from
  source, renders the tape against the public demo repository and uploads the GIF as an
  artifact; it commits nothing.

### Changed

- **Fewer false positives in security tools:** download-and-execute and decode-and-execute
  matches (RC-DLX-001 to 004, RC-OBF-003) that are clearly a regular expression inside a
  string are reported with confidence `low` instead of their usual confidence. They are
  not dropped, so regex syntax next to a real command cannot hide it.
- **RC-AGENT-001** only says that agents load a `SKILL.md` when it is in a folder agents
  load skills from (`.claude/skills`, also nested, `.agents/skills`, `.github/skills`,
  `.cursor/skills`, `.opencode/skills`, `.cline/skills`, `.windsurf/skills`,
  `.devin/skills`, `.kiro/skills`, `.agents/skills-<mode>`; see `docs/agent-skills.md`
  for the sources). Other `SKILL.md` files, such as test fixtures and
  plugin folders, appear in the provenance profile instead and are still checked for
  hidden text and dangerous instructions. Its message no longer repeats the path.
- The README starts with a step-by-step guide for people without technical experience,
  the menu and `repovet clone`, an example for GitHub Actions with SARIF upload and a
  short FAQ.
- Reworked the README into a short introduction for new users (tagline, badges, the demo
  GIF, why it matters, a quick start and a one-line-per-area overview) followed by the
  existing detailed sections, now with a table of contents.

## [0.1.0] - 2026-10-29

First release.

### Added

- `repovet scan PATH|URL` statically checks a local folder or a public GitHub
  repository (`https://github.com/<owner>/<repo>`, optional `--ref`) without running
  anything from it. URL targets are fetched as Git objects only, with dulwich, into a
  temporary folder that is deleted after the scan.
- 126 detection rules in eight areas, defined as YAML data: auto-run code (`RC-AUTO`),
  AI agent instructions and configuration (`RC-AGENT`), obfuscation (`RC-OBF`),
  download-and-execute (`RC-DLX`), binaries and file-system tricks (`RC-BIN`),
  dependencies (`RC-DEP`), provenance indicators (`RC-PROV`) and trust indicators
  (`RC-TRUST`).
- Every finding has a rule ID, severity, confidence, file and line where it applies,
  a reason and a recommendation. Gaps in coverage are listed under "Not checked".
- Provenance profile from the files and the Git history, and a trust profile from the
  GitHub REST API (optional token from `GITHUB_TOKEN` or `GH_TOKEN`; `--offline` turns
  the API off).
- Reports for the terminal, as JSON (`schema_version` 1.2) and as SARIF 2.1.0. Text from
  the checked repository is masked before output.
- Options to filter (`--min-severity`), set the failure threshold (`--fail-on`), skip
  rules (`--ignore-rule`), add rule folders (`--rules`) and set size and time limits.
- `repovet rules list` (with `--area` and `--markdown`).
- Exit codes: 0 no findings at or above the threshold, 1 findings at or above the
  threshold, 2 usage error, 3 analysis aborted.
- Windows, macOS and Linux with Python 3.12 and 3.13.

[Unreleased]: https://github.com/m3xXmo0/repovet/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/m3xXmo0/repovet/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/m3xXmo0/repovet/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/m3xXmo0/repovet/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/m3xXmo0/repovet/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/m3xXmo0/repovet/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/m3xXmo0/repovet/releases/tag/v0.1.0
