# Using repovet

repovet checks a Git repository **before** you run, install, build or open anything from
it, and it never runs anything from it. Give it a public GitHub link or a folder on your
computer; it shows what deserves a closer look and, just as honestly, what it could not
check.

- [Get started in three steps](#get-started-in-three-steps) (no experience needed)
- [Installation](#installation)
- [Usage](#usage): commands, examples and all options
- [Use the menu](#use-the-menu)
- [Clone after checking](#clone-after-checking)
- [Compare changes between commits](#compare-changes-between-commits)
- [Use it in CI](#use-it-in-ci)

## Get started in three steps

You do not need to know how to program. You type one command into a terminal window and
press Enter; repovet does the rest and never changes anything on your computer except
installing itself.

**Step 1 – open a terminal**

- **Windows:** press the Windows key, type `PowerShell`, press Enter.
- **macOS:** press Cmd + Space, type `Terminal`, press Enter.
- **Linux:** press Ctrl + Alt + T (or open "Terminal" from the menu).

**Step 2 – install repovet.** With Python 3.12 or newer (`python --version` shows it),
one line is enough:

```
pip install repovet
```

or, to keep it in its own environment, `pipx install repovet`.

No Python yet? [uv](https://docs.astral.sh/uv/), a small tool, installs repovet and
fetches the right Python for it. Copy the two lines for your system, paste them into the
terminal and press Enter after each one.

Windows (PowerShell):

```
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
uv tool install repovet
```

macOS and Linux:

```
curl -LsSf https://astral.sh/uv/install.sh | sh
uv tool install repovet
```

If the terminal then says `repovet` is not found, close it, open a new one and continue.

Yes, the first uv line downloads and runs an installer, which is exactly the kind of
thing repovet warns about. It comes from the official uv website; if you prefer, read
the [uv installation page](https://docs.astral.sh/uv/getting-started/installation/)
first or install Python from [python.org](https://www.python.org/downloads/) and use pip
or pipx.

**Step 3 – check a repository.** Type `repovet` and press Enter. A menu opens:

```
repovet 0.4.1 - check a Git repository before you run anything from it.
Nothing from the checked repository is run.

What do you want to do?
  1  Check a GitHub repository (URL)
  2  Check a folder on this computer
  3  Settings
  4  Exit
Choose 1-4:
```

Type `1`, press Enter, paste the link of the repository (for example
`https://github.com/m3xXmo0/repovet-demo`, a harmless project made to show what repovet
finds) and press Enter again.

**Reading the result.** The report starts with a summary box:

- one line on what not to do yet, for example "Do not open this folder in VS Code with
  trust";
- the number of findings per level: **critical** means code runs on its own as soon as
  you open or use the project with the tool concerned; **high** means code can run when
  you install, build or open it, or start an AI agent in it, or something is clearly
  disguised; **medium** is worth a look; **low** and **info** are hints and facts;
- **"Look at these first"**: the three findings that matter most.

Every finding below says where it is, what was found, why it matters (`Why`) and what to
do (`Do`). Labels such as `[test]` or `[docs]` mark findings in test files, docs,
examples or third-party code; they are shown, never hidden. At the end, **"Not checked"**
lists what repovet could not look at. **No findings does not mean the repository is
safe** – it means none of repovet's rules matched.

## Installation

repovet needs Python 3.12 or newer. Install it with pip, or with pipx as a
command-line tool in its own environment:

```
pip install repovet
# or
pipx install repovet

repovet --version
```

Without Python, [uv](https://docs.astral.sh/uv/) installs repovet and downloads a
matching Python:

```
uv tool install repovet
```

Runtime dependencies are PyYAML and [dulwich](https://www.dulwich.io/) (pure-Python Git,
which brings urllib3).

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
repovet                                  # menu (in a terminal)
repovet scan PATH|URL [options]          # check and print a report
repovet clone URL [FOLDER] [options]     # check, then clone if you agree
repovet diff PATH --base REV [options]   # compare two local Git revisions
repovet rules list [--area AREA]         # list the rules
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

# Explain every finding (Why/Do also for medium, low and info) and list every place
repovet scan ./some-repo --details

# A report to open in the browser: one HTML file, no scripts, works offline
repovet scan ./some-repo --format html -o report.html

# Check first, then clone into ./flask if you answer y
repovet clone https://github.com/pallets/flask

# Plain output without colors (also set by the NO_COLOR environment variable)
repovet scan ./some-repo --no-color

# Keep colors when piping into a pager (FORCE_COLOR; NO_COLOR and --no-color win)
FORCE_COLOR=1 repovet scan ./some-repo | less -R

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

`scan` options (`clone` takes the same, except `--keep-clone`, `--format`, `-o` and
`--details`, plus `--yes`):

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
| `--format FORMAT`       | `text` (default), `json`, `sarif` or `html`.                         |
| `-o`, `--output FILE`   | Write the report to FILE instead of stdout. FILE must be outside the checked folder. |
| `--details`             | Text report: Why/Do for every finding (by default only for critical and high) and every place of grouped findings. |
| `--no-color`            | Plain output without colors. `NO_COLOR` does the same; a non-empty `FORCE_COLOR` keeps colors when the output is piped. Reports written with `-o` never contain colors. |
| `--offline`             | No GitHub API queries for the trust area (a URL target is still downloaded). |
| `-v`, `--verbose`       | More detail.                                                         |
| `--yes`, `-y`           | `clone` only: clone without asking, but only if no finding is at or above `--fail-on`. |

Rule suppressions and other configuration are only taken from the command line, never
from the checked repository (that content is controlled by whoever wrote the repository).

What the reports look like and what the exit codes mean: [reports.md](reports.md).

## Use the menu

Run `repovet` without anything after it in a terminal to get the menu. After a check you
can show all details of one finding, save the report as an HTML page, JSON, SARIF or
text, or check another repository. Under **Settings** you see whether a GitHub token is
set (never its value, see [Trust](trust.md)) and can turn off the GitHub API for the
session (offline mode). The menu only appears when you type the command yourself: in
scripts, pipes and CI, and whenever you give arguments, repovet behaves exactly like the
commands above.

## Clone after checking

```
repovet clone https://github.com/<owner>/<repo> [FOLDER]
```

`repovet clone` first runs the same check as `repovet scan` on the URL, shows the summary
and then asks `Clone anyway? [y/N]` (Enter means no). Only if you answer `y` does it write
the files into `FOLDER` (default: the repository name; it must not exist or must be
empty).

The clone is written from the very Git objects that were checked – nothing is downloaded
twice – and it is deliberately limited: no Git hooks, no filters, no LFS downloads, no
submodules, and symbolic links are not created (they are listed). Every path is checked
before the first file is written; a repository with names that could escape the folder
or overwrite Git's own files (`.git` in any spelling, `..`, Windows device names such as
`aux`, `file:stream`, names that differ only in case) is not cloned at all. The folder
gets a normal `.git` folder, so `git pull` works afterwards.

`--yes` skips the question, but only when no finding is at or above `--fail-on` (default
`high`); without a terminal, repovet never clones a repository with such findings. The
exit code is the result of the check (0 or 1), whether you cloned or not.

## Compare changes between commits

`repovet diff` scans two local Git revisions with the same current rules and reports
new, unchanged, updated and no-longer-detected findings:

```console
repovet diff . --base main --head feature --fail-on high
repovet diff . --base main --head feature --format json -o ../delta.json
```

Base must be an ancestor of Head and both revisions must be available locally.
Nothing is checked out or executed. New findings and increases in severity, including
promotion from test/docs code into ordinary code, count against `--fail-on`.
Unchanged findings remain visible but do not fail the gate: an unchanged critical
finding can therefore return 0. Ambiguous matching, lost analysis scope and changed
files that cannot be checked return 3; a changed image whose signature matches its
extension is listed under "Not checked" without blocking. Equally unchecked, unchanged
files do not block the comparison. Newly available coverage is treated conservatively:
its findings are new.

A green diff means no new or worsened finding met the threshold within what the rules
could check. It does not replace a full scan. Changed behavior below an unchanged
install command is visible only within the existing chain analysis. Fingerprints are
result identities, not evidence that content has not been manipulated.

JSON scan reports use schema 1.5, diff reports schema 1.0, and SARIF remains 2.1.0.
Details, stored-report compatibility and the coverage rules are in [the diff guide](diff.md).

## Use it in CI

repovet runs in any CI. In GitHub Actions, the SARIF report shows the findings in the
**Security → Code scanning** tab and on pull requests:

```yaml
name: repovet
on: [push, pull_request]
permissions:
  contents: read
jobs:
  repovet:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # upload the SARIF report
    steps:
      - uses: actions/checkout@v7
        with:
          persist-credentials: false
      - uses: astral-sh/setup-uv@v10
      - name: Check the repository
        run: uvx repovet scan . --offline --format sarif -o repovet.sarif
      - name: Upload the report
        if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: repovet.sarif
          category: repovet
```

The scan step fails when a finding is at or above `--fail-on` (default `high`); the upload
step still runs (`if: always()`). Pin the actions to commit SHAs and repovet to a version
(`uvx repovet@0.5.1`) in production workflows. Leave out `--offline` to add the trust
indicators from the GitHub API (pass `GITHUB_TOKEN: ${{ github.token }}` as an
environment variable for a higher rate limit).
