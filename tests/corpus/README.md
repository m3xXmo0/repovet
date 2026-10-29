# False-positive corpus

`corpus.yaml` lists eight public repositories pinned to a commit. `tests/test_corpus.py`
scans each and fails on high/critical findings that are not listed as `accepted`.
The test is skipped unless `REPOVET_CORPUS_DIR` points to the extracted repositories,
because tests never download anything.

## Getting the repositories

Download each archive yourself (outside the test run), for example with curl, into an
empty folder, and extract it so that `REPOVET_CORPUS_DIR/<name>/` contains one folder
with the repository:

```
curl -L -o flask.tar.gz https://codeload.github.com/pallets/flask/legacy.tar.gz/d086db8
```

(same pattern for every entry: `https://codeload.github.com/<repo>/legacy.tar.gz/<commit>`)

Extract with Python's `tarfile` and the `data` filter, which rejects absolute paths,
`..` and links that leave the target folder:

```python
import tarfile
with tarfile.open("flask.tar.gz") as tar:
    tar.extractall("corpus/flask", filter="data")
```

Then run:

```
REPOVET_CORPUS_DIR=/path/to/corpus uv run pytest -m corpus
```

On Windows PowerShell: `$env:REPOVET_CORPUS_DIR = "C:\path\to\corpus"`.

Never run anything from these folders; repovet only reads them.

## Checking a corpus repository by URL

Since M3, repovet can fetch a repository itself (manual check, not part of the test
run, because tests never use the network). The commit must be given in full, so look it
up on GitHub first:

```
uv run repovet scan https://github.com/pallets/flask --ref <40-character commit id>
uv run repovet scan https://github.com/pallets/flask --format json -o flask-url.json
```

A URL scan reads the files straight from the Git objects of that commit and must give
the same findings, coverage and file profile as the extracted archive of the same
commit; it adds the Git history (provenance profile and `RC-PROV` indicators), which the
archives do not contain.

Without `--offline`, a URL scan also asks the GitHub API for the trust profile and the
`RC-TRUST` indicators (about 7 requests per repository; without a token GitHub allows
60 per hour, so at most about eight repositories per hour). These well-known
repositories must not get any trust finding above `info`.

## Last run

2026-10-29, all 111 M4 rules, by URL with the GitHub API and without a token (default
branches): flask, pip, pydantic-ai, claude-code, Humanizer, vscode-extension-samples and
vite (codex left out to stay within the hourly limit). **No trust finding** in any of
them and no gap in the trust profile; 7 API requests per repository, 16 to 127 seconds
per scan including the download. Danger findings as before (pip: the six accepted
distlib launchers, RC-BIN-001). One change came out of it: for
vscode-extension-samples the name search found a younger copy with one star and the
same description; such copies are no longer listed as lookalikes (only repositories
with more stars than the checked one can be the original).

Earlier run (M3):

2026-10-29, all 101 M3 rules, eight repositories, 93 s (was 8:48 min in M2: all file
rules now share one pass over the files): no unjustified high/critical findings,
accepted list unchanged. New provenance findings: claude-code RC-PROV-011 (info, 3x:
"Generated with Claude Code" in two scripts and "Written by Claude Code" in a type
definition) – correct by the rule. Manual URL check: `https://github.com/pallets/flask`
(default branch, commit `d086db8`, the same as the corpus entry) gave the same finding
(RC-AUTO-026, low), coverage and file profile as the extracted archive.

Earlier run (M2):

2026-10-29, all 92 M2 rules, eight repositories: no unjustified high/critical
findings. Accepted (see `corpus.yaml`): RC-BIN-001 for the six Windows launchers that
pip vendors from distlib. Medium findings seen include RC-AGENT-010/050 (HTML comments,
`!`git status`` in Claude slash commands), RC-AUTO-060 (pydantic-ai checks out PR code
under `pull_request_target`, deliberately), RC-DEP-010/013 (Git dependencies pinned to
commits), RC-BIN-005 (WebAssembly fixtures in vite), RC-OBF-009 (a stray zero-width
space in a pip comment) – all correct by the rules' definitions.

Earlier run (M1, five repositories):

2026-10-29, all 34 M1 rules: no high/critical findings in any of the five repositories.
Medium findings seen: RC-AGENT-010 (HTML comments with content in agent files, e.g.
`<!-- braindump: rules extracted from PR review patterns -->` in pydantic-ai) – correct
by the rule's definition and rated medium for exactly this reason.
