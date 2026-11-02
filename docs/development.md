# Development

```
uv sync                      # create .venv with the pinned dev tools
uv run pytest                # all tests
uv run mypy src tests scripts  # strict type check
uv run ruff check            # lint, including security rules
uv run ruff format --check   # formatting
```

All four must pass before a change is done. `uv run pytest -m "not slow"` skips the
performance test (10,000 generated files).

Every rule has at least one positive and one harmless test case in
`tests/rule_cases/*.yaml`; a meta test fails otherwise. Test fixtures are written to a
temporary folder only during the test, and every regular expression is tested against
pathological inputs (ReDoS).

After changing rules, regenerate the tables in [RULES.md](../RULES.md) with
`uv run repovet rules list --markdown` and paste them between the `rules-table` markers;
`tests/test_readme.py` checks it.

**False-positive corpus:** `tests/corpus/corpus.yaml` lists real open-source repositories
pinned to a commit (each one can also be checked by URL, see the corpus README).
`tests/test_corpus.py` scans each and fails on high or critical findings that are not
explicitly accepted. Tests never download anything, so the test is skipped unless
`REPOVET_CORPUS_DIR` points to the extracted repositories. See
[tests/corpus/README.md](../tests/corpus/README.md) for downloading and running it:

```
# Bash
REPOVET_CORPUS_DIR=/path/to/corpus uv run pytest -m corpus

# PowerShell
$env:REPOVET_CORPUS_DIR = "C:\path\to\corpus"; uv run pytest -m corpus
```

**Reconstructions of documented attacks:** `tests/reconstructions/` rebuilds the shape
of publicly documented incidents and techniques (event-stream, xz-utils, tj-actions,
Shai-Hulud, malicious VS Code tasks, hidden instructions in agent files, ...) as inert
inline fixtures, each with its sources, the rules that must fire, the rules that must not,
and known gaps. `tests/test_reconstructions.py` scans every one offline;
`uv run python scripts/reconstructions.py` prints an overview.
`uv run python scripts/evidence.py --write` regenerates the results table in
[evidence.md](evidence.md); `tests/test_evidence.py` checks it and the short numbers in
the README.

To compare findings between versions, `scripts/corpus_counts.py` scans every corpus
repository by URL at its pinned commit (offline, no API) and every reconstruction, prints
the findings per rule and lists what changed against the committed baseline
`scripts/corpus-baseline.json` (`--offline-only`: reconstructions only, no network;
`--update-baseline` rewrites it). `--save counts.json` and `--compare counts.json` compare
two arbitrary runs. `scripts/fp_benchmark.py -n 50` scans the most-starred public
repositories and writes [fp-benchmark.md](fp-benchmark.md);
`scripts/diff_benchmark.py` measures how often `repovet diff` ends incomplete and writes
[diff-benchmark.md](diff-benchmark.md). These need the network and are not part of the
tests.

**Self-scan:** the workflow `.github/workflows/self-scan.yml` scans this repository with
repovet from source, uploads the SARIF report to code scanning, and fails on findings
that are not in `tests/self-scan-baseline.json` (this repository contains detection
patterns and test data on purpose). `scripts/self_scan.py REPORT --update` rewrites the
baseline.

`docs/social-preview.png` (the picture GitHub shows when the repository is shared) is
generated with `uv run --group docs python scripts/social_preview.py`; Pillow is only in
that optional group.

Contributions are welcome; see [CONTRIBUTING.md](../CONTRIBUTING.md) for how to add a
rule with its rule cases, and the [code of conduct](../CODE_OF_CONDUCT.md).

## Roadmap

Changes per version are listed in [CHANGELOG.md](../CHANGELOG.md). Possible next steps,
without dates: Maven (`pom.xml`), Python 3.14 in CI, and an optional online lookup of
known malicious packages.
