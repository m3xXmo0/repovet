"""scripts/fp_benchmark.py without the network: recorded search answers and reports.

The committed docs/fp-benchmark.md must be exactly what the script renders from
docs/fp-benchmark.json, so its numbers cannot be edited by hand.
"""

import json
import shutil
import sys
from pathlib import Path
from typing import Any

import fp_benchmark
import pytest
from fp_benchmark import headline, most_starred, render_markdown, rule_table, run, summarize

from github_fake import Answer, FakeTransport
from repovet import __version__
from repovet.cli import EXIT_ABORTED, EXIT_FINDINGS, EXIT_OK, EXIT_USAGE
from repovet.github.client import GitHubClient

GOLDEN_REPORT = Path(__file__).parent / "golden" / "report.json"
SEARCH = (
    "/search/repositories?order=desc&page={page}&per_page={per_page}&q=stars%3A%3E1000&sort=stars"
)


def _item(name: str, stars: int, size: int = 100) -> dict[str, Any]:
    return {"full_name": name, "stargazers_count": stars, "size": size}


def _client(answers: dict[str, Answer]) -> GitHubClient:
    return GitHubClient(FakeTransport(answers), sleep=lambda s: None)


DATA: dict[str, Any] = {
    "date": "2026-10-30",
    "repovet": "0.3.0",
    "requested": 3,
    "rules_loaded": 126,
    "max_clone_size": 500 * 1024 * 1024,
    "repositories": [
        {
            "repo": "octo/alpha",
            "stars": 300,
            "commit": "a" * 40,
            "files": 120,
            "findings": {
                "RC-AUTO-001": {"severity": "medium", "high": 2, "medium": 0, "low": 0},
                "RC-BIN-001": {"severity": "high", "high": 1, "medium": 0, "low": 0},
            },
        },
        {
            "repo": "octo/beta",
            "stars": 200,
            "commit": "b" * 40,
            "files": 10,
            "findings": {
                "RC-AUTO-001": {"severity": "medium", "high": 1, "medium": 0, "low": 0},
            },
        },
    ],
    "skipped": [{"repo": "octo/huge", "stars": 100, "reason": "larger than the clone limit"}],
}


def test_most_starred_pages_and_filters_names() -> None:
    page1 = [_item("octo/alpha", 300), {"full_name": "bad name/x"}, _item("octo/beta", 200)]
    client = _client(
        {
            SEARCH.format(page=1, per_page=3): Answer({"items": page1}),
            SEARCH.format(page=2, per_page=3): Answer({"items": [_item("octo/gamma", 100, 7)]}),
        }
    )
    assert most_starred(client, 3) == [
        {"repo": "octo/alpha", "stars": 300, "size_kib": 100},
        {"repo": "octo/beta", "stars": 200, "size_kib": 100},
        {"repo": "octo/gamma", "stars": 100, "size_kib": 7},
    ]
    # An empty page ends the list early.
    client = _client({SEARCH.format(page=1, per_page=5): Answer({"items": page1})})
    assert [r["repo"] for r in most_starred(client, 5)] == ["octo/alpha", "octo/beta"]


def test_summarize_a_report() -> None:
    report = json.loads(GOLDEN_REPORT.read_text(encoding="utf-8"))
    report["facts"]["source"] = {"commit": "c" * 40}
    summary = summarize(report)
    assert summary["commit"] == "c" * 40
    assert summary["files"] == report["scan"]["files_scanned"]
    total = sum(sum(v[c] for c in ("high", "medium", "low")) for v in summary["findings"].values())
    assert total == len(report["findings"])
    assert list(summary["findings"]) == sorted(summary["findings"])


def test_scan_repository_skips_large_and_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    huge = {"repo": "octo/huge", "stars": 1, "size_kib": 600 * 1024}
    reason = fp_benchmark.scan_repository(huge, tmp_path, 500 * 1024 * 1024)
    assert reason == "larger than the clone limit (600 MB > 500 MB)"

    def failing(argv: list[str]) -> int:
        print("repovet: error: download larger than 500 MB", file=sys.stderr)
        return EXIT_ABORTED

    monkeypatch.setattr(fp_benchmark, "main", failing)
    small = {"repo": "octo/small", "stars": 1, "size_kib": 10}
    assert fp_benchmark.scan_repository(small, tmp_path, 500 * 1024 * 1024) == (
        "scan failed (exit code 3): repovet: error: download larger than 500 MB"
    )


def test_tables_and_headline() -> None:
    rows = rule_table(DATA)
    assert [(r["rule"], r["repos"], r["findings"]) for r in rows] == [
        ("RC-AUTO-001", 2, 3),
        ("RC-BIN-001", 1, 1),
    ]
    assert headline(DATA) == {
        "scanned": 2,
        "skipped": 1,
        "repos_high": 1,
        "critical": 0,
        "high": 1,
        "medium": 3,
        "low": 0,
        "info": 0,
    }


def test_markdown() -> None:
    text = render_markdown(DATA)
    assert text.startswith("# False-positive benchmark\n")
    assert "- Date: 2026-10-30" in text
    assert "- repovet version: 0.3.0" in text
    assert "- Scanned: 2 · skipped: 1" in text
    assert "- Repositories with at least one high or critical finding: 1 of 2" in text
    assert "| RC-AUTO-001 | medium | npm install lifecycle script present | 2 of 2 | 3 |" in text
    assert (
        f"| octo/alpha | 300 | `{'a' * 12}` | 120 | 0 | 1 | 2 | 0 | 0 "
        "| RC-AUTO-001 (2), RC-BIN-001 (1) |"
    ) in text
    assert "| octo/huge | 100 | larger than the clone limit |" in text
    assert "is not thereby safe" in text
    empty = render_markdown(DATA | {"repositories": [], "skipped": []})
    assert "| - | | no findings | | |" in empty
    assert empty.endswith("## Skipped\n\nNone.\n")


def test_run_writes_data_and_markdown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    items = [_item("octo/alpha", 300), _item("octo/huge", 200, 900 * 1024)]
    client = _client({SEARCH.format(page=1, per_page=2): Answer({"items": items})})
    calls: list[list[str]] = []

    def scan(argv: list[str]) -> int:
        calls.append(argv)
        shutil.copyfile(GOLDEN_REPORT, argv[argv.index("-o") + 1])
        return EXIT_FINDINGS

    monkeypatch.setattr(fp_benchmark, "main", scan)
    data, markdown = tmp_path / "b.json", tmp_path / "b.md"
    argv = ["-n", "2", "--data", str(data), "--markdown", str(markdown)]
    assert run(argv, client=client) == EXIT_OK
    assert [c[:4] for c in calls] == [
        ["scan", "https://github.com/octo/alpha", "--offline", "--format"]
    ]
    written = json.loads(data.read_text(encoding="utf-8"))
    assert written["repovet"] == __version__
    assert [r["repo"] for r in written["repositories"]] == ["octo/alpha"]
    assert written["skipped"][0]["repo"] == "octo/huge"
    assert markdown.read_text(encoding="utf-8") == render_markdown(written)

    # --render-only renders again from the data without scanning.
    markdown.write_text("stale", encoding="utf-8")
    assert run(["--render-only", "--data", str(data), "--markdown", str(markdown)]) == EXIT_OK
    assert markdown.read_text(encoding="utf-8") == render_markdown(written)


def test_run_errors(tmp_path: Path) -> None:
    assert run(["-n", "0"]) == EXIT_USAGE
    client = _client({})  # every search answers 404
    assert run(["-n", "2", "--data", str(tmp_path / "x.json")], client=client) == EXIT_ABORTED
    assert not (tmp_path / "x.json").exists()


def test_committed_report_matches_its_data() -> None:
    data = json.loads(fp_benchmark.DATA.read_text(encoding="utf-8"))
    assert fp_benchmark.MARKDOWN.read_text(encoding="utf-8") == render_markdown(data), (
        "docs/fp-benchmark.md is out of date; run scripts/fp_benchmark.py --render-only"
    )
