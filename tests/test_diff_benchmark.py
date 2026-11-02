"""scripts/diff_benchmark.py without the network: repositories served from tmp_path.

The committed docs/diff-benchmark.md must be exactly what the script renders from
docs/diff-benchmark.json, so its numbers cannot be edited by hand.
"""

import json
from pathlib import Path
from typing import Any

import diff_benchmark
from diff_benchmark import classify, evaluate, measure, render_markdown, run, spread, totals

from gitrepo import build_repo, local_transport
from repovet.cli import EXIT_ABORTED, EXIT_FINDINGS, EXIT_OK
from repovet.models import Severity

LIMIT = 500 * 1024 * 1024


def _history(path: Path, commits: int) -> list[str]:
    return build_repo(path, [{"files": {"README.md": f"Version {i}\n"}} for i in range(commits)])


def test_spread_picks_evenly_and_orders_neighbours() -> None:
    repos = [{"repo": f"o/r{i}", "files": i} for i in range(10)]
    slots = spread(repos, 3)
    assert [slot[0] for slot in slots] == ["o/r0", "o/r4", "o/r9"]
    assert slots[1][:3] == ["o/r4", "o/r3", "o/r5"]
    assert spread([], 3) == []


def test_measure_compares_two_ranges_offline(tmp_path: Path) -> None:
    ids = _history(tmp_path / "origin", 22)
    transport = local_transport({"octo/alpha": tmp_path / "origin"})
    runs = measure("octo/alpha", tmp_path, LIMIT, transport)
    assert isinstance(runs, list)
    assert [(r["range"], r["base"], r["head"]) for r in runs] == [
        ("HEAD~20..HEAD", ids[1], ids[-1]),
        ("HEAD~1..HEAD", ids[-2], ids[-1]),
    ]
    assert all(r["exit_code"] == EXIT_OK and r["causes"] == [] for r in runs)


def test_short_history_is_skipped(tmp_path: Path) -> None:
    _history(tmp_path / "origin", 5)
    transport = local_transport({"octo/alpha": tmp_path / "origin"})
    assert measure("octo/alpha", tmp_path, LIMIT, transport) == (
        "fewer than 21 commits on the first-parent line"
    )


def _finding(path: str, severity: str = "high", **extra: Any) -> dict[str, Any]:
    return {"severity": severity, "location": {"path": path}, "in_chain": None, **extra}


def _diff(issue_paths: list[str], *, base: list[dict[str, Any]], new: str | None) -> dict[str, Any]:
    gap = {
        "scope": "file",
        "status": "skipped",
        "reason": "File exceeds the size limit",
        "count": 1,
        "sample": ["big.js"],
        "paths": ["big.js"],
    }
    changes = (
        []
        if new is None
        else [{"status": "new", "worsened": False, "after": _finding("a.sh", new)}]
    )
    return {
        "exit_code": EXIT_ABORTED,
        "summary": {"new": len(changes)},
        "changes": changes,
        "base": {"report": {"findings": base}},
        "head": {"report": {"coverage": [gap]}},
        "issues": [{"paths": issue_paths, "reason": gap["reason"], "blocking": True}],
    }


def test_unchecked_changed_file_and_both_refinements() -> None:
    quiet = evaluate(_diff(["big.js"], base=[_finding("big.js", "low")], new=None), Severity.HIGH)
    assert quiet["causes"] == ["changed file unchecked"]
    assert (quiet["option_a"], quiet["option_b"]) == (EXIT_ABORTED, EXIT_OK)

    serious = _diff(["big.js"], base=[_finding("big.js")], new="high")
    outcome = evaluate(serious, Severity.HIGH)
    assert (outcome["new"], outcome["gated"]) == (1, 1)
    assert (outcome["option_a"], outcome["option_b"]) == (EXIT_FINDINGS, EXIT_ABORTED)


def test_classify_matching_and_global_causes() -> None:
    coverage = [
        {
            "scope": "file",
            "status": "skipped",
            "reason": "Too many files",
            "count": 9,
            "sample": ["x"],
            "paths": ["x"],
        },
    ]
    issue = {"paths": ["a", "b"], "reason": "Too many files"}
    assert classify(issue, coverage) == "global gap"
    for reason, cause in (
        ("Finding occurrences have equally plausible matches", "ambiguity"),
        ("Finding comparison exceeds its bounded matching budget", "budget"),
        ("A previous finding is no longer in a checked scope", "previous finding unknown"),
    ):
        assert classify({"paths": ["a"], "reason": reason}, coverage) == cause


def test_run_writes_data_and_markdown(tmp_path: Path) -> None:
    _history(tmp_path / "origin", 22)
    _history(tmp_path / "short", 3)
    source = tmp_path / "source.json"
    repositories = [{"repo": "octo/short", "files": 1}, {"repo": "octo/alpha", "files": 2}]
    source.write_text(json.dumps({"date": "2026-11-02", "repositories": repositories}))
    transport = local_transport(
        {"octo/alpha": tmp_path / "origin", "octo/short": tmp_path / "short"}
    )
    data, markdown = tmp_path / "d.json", tmp_path / "d.md"
    argv = ["-n", "1", "--source", str(source), "--data", str(data), "--markdown", str(markdown)]
    assert run(argv, transport) == EXIT_OK
    written = json.loads(data.read_text(encoding="utf-8"))
    assert [s["repo"] for s in written["skipped"]] == ["octo/short"]
    assert totals(written)["all"] == {0: 2, 1: 0, 2: 0, 3: 0}
    assert markdown.read_text(encoding="utf-8") == render_markdown(written)


def test_committed_report_matches_its_data() -> None:
    data = json.loads(diff_benchmark.DATA.read_text(encoding="utf-8"))
    assert diff_benchmark.MARKDOWN.read_text(encoding="utf-8") == render_markdown(data), (
        "docs/diff-benchmark.md is out of date; run scripts/diff_benchmark.py --render-only"
    )
