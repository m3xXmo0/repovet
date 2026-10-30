"""scripts/self_scan.py: the baseline of expected findings in repovet's own repository."""

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import self_scan
from self_scan import compare, file_findings, ignore_patterns, is_ignored, load_baseline, run

from repovet.cli import EXIT_FINDINGS, EXIT_OK, main

PROJECT = Path(__file__).parent.parent


def _finding(rule: str, path: str | None) -> dict[str, Any]:
    return {"rule_id": rule, "location": {"path": path, "line": 1} if path else None}


REPORT = {
    "findings": [
        _finding("RC-AUTO-001", "package.json"),
        _finding("RC-AUTO-001", "package.json"),
        _finding("RC-OBF-001", "src/a.js"),
        _finding("RC-PROV-001", None),
        _finding("RC-AGENT-001", "NOTES.md"),
        _finding("RC-AGENT-031", "scratch/settings.json"),
    ]
}


def test_file_findings_skip_repository_wide_findings() -> None:
    assert file_findings(REPORT) == Counter(
        {
            ("RC-AUTO-001", "package.json"): 2,
            ("RC-OBF-001", "src/a.js"): 1,
            ("RC-AGENT-001", "NOTES.md"): 1,
            ("RC-AGENT-031", "scratch/settings.json"): 1,
        }
    )


@pytest.mark.parametrize(
    ("path", "ignored"),
    [
        ("NOTES.md", True),
        ("docs/NOTES.md", True),
        ("scratch/settings.json", True),
        ("a/scratch/x", True),
        ("x/.cache/state.lock", True),
        (".cache/other.lock", False),
        ("src/mod.pyc", True),
        ("build/x.txt", True),
        ("src/build/x.txt", True),
        ("build", False),
        ("NOTES.md.txt", False),
        ("tests/rule_cases/agents.yaml", False),
        ("top/only.txt", True),
        ("sub/top/only.txt", False),
    ],
)
def test_ignore_patterns(path: str, ignored: bool) -> None:
    patterns = [
        "NOTES.md",
        "scratch/",
        "**/.cache/state.lock",
        "*.py[cod]",
        "build/",
        "/top/only.txt",
    ]
    assert is_ignored(path, patterns) is ignored


def test_patterns_from_both_files(tmp_path: Path) -> None:
    (tmp_path / ".git" / "info").mkdir(parents=True)
    (tmp_path / ".gitignore").write_text("# comment\n\n.venv/\n!keep.txt\n", encoding="utf-8")
    (tmp_path / ".git" / "info" / "exclude").write_text("NOTES.md\n", encoding="utf-8")
    assert ignore_patterns(tmp_path) == [".venv/", "NOTES.md"]
    assert ignore_patterns(tmp_path / "missing") == []


def test_compare() -> None:
    found = Counter({("R1", "a"): 2, ("R2", "b"): 1})
    expected = Counter({("R1", "a"): 1, ("R3", "c"): 1})
    assert compare(found, expected) == (
        ["R1 a: 2 finding(s), baseline 1", "R2 b: 1 finding(s), baseline 0"],
        ["R3 c: 0 finding(s), baseline 1"],
    )
    assert compare(found, found) == ([], [])


def test_update_then_check(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    (root / ".gitignore").write_text("NOTES.md\nscratch/\n", encoding="utf-8")
    report, baseline = tmp_path / "report.json", tmp_path / "baseline.json"
    report.write_text(json.dumps(REPORT), encoding="utf-8")
    common = [str(report), "--baseline", str(baseline)]

    assert run([*common]) == 2
    assert "create it with --update" in capsys.readouterr().err
    assert run([*common, "--update", "--root", str(root)]) == EXIT_OK
    assert "3 findings (2 in ignored paths)" in capsys.readouterr().out
    assert load_baseline(baseline) == Counter(
        {("RC-AUTO-001", "package.json"): 2, ("RC-OBF-001", "src/a.js"): 1}
    )
    written = json.loads(baseline.read_text(encoding="utf-8"))
    assert [e["rule"] for e in written["expected"]] == ["RC-AUTO-001", "RC-OBF-001"]

    # The ignored files are absent in CI: a report without them passes.
    in_ci = {"findings": REPORT["findings"][:4]}
    report.write_text(json.dumps(in_ci), encoding="utf-8")
    assert run(common) == EXIT_OK
    assert "no new findings" in capsys.readouterr().out

    # One more finding fails; a missing one is only listed.
    more = {"findings": [*REPORT["findings"], _finding("RC-DLX-001", "x.sh")][1:]}
    report.write_text(json.dumps(more), encoding="utf-8")
    assert run(common) == 1
    out = capsys.readouterr().out
    assert "RC-DLX-001 x.sh: 1 finding(s), baseline 0" in out
    assert "RC-AUTO-001 package.json: 1 finding(s), baseline 2" in out


def test_committed_baseline_matches_a_scan_of_this_repository(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The same check as the self-scan workflow, minus files Git ignores locally."""
    report = tmp_path / "self.json"
    code = main(["scan", str(PROJECT), "--offline", "--format", "json", "-o", str(report)])
    assert code in (EXIT_OK, EXIT_FINDINGS)
    patterns = ignore_patterns(PROJECT)
    found = Counter(
        {
            k: n
            for k, n in file_findings(json.loads(report.read_text("utf-8"))).items()
            if not is_ignored(k[1], patterns)
        }
    )
    new, gone = compare(found, load_baseline(self_scan.BASELINE))
    assert not new, "new findings in this repository; fix them or run scripts/self_scan.py --update"
    assert not gone, "the baseline lists findings that are gone; run scripts/self_scan.py --update"
