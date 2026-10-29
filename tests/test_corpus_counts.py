"""scripts/corpus_counts.py with recorded data: no repository is fetched.

The scan itself is replaced by a recorded JSON report (tests/golden/report.json), so
counting, the table, ``--save`` and ``--compare`` are tested without the network.
"""

import json
import shutil
from pathlib import Path

import corpus_counts
import pytest
from corpus_counts import Counts, build_parser, print_comparison, print_table, run, totals

from repovet import __version__
from repovet.cli import EXIT_ABORTED, EXIT_FINDINGS

GOLDEN_REPORT = Path(__file__).parent / "golden" / "report.json"
MANIFEST = """\
- name: alpha
  repo: octo/alpha
  commit: 1111111111111111111111111111111111111111
- name: beta
  repo: octo/beta
  commit: 2222222222222222222222222222222222222222
"""
# Counts as an earlier run recorded them with --save.
EARLIER: Counts = {
    "alpha": {
        "RC-AGENT-002": {"high": 1, "medium": 0, "low": 0},
        "RC-AGENT-020": {"high": 0, "medium": 3, "low": 0},
        "RC-DLX-001": {"high": 0, "medium": 0, "low": 2},
    },
    "beta": {"RC-AUTO-001": {"high": 1, "medium": 0, "low": 0}},
}

type Capture = pytest.CaptureFixture[str]


def test_arguments() -> None:
    args = build_parser().parse_args([])
    assert args.manifest == corpus_counts.MANIFEST
    assert (args.only, args.save, args.compare) == ([], None, None)
    args = build_parser().parse_args(
        ["--only", "flask", "--only", "ruff", "--save", "new.json", "--compare", "old.json"]
    )
    assert args.only == ["flask", "ruff"]
    assert (args.save, args.compare) == (Path("new.json"), Path("old.json"))
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--unknown"])
    assert exc.value.code == 2


def test_manifest_must_be_a_list(tmp_path: Path) -> None:
    manifest = tmp_path / "corpus.yaml"
    manifest.write_text("name: flask\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="expected a list"):
        corpus_counts.load_manifest(manifest)


def _recorded_scan(monkeypatch: pytest.MonkeyPatch, calls: list[list[str]]) -> None:
    """Replace the scan by copying the recorded report to the ``-o`` path."""

    def scan(argv: list[str]) -> int:
        calls.append(argv)
        shutil.copyfile(GOLDEN_REPORT, argv[argv.index("-o") + 1])
        return EXIT_FINDINGS

    monkeypatch.setattr(corpus_counts, "main", scan)


def test_scan_entry_counts_findings_per_rule_and_confidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    _recorded_scan(monkeypatch, calls)
    entry = {"name": "alpha", "repo": "octo/alpha", "commit": "1" * 40}
    assert corpus_counts.scan_entry(entry, tmp_path) == {
        "RC-AGENT-002": {"high": 1, "medium": 0, "low": 0},
        "RC-AGENT-020": {"high": 0, "medium": 2, "low": 0},
        "RC-AUTO-001": {"high": 1, "medium": 0, "low": 0},
        "RC-TRUST-001": {"high": 1, "medium": 0, "low": 0},
    }
    assert calls == [
        [
            "scan",
            "https://github.com/octo/alpha",
            "--ref",
            "1" * 40,
            "--offline",
            "--format",
            "json",
            "-o",
            str(tmp_path / "alpha.json"),
        ]
    ]


def test_scan_entry_reports_a_failed_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(corpus_counts, "main", lambda argv: EXIT_ABORTED)
    entry = {"name": "alpha", "repo": "octo/alpha", "commit": "1" * 40}
    assert corpus_counts.scan_entry(entry, tmp_path) == "scan failed with exit code 3"


def test_totals() -> None:
    assert totals(EARLIER) == {
        "RC-AGENT-002": 1,
        "RC-AGENT-020": 3,
        "RC-DLX-001": 2,
        "RC-AUTO-001": 1,
    }


def test_table_format(capsys: Capture) -> None:
    print_table(EARLIER)
    assert capsys.readouterr().out.splitlines() == [
        "rule           total         h/m/l  alpha   beta",
        "RC-AGENT-002       1         1/0/0      1      0",
        "RC-AGENT-020       3         0/3/0      3      0",
        "RC-AUTO-001        1         1/0/0      0      1",
        "RC-DLX-001         2         0/0/2      2      0",
    ]


def test_comparison_lists_only_changed_rules(capsys: Capture) -> None:
    later: Counts = {
        "alpha": {
            "RC-AGENT-002": {"high": 1, "medium": 0, "low": 0},
            "RC-AGENT-020": {"high": 0, "medium": 1, "low": 0},
            "RC-OBF-009": {"high": 0, "medium": 0, "low": 4},
        },
        "beta": {"RC-AUTO-001": {"high": 1, "medium": 0, "low": 0}},
    }
    print_comparison(EARLIER, later)
    assert capsys.readouterr().out.splitlines() == [
        "rule           before   after  change",
        "RC-AGENT-020        3       1      -2",
        "RC-DLX-001          2       0      -2",
        "RC-OBF-009          0       4      +4",
    ]
    print_comparison(EARLIER, EARLIER)
    assert capsys.readouterr().out == "no change in the number of findings per rule\n"


def test_save_then_compare_two_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    manifest = tmp_path / "corpus.yaml"
    manifest.write_text(MANIFEST, encoding="utf-8")
    calls: list[list[str]] = []
    _recorded_scan(monkeypatch, calls)
    saved = tmp_path / "now.json"
    assert run(["--manifest", str(manifest), "--save", str(saved)]) == 0
    first = capsys.readouterr()
    assert first.out.startswith(f"repovet {__version__}, 2 repositories\n")
    assert "scanning octo/alpha @ 111111111111 ..." in first.err
    payload = json.loads(saved.read_text(encoding="utf-8"))
    assert payload["repovet"] == __version__
    assert sorted(payload["counts"]) == ["alpha", "beta"]

    # A second run compared with the recorded earlier one; --only limits both sides.
    earlier = tmp_path / "earlier.json"
    earlier.write_text(json.dumps({"repovet": "0.1.0", "counts": EARLIER}), encoding="utf-8")
    assert run(["--manifest", str(manifest), "--only", "alpha", "--compare", str(earlier)]) == 0
    out = capsys.readouterr().out
    assert len(calls) == 3
    assert f"repovet {__version__}, 1 repositories" in out
    comparison = out.split(f"compared with repovet 0.1.0 ({earlier})\n", 1)[1]
    assert comparison.splitlines() == [
        "rule           before   after  change",
        "RC-AGENT-020        3       2      -1",
        "RC-AUTO-001         0       1      +1",
        "RC-DLX-001          2       0      -2",
        "RC-TRUST-001        0       1      +1",
    ]


def test_failed_scans_are_listed_and_set_the_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    manifest = tmp_path / "corpus.yaml"
    manifest.write_text(MANIFEST, encoding="utf-8")
    monkeypatch.setattr(corpus_counts, "main", lambda argv: EXIT_ABORTED)
    assert run(["--manifest", str(manifest)]) == 1
    captured = capsys.readouterr()
    assert "repovet" in captured.out and "0 repositories" in captured.out
    assert "alpha: scan failed with exit code 3" in captured.err
    assert "beta: scan failed with exit code 3" in captured.err
