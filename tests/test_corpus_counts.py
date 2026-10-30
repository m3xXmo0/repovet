"""scripts/corpus_counts.py with recorded data: no repository is fetched.

The scan itself is replaced by a recorded JSON report (tests/golden/report.json), so
counting, the table, ``--save``, ``--compare`` and the baseline are tested without the
network. The reconstructions are replaced by fixed counts here; they are scanned for
real in tests/test_reconstructions.py.
"""

import json
import shutil
from pathlib import Path

import corpus_counts
import pytest
from corpus_counts import (
    Counts,
    build_parser,
    changes,
    print_changes,
    print_comparison,
    print_table,
    run,
    totals,
)

from repovet import __version__
from repovet.cli import EXIT_ABORTED, EXIT_FINDINGS, EXIT_USAGE

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

RECONSTRUCTED: Counts = {
    "demo-attack": {"RC-AUTO-001": {"high": 1, "medium": 0, "low": 0}},
    "quiet-attack": {},
}

type Capture = pytest.CaptureFixture[str]


@pytest.fixture(autouse=True)
def _no_real_scans(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Fixed reconstruction counts and no committed baseline in these tests."""
    monkeypatch.setattr(corpus_counts, "reconstruction_counts", lambda: RECONSTRUCTED)
    monkeypatch.setattr(corpus_counts, "BASELINE", tmp_path / "no-baseline.json")


def test_arguments() -> None:
    args = build_parser().parse_args([])
    assert args.manifest == corpus_counts.MANIFEST
    assert (args.only, args.save, args.compare) == ([], None, None)
    assert (args.offline_only, args.update_baseline) == (False, False)
    assert args.baseline == corpus_counts.BASELINE
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
    # Every finding of a rule counts, also the parts of a chain.
    assert corpus_counts.scan_entry(entry, tmp_path) == {
        "RC-AGENT-001": {"high": 2, "medium": 0, "low": 0},
        "RC-AGENT-002": {"high": 1, "medium": 0, "low": 0},
        "RC-AGENT-020": {"high": 0, "medium": 2, "low": 0},
        "RC-AUTO-001": {"high": 1, "medium": 0, "low": 0},
        "RC-AUTO-090": {"high": 1, "medium": 0, "low": 0},
        "RC-DLX-001": {"high": 1, "medium": 0, "low": 0},
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
    assert comparison.split("\n\n")[0].splitlines() == [
        "rule           before   after  change",
        "RC-AGENT-001        0       2      +2",
        "RC-AGENT-020        3       2      -1",
        "RC-AUTO-001         0       1      +1",
        "RC-AUTO-090         0       1      +1",
        "RC-DLX-001          2       1      -1",
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


def test_changes_per_entry_and_rule(capsys: Capture) -> None:
    later: Counts = {
        "alpha": {
            "RC-AGENT-002": {"high": 1, "medium": 0, "low": 0},
            "RC-AGENT-020": {"high": 0, "medium": 1, "low": 0},
        },
        "gamma": {"RC-OBF-009": {"high": 0, "medium": 0, "low": 4}},
    }
    assert changes(EARLIER, later) == [
        ("alpha", "RC-AGENT-020", 3, 1),
        ("alpha", "RC-DLX-001", 2, 0),
        ("beta", "RC-AUTO-001", 1, 0),
        ("gamma", "RC-OBF-009", 0, 4),
    ]
    print_changes(EARLIER, later)
    assert capsys.readouterr().out.splitlines() == [
        "       rule           before   after  change",
        "alpha  RC-AGENT-020        3       1      -2",
        "alpha  RC-DLX-001          2       0      -2",
        "beta   RC-AUTO-001         1       0      -1",
        "gamma  RC-OBF-009          0       4      +4",
    ]
    print_changes(EARLIER, EARLIER)
    assert capsys.readouterr().out == "no change against the baseline\n"


def _no_network(argv: list[str]) -> int:
    raise AssertionError("the real repositories must not be scanned")


def test_offline_only_without_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    monkeypatch.setattr(corpus_counts, "main", _no_network)
    baseline = tmp_path / "baseline.json"
    assert run(["--offline-only", "--baseline", str(baseline)]) == 0
    out = capsys.readouterr().out
    assert f"repovet {__version__}, 2 reconstructions" in out
    assert "demo-attack   RC-AUTO-001 1" in out
    assert "quiet-attack  -" in out
    assert f"no baseline for the reconstructions in {baseline}" in out
    assert not baseline.exists()


def test_update_then_compare_with_the_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    manifest = tmp_path / "corpus.yaml"
    manifest.write_text(MANIFEST, encoding="utf-8")
    _recorded_scan(monkeypatch, [])
    baseline = tmp_path / "baseline.json"
    common = ["--manifest", str(manifest), "--baseline", str(baseline)]
    assert run([*common, "--update-baseline"]) == 0
    assert f"baseline written: {baseline} (real, reconstructions)" in capsys.readouterr().out
    written = json.loads(baseline.read_text(encoding="utf-8"))
    assert list(written) == ["real", "reconstructions"]
    assert written["real"]["repovet"] == __version__
    assert sorted(written["real"]["counts"]) == ["alpha", "beta"]
    assert written["reconstructions"]["counts"] == RECONSTRUCTED

    # Same results: no change in either part, and the file is not touched without the flag.
    before = baseline.read_text(encoding="utf-8")
    assert run(common) == 0
    out = capsys.readouterr().out
    assert out.count("no change against the baseline") == 2
    assert baseline.read_text(encoding="utf-8") == before

    # A changed reconstruction shows up per entry and rule.
    changed: Counts = {"demo-attack": {}, "quiet-attack": {"RC-OBF-009": {"low": 2}}}
    monkeypatch.setattr(corpus_counts, "reconstruction_counts", lambda: changed)
    monkeypatch.setattr(corpus_counts, "main", _no_network)
    assert run(["--offline-only", "--baseline", str(baseline)]) == 0
    out = capsys.readouterr().out
    assert f"reconstructions against the baseline (repovet {__version__}):" in out
    assert "demo-attack   RC-AUTO-001         1       0      -1" in out
    assert "quiet-attack  RC-OBF-009          0       2      +2" in out

    # --offline-only replaces only the reconstruction part.
    assert run(["--offline-only", "--baseline", str(baseline), "--update-baseline"]) == 0
    assert "(reconstructions)" in capsys.readouterr().out
    updated = json.loads(baseline.read_text(encoding="utf-8"))
    assert updated["real"] == written["real"]
    assert updated["reconstructions"]["counts"] == changed


def test_baseline_is_not_updated_after_failed_scans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    manifest = tmp_path / "corpus.yaml"
    manifest.write_text(MANIFEST, encoding="utf-8")
    monkeypatch.setattr(corpus_counts, "main", lambda argv: EXIT_ABORTED)
    baseline = tmp_path / "baseline.json"
    args = ["--manifest", str(manifest), "--baseline", str(baseline), "--update-baseline"]
    assert run(args) == 1
    assert "baseline not updated" in capsys.readouterr().err
    assert not baseline.exists()


@pytest.mark.parametrize(
    "argv",
    [
        ["--update-baseline", "--only", "alpha"],
        ["--offline-only", "--only", "alpha"],
        ["--offline-only", "--save", "x.json"],
        ["--offline-only", "--compare", "x.json"],
    ],
)
def test_contradicting_options(
    argv: list[str], monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    monkeypatch.setattr(corpus_counts, "main", _no_network)
    assert run(argv) == EXIT_USAGE
    assert capsys.readouterr().err


def test_invalid_baseline(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"other": {}}', encoding="utf-8")
    with pytest.raises(SystemExit, match="expected an object"):
        corpus_counts.load_baseline(baseline)
