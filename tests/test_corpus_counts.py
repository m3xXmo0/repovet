"""Versioned corpus records, shared finding comparisons and deliberate migration."""

import json
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import quote

import corpus_counts
import pytest
from jsonschema import Draft202012Validator

from repovet import __version__
from repovet.cli import EXIT_ABORTED, EXIT_FINDINGS, EXIT_USAGE

ROOT = Path(__file__).parent.parent
DIGEST = "a" * 64
MANIFEST = """\
- name: alpha
  repo: octo/alpha
  commit: 1111111111111111111111111111111111111111
- name: beta
  repo: octo/beta
  commit: 2222222222222222222222222222222222222222
"""
type Capture = pytest.CaptureFixture[str]


def finding(
    fingerprint: str = "1", *, path: str = "setup.sh", severity: str = "medium"
) -> dict[str, Any]:
    return {
        "rule_id": "RC-DLX-001",
        "title": "Example",
        "category": "danger",
        "area": "download_exec",
        "severity": severity,
        "confidence": "high",
        "location": {"path": path, "uri": quote(path, safe="/"), "line": 1, "column": None},
        "message": "do not copy this payload",
        "evidence": "PRIVATE_FIXTURE_TEXT",
        "rationale": "Example",
        "recommendation": "Review",
        "references": [],
        "context": None,
        "chain": None,
        "in_chain": None,
        "fingerprint": "repovet:v1:" + fingerprint * 64,
    }


def section(records: dict[str, list[dict[str, Any]]] | None = None) -> corpus_counts.Section:
    return corpus_counts.Section(__version__, DIGEST, records or {"quiet": []})


@pytest.fixture(autouse=True)
def no_real_scans(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(corpus_counts, "BASELINE", tmp_path / "no-baseline.json")
    monkeypatch.setattr(corpus_counts, "current_digest", lambda: DIGEST, raising=False)
    monkeypatch.setattr(corpus_counts, "reconstruction_section", section, raising=False)


def recorded_scan(monkeypatch: pytest.MonkeyPatch, calls: list[list[str]]) -> None:
    def scan(argv: list[str]) -> int:
        calls.append(argv)
        Path(argv[argv.index("-o") + 1]).write_text(
            json.dumps(
                {
                    "schema_version": "1.5",
                    "tool": {"name": "repovet", "version": __version__},
                    "ruleset_digest": DIGEST,
                    "findings": [finding()],
                    "coverage": [],
                    "scan": {"snapshot": None},
                }
            ),
            encoding="utf-8",
        )
        return EXIT_FINDINGS

    monkeypatch.setattr(corpus_counts, "main", scan)


def test_arguments() -> None:
    args = corpus_counts.build_parser().parse_args([])
    assert (args.only, args.save, args.compare) == ([], None, None)
    assert not args.offline_only and not args.update_baseline


def test_scan_entry_retains_count_wrapper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    recorded_scan(monkeypatch, calls)
    assert corpus_counts.scan_entry(
        {"name": "alpha", "repo": "octo/alpha", "commit": "1" * 40}, tmp_path
    ) == {"RC-DLX-001": {"high": 1, "medium": 0, "low": 0}}
    assert calls[0][0:2] == ["scan", "https://github.com/octo/alpha"]


def test_scan_failure_does_not_write_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    manifest = tmp_path / "corpus.yaml"
    manifest.write_text(MANIFEST, encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    monkeypatch.setattr(corpus_counts, "main", lambda argv: EXIT_ABORTED)
    assert (
        corpus_counts.run(
            ["--manifest", str(manifest), "--baseline", str(baseline), "--update-baseline"]
        )
        == 1
    )
    assert not baseline.exists()
    assert "baseline not updated" in capsys.readouterr().err


def test_compact_records_do_not_publish_payload_text() -> None:
    record = corpus_counts.compact_finding(finding())
    assert record["fingerprint"] == "repovet:v1:" + "1" * 64
    assert record["location"]["path"] == "setup.sh"
    assert record["message"] == "" and record["evidence"] is None
    assert "PRIVATE_FIXTURE_TEXT" not in json.dumps(record)


def test_baseline_round_trip_is_versioned_and_schema_valid(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    expected = section({"alpha": [corpus_counts.compact_finding(finding())], "quiet": []})
    corpus_counts.write_baseline(baseline, {"real": expected})
    data = json.loads(baseline.read_text(encoding="utf-8"))
    assert data["schema_version"] == "2.0"
    assert data["real"]["tool"] == {"name": "repovet", "version": __version__}
    assert data["real"]["ruleset_digest"] == DIGEST
    schema = json.loads((ROOT / "docs" / "corpus-baseline.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(data)
    loaded = corpus_counts.load_baseline(baseline)
    assert loaded["real"].counts == {
        "alpha": {"RC-DLX-001": {"high": 1, "medium": 0, "low": 0}},
        "quiet": {},
    }


def test_counts_cannot_disagree_with_stored_findings(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    corpus_counts.write_baseline(
        baseline, {"real": section({"alpha": [corpus_counts.compact_finding(finding())]})}
    )
    data = json.loads(baseline.read_text(encoding="utf-8"))
    data["real"]["counts"]["alpha"]["RC-DLX-001"]["high"] = 9
    baseline.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match=r"counts.*findings"):
        corpus_counts.load_baseline(baseline)


@pytest.mark.parametrize(
    "legacy", [{"real": {"repovet": "0.4.1", "counts": {}}}, {"repovet": "0.4.1", "counts": {}}]
)
def test_counts_only_baseline_is_rejected(tmp_path: Path, legacy: dict[str, Any]) -> None:
    baseline = tmp_path / "old.json"
    baseline.write_text(json.dumps(legacy), encoding="utf-8")
    with pytest.raises(ValueError, match="regenerate"):
        corpus_counts.load_baseline(baseline)


def test_explicit_offline_migration_discards_old_real_section(
    tmp_path: Path, capsys: Capture
) -> None:
    baseline = tmp_path / "old.json"
    baseline.write_text(json.dumps({"real": {"repovet": "0.4.1", "counts": {}}}), encoding="utf-8")
    assert (
        corpus_counts.run(["--offline-only", "--baseline", str(baseline), "--update-baseline"]) == 0
    )
    data = json.loads(baseline.read_text(encoding="utf-8"))
    assert data["schema_version"] == "2.0" and "real" not in data
    assert "discarded" in capsys.readouterr().err


def test_offline_update_preserves_valid_real_section(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    old = section({"alpha": [corpus_counts.compact_finding(finding())]})
    corpus_counts.write_baseline(baseline, {"real": old})
    assert (
        corpus_counts.run(["--offline-only", "--baseline", str(baseline), "--update-baseline"]) == 0
    )
    assert corpus_counts.load_baseline(baseline)["real"].records == old.records


def test_equal_counts_can_still_have_new_and_absent_findings(capsys: Capture) -> None:
    before = section({"alpha": [corpus_counts.compact_finding(finding("1"))]})
    after = section({"alpha": [corpus_counts.compact_finding(finding("2"))]})
    assert before.counts == after.counts
    assert corpus_counts.print_finding_changes(before, after) == 0
    out = capsys.readouterr().out
    assert "RC-DLX-001" in out and "new 1" in out and "absent 1" in out


def test_shared_matcher_handles_line_shift(capsys: Capture) -> None:
    first = corpus_counts.compact_finding(finding())
    second = deepcopy(first)
    second["location"]["line"] = 20
    assert (
        corpus_counts.print_finding_changes(
            section({"alpha": [first]}), section({"alpha": [second]})
        )
        == 0
    )
    assert "no change in finding identities" in capsys.readouterr().out


def test_shared_matcher_reports_severity_promotion(capsys: Capture) -> None:
    old = corpus_counts.compact_finding(finding(severity="medium"))
    new = corpus_counts.compact_finding(finding(severity="high"))
    assert (
        corpus_counts.print_finding_changes(section({"alpha": [old]}), section({"alpha": [new]}))
        == 0
    )
    assert "worsened 1" in capsys.readouterr().out


def test_version_and_rule_digest_changes_are_explicit(capsys: Capture) -> None:
    old = corpus_counts.Section("0.0.0", "b" * 64, {"quiet": []})
    assert corpus_counts.print_finding_changes(old, section()) == 0
    err = capsys.readouterr().err
    assert "version" in err and "ruleset" in err


def test_save_and_compare_use_record_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    manifest = tmp_path / "corpus.yaml"
    manifest.write_text(MANIFEST, encoding="utf-8")
    recorded_scan(monkeypatch, [])
    saved = tmp_path / "saved.json"
    assert corpus_counts.run(["--manifest", str(manifest), "--save", str(saved)]) == 0
    assert corpus_counts.load_baseline(saved)["real"].records
    assert corpus_counts.run(["--manifest", str(manifest), "--compare", str(saved)]) == 0
    assert "no change in finding identities" in capsys.readouterr().out


def test_changed_rule_metadata_during_scan_is_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    manifest = tmp_path / "corpus.yaml"
    manifest.write_text(MANIFEST, encoding="utf-8")
    recorded_scan(monkeypatch, [])
    monkeypatch.setattr(corpus_counts, "current_digest", lambda: "b" * 64)
    assert corpus_counts.run(["--manifest", str(manifest)]) == 1
    assert "metadata changed" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        ["--update-baseline", "--only", "alpha"],
        ["--offline-only", "--only", "alpha"],
        ["--offline-only", "--save", "x.json"],
        ["--offline-only", "--compare", "x.json"],
    ],
)
def test_contradicting_options(argv: list[str], capsys: Capture) -> None:
    assert corpus_counts.run(argv) == EXIT_USAGE
    assert capsys.readouterr().err


def test_ambiguous_occurrences_are_not_a_success(capsys: Capture) -> None:
    before = section(
        {
            "alpha": [
                corpus_counts.compact_finding(finding(path="a.sh")),
                corpus_counts.compact_finding(finding(path="b.sh")),
            ]
        }
    )
    after = section(
        {
            "alpha": [
                corpus_counts.compact_finding(finding(path="c.sh")),
                corpus_counts.compact_finding(finding(path="d.sh")),
            ]
        }
    )
    assert corpus_counts.print_finding_changes(before, after) == EXIT_ABORTED
    assert "alpha: comparison issues: 1 blocking, 0 not checked" in capsys.readouterr().out


def test_payload_text_in_stored_baseline_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    corpus_counts.write_baseline(path, {"real": section({"alpha": [finding()]})})
    data = json.loads(path.read_text(encoding="utf-8"))
    data["real"]["findings"]["alpha"][0]["message"] = "unwanted external text"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="omit payload"):
        corpus_counts.load_baseline(path)


def test_metadata_change_between_sections_prevents_baseline_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    manifest = tmp_path / "corpus.yaml"
    manifest.write_text(MANIFEST, encoding="utf-8")
    recorded_scan(monkeypatch, [])
    monkeypatch.setattr(
        corpus_counts,
        "reconstruction_section",
        lambda: corpus_counts.Section(__version__, "b" * 64, {"quiet": []}),
    )
    baseline = tmp_path / "baseline.json"
    assert (
        corpus_counts.run(
            ["--manifest", str(manifest), "--baseline", str(baseline), "--update-baseline"]
        )
        == 1
    )
    assert not baseline.exists()
    assert "between corpus sections" in capsys.readouterr().err


EARLIER: corpus_counts.Counts = {
    "alpha": {
        "RC-AGENT-002": {"high": 1, "medium": 0, "low": 0},
        "RC-AGENT-020": {"high": 0, "medium": 3, "low": 0},
        "RC-DLX-001": {"high": 0, "medium": 0, "low": 2},
    },
    "beta": {"RC-AUTO-001": {"high": 1, "medium": 0, "low": 0}},
}


def test_totals() -> None:
    assert corpus_counts.totals(EARLIER) == {
        "RC-AGENT-002": 1,
        "RC-AGENT-020": 3,
        "RC-DLX-001": 2,
        "RC-AUTO-001": 1,
    }


def test_table_format(capsys: Capture) -> None:
    corpus_counts.print_table(EARLIER)
    assert capsys.readouterr().out.splitlines() == [
        "rule           total         h/m/l  alpha   beta",
        "RC-AGENT-002       1         1/0/0      1      0",
        "RC-AGENT-020       3         0/3/0      3      0",
        "RC-AUTO-001        1         1/0/0      0      1",
        "RC-DLX-001         2         0/0/2      2      0",
    ]


def test_comparison_lists_only_changed_rules(capsys: Capture) -> None:
    later: corpus_counts.Counts = {
        "alpha": {
            "RC-AGENT-002": {"high": 1, "medium": 0, "low": 0},
            "RC-AGENT-020": {"high": 0, "medium": 1, "low": 0},
            "RC-OBF-009": {"high": 0, "medium": 0, "low": 4},
        },
        "beta": {"RC-AUTO-001": {"high": 1, "medium": 0, "low": 0}},
    }
    corpus_counts.print_comparison(EARLIER, later)
    assert capsys.readouterr().out.splitlines() == [
        "rule           before   after  change",
        "RC-AGENT-020        3       1      -2",
        "RC-DLX-001          2       0      -2",
        "RC-OBF-009          0       4      +4",
    ]
    corpus_counts.print_comparison(EARLIER, EARLIER)
    assert capsys.readouterr().out == "no change in the number of findings per rule\n"


def test_changes_per_entry_and_rule(capsys: Capture) -> None:
    later: corpus_counts.Counts = {
        "alpha": {
            "RC-AGENT-002": {"high": 1, "medium": 0, "low": 0},
            "RC-AGENT-020": {"high": 0, "medium": 1, "low": 0},
        },
        "gamma": {"RC-OBF-009": {"high": 0, "medium": 0, "low": 4}},
    }
    assert corpus_counts.changes(EARLIER, later) == [
        ("alpha", "RC-AGENT-020", 3, 1),
        ("alpha", "RC-DLX-001", 2, 0),
        ("beta", "RC-AUTO-001", 1, 0),
        ("gamma", "RC-OBF-009", 0, 4),
    ]
    corpus_counts.print_changes(EARLIER, later)
    assert capsys.readouterr().out.splitlines() == [
        "       rule           before   after  change",
        "alpha  RC-AGENT-020        3       1      -2",
        "alpha  RC-DLX-001          2       0      -2",
        "beta   RC-AUTO-001         1       0      -1",
        "gamma  RC-OBF-009          0       4      +4",
    ]
    corpus_counts.print_changes(EARLIER, EARLIER)
    assert capsys.readouterr().out == "no change against the baseline\n"


def test_compact_record_retains_lossless_uri_beyond_the_display_limit() -> None:
    from repovet.report.json_in import finding_from_data

    raw_path = "odd/\u202e" + "a" * 300 + ".sh"
    original = finding(path=raw_path)
    compact = corpus_counts.compact_finding(original)
    assert compact["location"]["path"] != raw_path
    assert "%E2%80%AE" in compact["location"]["uri"]
    parsed = finding_from_data(compact)
    assert parsed.location is not None and parsed.location.path == raw_path


def coverage_record(path: str = "setup.sh") -> dict[str, Any]:
    return {
        "scope": "file",
        "status": "partial",
        "reason": "DUMMY PARSER DETAIL",
        "count": 1,
        "sample": [path],
        "paths": [path],
        "uris": [quote(path, safe="/")],
    }


def git_snapshot(content: str) -> dict[str, str]:
    return {".": "40000:" + content * 40, "setup.sh": "100644:" + content * 40}


def test_compact_coverage_is_idempotent_without_copying_foreign_reason() -> None:
    from repovet.report.json_in import coverage_from_data

    path = "odd/\u202e" + "a" * 300 + ".sh"
    stored = corpus_counts.compact_coverage(coverage_record(path))
    assert stored == corpus_counts.compact_coverage(stored)
    assert stored["reason"].startswith("sha256:")
    assert "DUMMY PARSER DETAIL" not in json.dumps(stored)
    assert coverage_from_data(stored).paths == (path,)


def test_changed_capped_entry_uses_shared_coverage_gate(capsys: Capture) -> None:
    old = corpus_counts.Section(
        __version__, DIGEST, {"alpha": []}, {"alpha": []}, {"alpha": git_snapshot("1")}
    )
    gap = corpus_counts.compact_coverage(coverage_record())
    new = corpus_counts.Section(
        __version__, DIGEST, {"alpha": []}, {"alpha": [gap]}, {"alpha": git_snapshot("2")}
    )
    assert corpus_counts.print_finding_changes(old, new) == EXIT_ABORTED
    assert "alpha: comparison issues: 1 blocking, 0 not checked" in capsys.readouterr().out


def test_unchanged_capped_entry_does_not_block(capsys: Capture) -> None:
    gap = corpus_counts.compact_coverage(coverage_record())
    old = corpus_counts.Section(
        __version__, DIGEST, {"alpha": []}, {"alpha": [gap]}, {"alpha": git_snapshot("1")}
    )
    assert corpus_counts.print_finding_changes(old, old) == 0
    # A gap that did not change is listed but does not block the comparison.
    out = capsys.readouterr().out
    assert "alpha: comparison issues: 0 blocking, 1 not checked" in out
    assert "unresolved" not in out


def test_missing_snapshot_is_explicit_without_inventing_changed_paths(capsys: Capture) -> None:
    assert corpus_counts.print_finding_changes(section(), section()) == 0
    assert "without proof of file changes" in capsys.readouterr().err


def test_baseline_transports_complete_coverage_and_raw_snapshot_keys(tmp_path: Path) -> None:
    raw_path = "odd/\u202e" + "a" * 300 + ".sh"
    gap = corpus_counts.compact_coverage(coverage_record(raw_path))
    snapshot = {".": "40000:" + "1" * 40, raw_path: "100644:" + "2" * 40}
    stored = corpus_counts.Section(
        __version__, DIGEST, {"alpha": []}, {"alpha": [gap]}, {"alpha": snapshot}
    )
    path = tmp_path / "baseline.json"
    corpus_counts.write_baseline(path, {"real": stored})
    loaded = corpus_counts.load_baseline(path)["real"]
    assert loaded.snapshots["alpha"] == snapshot
    assert loaded.coverage["alpha"] == [gap]
    data = json.loads(path.read_text(encoding="utf-8"))
    assert quote(raw_path, safe="/") in data["real"]["snapshots"]["alpha"]
    schema = json.loads((ROOT / "docs" / "corpus-baseline.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(data)
