"""scripts/fp_benchmark.py without the network: recorded search answers and reports.

The committed docs/fp-benchmark.md must be exactly what the script renders from
docs/fp-benchmark.json, so its numbers cannot be edited by hand.
"""

import json
import sys
from pathlib import Path
from typing import Any

import fp_benchmark
import pytest
from corpus_counts import compact_coverage
from fp_benchmark import (
    area_lines,
    area_table,
    headline,
    most_starred,
    render_markdown,
    rule_table,
    run,
    summarize,
)

from github_fake import Answer, FakeTransport
from repovet import __version__
from repovet.cli import EXIT_ABORTED, EXIT_FINDINGS, EXIT_OK, EXIT_USAGE
from repovet.engine.loader import load_rules
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
    # The two parts of the chain in the golden report are not counted again.
    parts = sum(1 for f in report["findings"] if f["in_chain"])
    assert (total, summary["chain_parts"]) == (len(report["findings"]) - parts, parts)
    assert list(summary["findings"]) == sorted(summary["findings"])


def test_area_table() -> None:
    finding = {"severity": "high", "high": 1, "medium": 0, "low": 0, "severities": {"high": 1}}
    data = {
        "repositories": [
            {"repo": "a/b", "findings": {"RC-DLX-001": finding, "RC-DLX-007": finding}},
            {"repo": "c/d", "findings": {"RC-AGENT-028": finding}},
        ],
        "skipped": [],
    }
    rows = {row["area"]: row for row in area_table(data)}
    assert (rows["download_exec"]["high"], rows["download_exec"]["repos"]) == (2, 1)
    assert (rows["agents"]["high"], rows["trust"]["repos"]) == (1, 0)
    assert area_lines(data)[2].startswith("| autorun | 0 | 0 |")


def test_findings_below_their_rule_severity_are_counted_at_their_own() -> None:
    finding = {"rule_id": "RC-AGENT-020", "severity": "low", "confidence": "low"}
    report = {
        "findings": [finding, {**finding, "severity": "high", "confidence": "medium"}, finding],
        "scan": {"files_scanned": 3},
    }
    entry = summarize(report)["findings"]["RC-AGENT-020"]
    assert entry["severity"] == "high"
    assert entry["severities"] == {"low": 2, "high": 1}
    data = {"repositories": [{"repo": "o/r", "findings": {"RC-AGENT-020": entry}}], "skipped": []}
    assert (headline(data)["high"], headline(data)["low"], headline(data)["repos_high"]) == (
        1,
        2,
        1,
    )
    (row,) = rule_table(data)
    assert fp_benchmark.severity_cell(row) == "high 1, low 2"
    assert fp_benchmark.severity_cell({**row, "severities": {"low": 3}}) == "low"
    all_low = {
        "repositories": [{"repo": "o/r", "findings": {"X": {**entry, "severities": {"low": 3}}}}],
        "skipped": [],
    }
    assert headline(all_low)["repos_high"] == 0


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
        Path(argv[argv.index("-o") + 1]).write_text(json.dumps(_raw_report()), encoding="utf-8")
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


def _finding(identity: str = "1", *, line: int = 1) -> dict[str, Any]:
    return {
        "rule_id": "RC-DLX-001",
        "title": "Example",
        "category": "danger",
        "area": "download_exec",
        "severity": "medium",
        "confidence": "high",
        "location": {"path": "setup.sh", "line": line, "column": None},
        "message": "DUMMY_EXTERNAL_PAYLOAD",
        "evidence": "DUMMY_EXTERNAL_PAYLOAD",
        "rationale": "Example",
        "recommendation": "Review",
        "references": ["https://example.invalid/reference"],
        "context": None,
        "chain": None,
        "in_chain": None,
        "fingerprint": "repovet:v1:" + identity * 64,
    }


def _raw_report(*, digest: str | None = None) -> dict[str, Any]:
    return {
        "tool": {"name": "repovet", "version": __version__},
        "ruleset_digest": digest or load_rules().digest,
        "facts": {"source": {"commit": "a" * 40}},
        "scan": {
            "files_scanned": 1,
            "snapshot": {".": "40000:" + "3" * 40, "setup.sh": "100644:" + "2" * 40},
        },
        "coverage": [],
        "findings": [_finding()],
    }


def _new_data(identity: str = "1", *, line: int = 1) -> dict[str, Any]:
    report = _raw_report(digest="a" * 64)
    report["findings"] = [_finding(identity, line=line)]
    report["scan"]["snapshot"]["setup.sh"] = "100644:" + identity * 40
    entry = summarize(report, include_records=True)
    entry.pop("tool_version")
    entry.pop("ruleset_digest")
    return {
        **DATA,
        "schema_version": "2.0",
        "repovet": __version__,
        "ruleset_digest": "a" * 64,
        "repositories": [{"repo": "octo/alpha", "stars": 300, **entry}],
        "skipped": [],
    }


def test_summarize_persists_compact_counted_records() -> None:
    report = _raw_report()
    report["findings"].append({**_finding("2"), "in_chain": "chain-1"})
    summary = summarize(report, include_records=True)
    assert summary["ruleset_digest"] == report["ruleset_digest"]
    assert summary["tool_version"] == __version__
    assert len(summary["finding_records"]) == 1
    stored = summary["finding_records"][0]
    assert stored["fingerprint"] == _finding()["fingerprint"]
    assert stored["message"] == "" and stored["evidence"] is None
    assert stored["references"] == []
    assert "DUMMY_EXTERNAL_PAYLOAD" not in json.dumps(summary)


def test_individual_comparison_uses_shared_identity_matcher(
    capsys: pytest.CaptureFixture[str],
) -> None:
    before, after = _new_data(), _new_data("2")
    assert before["repositories"][0]["findings"] == after["repositories"][0]["findings"]
    assert fp_benchmark.compare_runs(before, after) == EXIT_OK
    out = capsys.readouterr().out
    assert "new 1" in out and "absent 1" in out
    assert fp_benchmark.compare_runs(before, _new_data(line=20)) == EXIT_OK
    assert "no change in finding identities" in capsys.readouterr().out


def test_benchmark_comparison_warns_about_commit_and_rule_drift(
    capsys: pytest.CaptureFixture[str],
) -> None:
    before, after = _new_data(), _new_data()
    after["repositories"][0]["commit"] = "b" * 40
    after["ruleset_digest"] = "b" * 64
    assert fp_benchmark.compare_runs(before, after) == EXIT_OK
    err = capsys.readouterr().err
    assert "commit" in err and "octo/alpha" in err and "ruleset" in err


def test_legacy_benchmark_comparison_is_explicitly_aggregate_only(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert fp_benchmark.compare_runs(DATA, _new_data()) == EXIT_OK
    out = capsys.readouterr().out
    assert "aggregate comparison only" in out
    assert "finding identities unavailable" in out
    assert "no change in finding identities" not in out


def test_benchmark_rejects_payloads_in_stored_records() -> None:
    before, after = _new_data(), _new_data()
    before["repositories"][0]["finding_records"][0]["evidence"] = "DUMMY_EXTERNAL_PAYLOAD"
    with pytest.raises(ValueError, match="payload"):
        fp_benchmark.compare_runs(before, after)


def test_render_only_can_compare_without_scanning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    previous, current, markdown = tmp_path / "old.json", tmp_path / "new.json", tmp_path / "b.md"
    previous.write_text(json.dumps(_new_data()), encoding="utf-8")
    current.write_text(json.dumps(_new_data("2")), encoding="utf-8")
    monkeypatch.setattr(fp_benchmark, "main", lambda _args: pytest.fail("unexpected scan"))
    assert (
        run(
            [
                "--render-only",
                "--data",
                str(current),
                "--markdown",
                str(markdown),
                "--compare",
                str(previous),
            ]
        )
        == EXIT_OK
    )
    assert "new 1" in capsys.readouterr().out
    assert "Ruleset digest" in markdown.read_text(encoding="utf-8")


def test_skipped_repository_is_not_reported_as_resolved(
    capsys: pytest.CaptureFixture[str],
) -> None:
    before, after = _new_data(), _new_data()
    before["repositories"].append({**before["repositories"][0], "repo": "octo/beta"})
    after["skipped"] = [{"repo": "octo/beta", "stars": 1, "reason": "larger than limit"}]
    assert fp_benchmark.compare_runs(before, after) == EXIT_OK
    captured = capsys.readouterr()
    assert "not comparable" in captured.err and "octo/beta" in captured.err
    assert "absent" not in captured.out


def test_metadata_change_during_benchmark_prevents_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(
        {SEARCH.format(page=1, per_page=1): Answer({"items": [_item("octo/alpha", 1)]})}
    )

    def scan(argv: list[str]) -> int:
        Path(argv[argv.index("-o") + 1]).write_text(
            json.dumps(_raw_report(digest="b" * 64)), encoding="utf-8"
        )
        return EXIT_FINDINGS

    monkeypatch.setattr(fp_benchmark, "main", scan)
    data, markdown = tmp_path / "b.json", tmp_path / "b.md"
    assert (
        run(["-n", "1", "--data", str(data), "--markdown", str(markdown)], client=client)
        == EXIT_ABORTED
    )
    assert not data.exists() and not markdown.exists()


def _file_gap() -> dict[str, Any]:
    return compact_coverage(
        {
            "scope": "file",
            "status": "skipped",
            "reason": "PRIVATE_DUMMY_PARSE_PAYLOAD",
            "count": 1,
            "sample": ["setup.sh"],
            "paths": ["setup.sh"],
            "uris": ["setup.sh"],
        }
    )


def test_benchmark_comparison_blocks_changed_unchecked_file() -> None:
    before, after = _new_data(), _new_data("2")
    after["repositories"][0]["coverage_records"] = [_file_gap()]
    assert "PRIVATE_DUMMY_PARSE_PAYLOAD" not in json.dumps(after)
    assert fp_benchmark.compare_runs(before, after) == EXIT_ABORTED


def test_benchmark_comparison_does_not_block_unchanged_unchecked_file() -> None:
    before, after = _new_data(), _new_data()
    for data in (before, after):
        data["repositories"][0]["coverage_records"] = [_file_gap()]
    assert fp_benchmark.compare_runs(before, after) == EXIT_OK


def test_new_benchmark_metadata_is_validated() -> None:
    before, after = _new_data(), _new_data()
    before["ruleset_digest"] = "invalid"
    with pytest.raises(ValueError, match="digest"):
        fp_benchmark.compare_runs(before, after)


def test_missing_comparison_file_fails_before_any_network(tmp_path: Path) -> None:
    assert run(["--compare", str(tmp_path / "missing.json")]) == EXIT_USAGE


def test_compare_loads_old_data_before_overwriting_same_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data, markdown = tmp_path / "b.json", tmp_path / "b.md"
    data.write_text(json.dumps(_new_data()), encoding="utf-8")
    client = _client(
        {SEARCH.format(page=1, per_page=1): Answer({"items": [_item("octo/alpha", 1)]})}
    )

    def scan(argv: list[str]) -> int:
        report = _raw_report()
        report["findings"] = [_finding("2")]
        Path(argv[argv.index("-o") + 1]).write_text(json.dumps(report), encoding="utf-8")
        return EXIT_FINDINGS

    monkeypatch.setattr(fp_benchmark, "main", scan)
    assert (
        run(
            ["-n", "1", "--data", str(data), "--markdown", str(markdown), "--compare", str(data)],
            client=client,
        )
        == EXIT_OK
    )
    out = capsys.readouterr().out
    assert "new 1" in out and "absent 1" in out


def test_benchmark_without_common_scans_is_incomplete() -> None:
    before, after = _new_data(), _new_data()
    after["repositories"][0]["repo"] = "octo/beta"
    assert fp_benchmark.compare_runs(before, after) == EXIT_ABORTED


def test_benchmark_rejects_counts_not_derived_from_records() -> None:
    before, after = _new_data(), _new_data()
    before["repositories"][0]["findings"]["RC-DLX-001"]["high"] = 2
    with pytest.raises(ValueError, match="aggregates"):
        fp_benchmark.compare_runs(before, after)
