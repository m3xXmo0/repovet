"""JSON and SARIF reports: golden output and schema validation (schemas are local files).

Regenerate the golden files after an intended change with
``REPOVET_UPDATE_GOLDEN=1 uv run pytest tests/test_report_formats.py`` and review the diff.
"""

import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft4Validator, Draft202012Validator

from helpers import builtin_rules, materialize
from repovet.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main
from repovet.engine.loader import Rule
from repovet.models import Location, Severity
from repovet.report import json_out, sarif
from test_terminal import sample_findings, sample_result

ROOT = Path(__file__).parent.parent
GOLDEN = Path(__file__).parent / "golden"
JSON_SCHEMA = json.loads((ROOT / "docs" / "report.schema.json").read_text(encoding="utf-8"))
SARIF_SCHEMA = json.loads(
    (Path(__file__).parent / "schemas" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8")
)
TASKS = '{"tasks": [{"label": "x", "runOptions": {"runOn": "folderOpen"}}]}'

type Capture = pytest.CaptureFixture[str]


def sample_rules() -> list[Rule]:
    return [r for r in builtin_rules().active() if r.id in {"RC-AUTO-001", "RC-AGENT-002"}]


def check_golden(name: str, text: str) -> None:
    path = GOLDEN / name
    if os.environ.get("REPOVET_UPDATE_GOLDEN"):
        path.write_bytes(text.encode("utf-8"))
    assert text == path.read_bytes().decode("utf-8")


def validate_json(report: dict[str, Any]) -> None:
    validator = Draft202012Validator(
        JSON_SCHEMA, format_checker=Draft202012Validator.FORMAT_CHECKER
    )
    errors = [e.message for e in validator.iter_errors(report)]
    assert errors == []


def validate_sarif(report: dict[str, Any]) -> None:
    errors = [
        f"{list(e.absolute_path)}: {e.message}"
        for e in Draft4Validator(SARIF_SCHEMA).iter_errors(report)
    ]
    assert errors == []


def test_schemas_are_valid() -> None:
    Draft202012Validator.check_schema(JSON_SCHEMA)
    Draft4Validator.check_schema(SARIF_SCHEMA)


def test_json_matches_golden_and_schema() -> None:
    text = json_out.render(sample_result(sample_findings()))
    check_golden("report.json", text)
    validate_json(json.loads(text))


def test_sarif_matches_golden_and_schema() -> None:
    text = sarif.render(sample_result(sample_findings()), sample_rules())
    check_golden("report.sarif", text)
    validate_sarif(json.loads(text))


@pytest.mark.parametrize("fmt", ["json", "sarif"])
def test_reports_are_ascii_and_sanitized(fmt: str) -> None:
    result = sample_result(sample_findings())
    text = json_out.render(result) if fmt == "json" else sarif.render(result, sample_rules())
    assert text.isascii()
    decoded = json.dumps(json.loads(text), ensure_ascii=False)
    assert "\x1b" not in decoded
    assert "\u202e" not in decoded
    assert "<U+E0048>" in decoded


def test_json_content() -> None:
    report: Any = json_out.build(sample_result(sample_findings()), Severity.MEDIUM)
    findings = report["findings"]
    assert [f["rule_id"] for f in findings] == [
        "RC-AGENT-002",
        "RC-AUTO-090",
        "RC-AGENT-020",
        "RC-AGENT-020",
        "RC-AUTO-001",
        "RC-DLX-001",
    ]
    # One entry per finding (the text report groups them) with its context label.
    assert [f["context"] for f in findings] == [None, None, "test", "test", None, None]
    assert findings[1]["chain"] == {
        "id": "chain-1",
        "steps": [
            {"path": "package.json", "line": 3},
            {"path": "x.js", "line": None},
            {"path": "x.sh", "line": 2},
        ],
    }
    assert [f["in_chain"] for f in findings] == [None, None, None, None, "chain-1", "chain-1"]
    summary = report["summary"]
    assert summary["hidden_below_min_severity"] == 3
    # The parts of the chain are listed but counted once, through the chain finding.
    assert (summary["findings"], summary["part_of_chains"]) == (4, 2)
    assert summary["by_severity"] == {"critical": 1, "high": 3, "medium": 0, "low": 0, "info": 0}
    assert "not proof" in str(report["disclaimer"])
    empty = json_out.build(sample_result([]))
    assert "not a guarantee" in str(empty["disclaimer"])
    validate_json(empty)


def test_sarif_mapping() -> None:
    report: Any = sarif.build(sample_result(sample_findings()), sample_rules())
    run = report["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert rules["RC-AGENT-002"]["properties"]["security-severity"] == "8.0"
    assert rules["RC-AGENT-002"]["defaultConfiguration"]["level"] == "error"
    results = run["results"]
    levels = ["error"] * 4 + ["warning"] * 2 + ["note"] * 3
    assert [r["level"] for r in results] == levels
    assert results[2]["properties"]["context"] == "test"
    assert "context" not in results[0]["properties"]
    # The chain finding links its steps; its parts name the chain.
    assert results[1]["properties"]["chain"] == "chain-1"
    related = results[1]["relatedLocations"]
    assert [r["physicalLocation"]["artifactLocation"]["uri"] for r in related] == [
        "package.json",
        "x.js",
        "x.sh",
    ]
    assert [r["properties"].get("inChain") for r in results[4:6]] == ["chain-1", "chain-1"]
    # Repository-wide finding (no location); unknown rule id has no ruleIndex.
    assert "locations" not in results[6] and "ruleIndex" not in results[6]
    location = results[0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"] == {"uri": "CLAUDE.md", "uriBaseId": "SRCROOT"}
    assert run["originalUriBaseIds"]["SRCROOT"]["uri"] == "file:///D:/src/demo/"
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert notes[1]["message"]["text"].endswith("(4)")


def test_sarif_uris_are_percent_encoded() -> None:
    odd = replace(sample_findings()[1], location=Location("dir name/a\u202eb.md", None))
    report: Any = sarif.build(sample_result([odd]), sample_rules())
    result = report["runs"][0]["results"][0]
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "dir%20name/a%E2%80%AEb.md"
    assert location["region"] == {"startLine": 1}
    assert result["properties"]["fileLevel"] is True
    validate_sarif(report)


def test_root_uri() -> None:
    assert sarif.root_uri("D:\\src\\demo") == "file:///D:/src/demo/"
    assert sarif.root_uri("/home/u/my repo") == "file:///home/u/my%20repo/"
    assert sarif.root_uri("relative/path") is None
    assert sarif.root_uri("/") == "file:///"


def test_sarif_uri_of_a_name_that_is_not_utf8() -> None:
    # POSIX file systems and Git trees can hold names that are not valid UTF-8; they
    # arrive with surrogate escapes and must not crash the SARIF output.
    odd = replace(sample_findings()[0], location=Location("bad\udcff.md", 1, None))
    report: Any = sarif.build(sample_result([odd]), sample_rules())
    location = report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "bad%FF.md"
    validate_sarif(report)


# --- CLI ---------------------------------------------------------------------


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return materialize(tmp_path / "repo", {".vscode/tasks.json": TASKS, "README.md": "hi\n"})


def test_cli_json_to_stdout(repo: Path, capsys: Capture) -> None:
    code = main(["scan", str(repo), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert code == EXIT_FINDINGS
    assert [f["rule_id"] for f in report["findings"]] == ["RC-AUTO-020"]
    assert report["findings"][0]["location"] == {
        "path": ".vscode/tasks.json",
        "line": 1,
        "column": None,
    }
    assert report["scan"]["rules_loaded"] == len(builtin_rules().active())
    validate_json(report)


def test_cli_sarif_to_file(repo: Path, tmp_path: Path, capsys: Capture) -> None:
    out = tmp_path / "out" / "report.sarif"
    out.parent.mkdir()
    code = main(["scan", str(repo), "--format", "sarif", "-o", str(out)])
    assert code == EXIT_FINDINGS
    assert capsys.readouterr().out == ""
    report = json.loads(out.read_text(encoding="utf-8"))
    validate_sarif(report)
    run = report["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == len(builtin_rules().active())
    assert [r["ruleId"] for r in run["results"]] == ["RC-AUTO-020"]


def test_cli_text_to_file_has_no_colors(repo: Path, tmp_path: Path, capsys: Capture) -> None:
    out = tmp_path / "report.txt"
    assert main(["scan", str(repo), "-o", str(out)]) == EXIT_FINDINGS
    text = out.read_bytes().decode("utf-8")
    assert "\x1b[" not in text
    assert "RC-AUTO-020" in text
    assert "\r\n" not in text


def test_cli_output_never_inside_target(repo: Path, tmp_path: Path, capsys: Capture) -> None:
    code = main(["scan", str(repo), "--format", "json", "-o", str(repo / "report.json")])
    assert code == EXIT_USAGE
    assert "outside the checked folder" in capsys.readouterr().err
    assert not (repo / "report.json").exists()
    assert main(["scan", str(repo), "-o", str(tmp_path / "missing" / "r.json")]) == EXIT_USAGE
    assert main(["scan", str(repo), "-o", str(tmp_path)]) == EXIT_USAGE


def test_cli_output_inside_target_under_another_name(repo: Path, capsys: Capture) -> None:
    # The same folder reached through another case (macOS, Windows) or a link is still
    # the checked folder.
    other = repo.parent / repo.name.upper()
    if not other.is_dir():
        try:
            other.symlink_to(repo, target_is_directory=True)
        except OSError:
            pytest.skip("cannot create a second name for the folder")
    code = main(["scan", str(other), "--format", "json", "-o", str(repo / "r.json")])
    assert code == EXIT_USAGE
    code = main(["scan", str(repo), "--format", "json", "-o", str(other / "r.json")])
    assert code == EXIT_USAGE
    assert not (repo / "r.json").exists()


def test_cli_min_severity_applies_to_json(repo: Path, capsys: Capture) -> None:
    code = main(["scan", str(repo), "--format", "json", "--min-severity", "critical"])
    report = json.loads(capsys.readouterr().out)
    assert code == EXIT_FINDINGS  # exit code does not depend on what is shown
    assert report["findings"] == []
    assert report["summary"]["hidden_below_min_severity"] == 1


def test_cli_clean_folder_json(tmp_path: Path, capsys: Capture) -> None:
    clean = materialize(tmp_path / "clean", {"README.md": "hello\n"})
    assert main(["scan", str(clean), "--format", "sarif"]) == EXIT_OK
    report = json.loads(capsys.readouterr().out)
    assert report["runs"][0]["results"] == []
    assert "not a guarantee" in report["runs"][0]["properties"]["disclaimer"]
