"""Meta-test: every rule has positive and negative cases, and they behave as expected."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from gitrepo import build_repo, expand_history
from helpers import builtin_rules, can_create, materialize, scan
from repovet.models import CoverageStatus

CASES_DIR = Path(__file__).parent / "rule_cases"
_CASE_KEYS = {"positive", "negative"}
_ENTRY_KEYS = {"name", "files", "history", "github", "expect", "requires"}


def load_cases() -> dict[str, dict[str, list[dict[str, Any]]]]:
    cases: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for path in sorted(CASES_DIR.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for rule_id, spec in data.items():
            if rule_id in cases:
                raise ValueError(f"{path.name}: cases for {rule_id} defined twice")
            cases[rule_id] = spec
    return cases


CASES = load_cases()


def _params() -> Iterator[Any]:
    for rule_id, spec in CASES.items():
        for kind in ("positive", "negative"):
            for case in spec.get(kind) or []:
                yield pytest.param(rule_id, kind, case, id=f"{rule_id}:{kind}:{case['name']}")


def test_every_active_rule_has_positive_and_negative_cases() -> None:
    missing = [
        rule.id
        for rule in builtin_rules().active()
        if not CASES.get(rule.id, {}).get("positive") or not CASES.get(rule.id, {}).get("negative")
    ]
    assert not missing, f"rules without positive and negative cases: {missing}"


def test_no_cases_for_unknown_rules() -> None:
    known = {rule.id for rule in builtin_rules().rules}
    assert not set(CASES) - known


def test_case_format() -> None:
    for rule_id, spec in CASES.items():
        assert set(spec) <= _CASE_KEYS, rule_id
        for kind, entries in spec.items():
            for entry in entries:
                assert set(entry) <= _ENTRY_KEYS, (rule_id, entry)
                assert entry.get("name"), (rule_id, entry)
                assert entry.get("files") or entry.get("history") or "github" in entry, (
                    rule_id,
                    entry,
                )
                if kind == "negative":
                    assert "expect" not in entry, (rule_id, entry["name"])


@pytest.mark.parametrize(("rule_id", "kind", "case"), list(_params()))
def test_rule_case(rule_id: str, kind: str, case: dict[str, Any], tmp_path: Path) -> None:
    rule = builtin_rules().get(rule_id)
    assert rule is not None
    for requirement in case.get("requires", []):
        if not can_create(tmp_path, requirement):
            pytest.skip(f"this file system cannot create the fixture ({requirement})")
    root = materialize(tmp_path / "repo", case.get("files") or {})
    if case.get("history"):
        # Commits go into repo/.git as a bare object store; nothing is checked out.
        build_repo(root / ".git", expand_history(case["history"]))
    # github: recorded API answers for the trust area (tests/github_fake.py).
    outcome = scan(root, [rule], github=case.get("github"))

    failed = [c for c in outcome.coverage if c.status == CoverageStatus.FAILED]
    assert not failed, f"fixture could not be read or parsed: {failed}"
    if kind == "negative":
        assert not outcome.findings, [f.message for f in outcome.findings]
        return
    assert outcome.findings, "rule did not fire"
    for expected in case.get("expect", []):
        if expected.get("repository"):
            assert any(f.location is None for f in outcome.findings)
            continue
        assert any(
            f.location is not None
            and f.location.path == expected["path"]
            and ("line" not in expected or f.location.line == expected["line"])
            and ("confidence" not in expected or f.confidence.label == expected["confidence"])
            and ("severity" not in expected or f.severity.label == expected["severity"])
            for f in outcome.findings
        ), (
            expected,
            [(f.location, f.severity.label, f.confidence.label) for f in outcome.findings],
        )
