import pytest

from helpers import run_check
from repovet.engine.checks.base import CheckError
from repovet.engine.checks.workflow import ExpansionLimit, guard_facts, resolve

REPO = "github.event.workflow_run.head_repository.full_name == github.repository"
BRANCH = "github.event.workflow_run.head_branch == github.event.repository.default_branch"
EVENT = "github.event.workflow_run.event == 'push'"


def test_only_guards_required_by_every_boolean_branch_are_proven() -> None:
    combined = f"{REPO} && {BRANCH} && {EVENT}"
    expected = {"same_repository", "default_branch", "trusted_event"}
    assert guard_facts(combined) == expected
    assert guard_facts("${{ (" + combined + ") }}") == expected
    assert not guard_facts(f"({combined}) || github.actor == 'outside'")
    assert guard_facts(f"({combined}) && contains(github.actor, 'a||b')") == expected


@pytest.mark.parametrize("condition", ["", "!true", "x != y", "'push'", "a" * 50_000])
def test_unknown_conditions_prove_no_guard(condition: str) -> None:
    assert not guard_facts(condition)


def test_malformed_spec_is_rejected() -> None:
    with pytest.raises(CheckError):
        run_check({"type": "workflow", "mode": "typo", "pattern": "x"}, "a.yml", "")


def test_environment_expansion_is_bounded_before_allocating_the_result() -> None:
    with pytest.raises(ExpansionLimit):
        resolve("$PAYLOAD", {"PAYLOAD": "x" * 20_001}, variables=True)
    with pytest.raises(ExpansionLimit):
        resolve("${{ env.A }}", {"A": "${{ env.A }}" * 10})
