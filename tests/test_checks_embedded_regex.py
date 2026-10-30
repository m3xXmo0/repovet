import pytest

from helpers import run_check, view_of
from repovet.engine.checks import BUILDERS
from repovet.engine.checks.base import BuildEnv, CheckError, Params
from repovet.models import CoverageStatus

SPEC = {
    "type": "embedded_regex",
    "paths": ["jobs.*.steps.*.run"],
    "regex": {"pattern": "danger", "ignore": "^#"},
}


def test_only_run_scalars_and_original_lines_are_used() -> None:
    text = (
        "jobs:\n  a:\n    steps:\n      - name: danger\n"
        "        run: |\n          # danger\n          danger\n"
    )
    (hit,) = run_check(SPEC, ".github/workflows/a.yml", text)
    assert hit.line == 7
    assert hit.evidence == "          danger"


def test_scripts_use_the_same_check_without_yaml_parsing() -> None:
    (hit,) = run_check(SPEC, "a.sh", "# danger\ndanger\n")
    assert hit.line == 2


def test_bad_yaml_is_reported_as_coverage() -> None:
    view = view_of(".github/workflows/a.yml", "jobs: [unclosed")
    check = BUILDERS["embedded_regex"](Params(SPEC), BuildEnv({}))
    assert not list(check.matches(view))
    assert view._coverage.items()[0].status == CoverageStatus.FAILED


def test_invalid_unicode_scalar_is_reported_instead_of_aborting() -> None:
    view = view_of(
        ".github/workflows/a.yml", 'jobs:\n  a:\n    steps:\n      - run: "echo \\ud800"\n'
    )
    check = BUILDERS["embedded_regex"](Params(SPEC), BuildEnv({}))
    assert not list(check.matches(view))
    (note,) = view._coverage.items()
    assert note.status == CoverageStatus.PARTIAL
    assert "invalid Unicode" in note.reason


def test_invalid_nested_regex_parameters_are_rejected() -> None:
    with pytest.raises(CheckError, match="mapping"):
        run_check({**SPEC, "regex": []}, "a.yml", "")
    with pytest.raises(CheckError, match="unknown"):
        run_check({**SPEC, "regex": {"pattern": "x", "typo": True}}, "a.yml", "")


def test_markdown_scalar_checks_keep_their_own_required_context() -> None:
    spec = {
        "type": "embedded_regex",
        "source": "markdown",
        "regex": [{"pattern": "execute", "file_requires": ["download"]}],
    }
    assert not run_check(spec, "AGENTS.md", "Download docs first, then `execute local`.\n")
    assert run_check(spec, "AGENTS.md", "Run `download; execute`.\n")
