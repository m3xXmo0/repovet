import pytest

from helpers import run_check
from repovet.engine.checks.base import CheckError

SETUP = """\
import subprocess as sp
from os import system
import urllib.request
from setuptools import setup

sp.run(["echo", "hi"])
system("echo hi")
urllib.request.urlopen("https://example.invalid/x")
exec("print(1)")
setup(name="demo", cmdclass={"install": object})
"""


def calls(spec_calls: list[str]) -> list[tuple[int | None, str]]:
    matches = run_check({"type": "python_ast", "calls": spec_calls}, "setup.py", SETUP)
    return [(m.line, m.values["match"]) for m in matches]


def test_calls_resolve_import_aliases() -> None:
    assert calls(["subprocess.*", "os.system"]) == [(6, "subprocess.run"), (7, "os.system")]


def test_calls_with_full_dotted_name_and_builtins() -> None:
    assert calls(["urllib.request.urlopen", "exec"]) == [(8, "urllib.request.urlopen"), (9, "exec")]


def test_keywords_in_call() -> None:
    spec = {"type": "python_ast", "keywords": ["cmdclass"], "in_call": ["setuptools.setup"]}
    (match,) = run_check(spec, "setup.py", SETUP)
    assert match.line == 10
    assert match.values["value"] == "setuptools.setup"
    other = {**spec, "in_call": ["distutils.core.setup"]}
    assert not run_check(other, "setup.py", SETUP)


def test_syntax_errors_give_no_match() -> None:
    assert not run_check({"type": "python_ast", "calls": ["exec"]}, "a.py", "exec(\n")


def test_nothing_is_executed() -> None:
    marker: list[str] = []
    code = "marker.append('ran')\nexec('marker.append(1)')\n"
    assert run_check({"type": "python_ast", "calls": ["exec"]}, "a.py", code)
    assert marker == []


@pytest.mark.parametrize(
    "spec",
    [
        {"type": "python_ast"},
        {"type": "python_ast", "calls": ["x"], "keywords": ["y"]},
        {"type": "python_ast", "calls": ["x"], "in_call": ["y"]},
    ],
)
def test_invalid_specs(spec: dict[str, object]) -> None:
    with pytest.raises(CheckError):
        run_check(spec, "a.py", "x")
