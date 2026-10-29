import pytest

from helpers import run_check
from repocheck.engine.checks.base import CheckError


def test_existence_without_regex() -> None:
    (match,) = run_check({"type": "filename"}, "dir/setup.py", "x")
    assert match.values["match"] == "setup.py"
    assert match.line is None


def test_name_regex_is_case_insensitive_by_default() -> None:
    spec = {"type": "filename", "name_regex": r"\.lnk$"}
    assert run_check(spec, "a/README.LNK", b"\x00")
    assert not run_check(spec, "a/README.LNK", b"\x00", case_sensitive=True)


def test_not_name_regex_excludes() -> None:
    spec = {"type": "filename", "name_regex": ".", "not_name_regex": r"\.sample$"}
    assert run_check(spec, ".git/hooks/pre-commit", "x")
    assert not run_check(spec, ".git/hooks/pre-commit.sample", "x")


def test_filename_does_not_need_text() -> None:
    assert run_check({"type": "filename"}, "a.bin", b"\x00\x01\x02")


def test_unknown_parameter() -> None:
    with pytest.raises(CheckError):
        run_check({"type": "filename", "name": "x"}, "a", "x")
