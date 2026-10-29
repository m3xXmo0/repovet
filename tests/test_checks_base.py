import pytest

from helpers import view_of
from repovet.engine.checks.base import BuildEnv, CheckError, Params, Wildcard, format_value
from repovet.limits import Limits
from repovet.models import CoverageCollector, CoverageStatus


def test_params_reject_unknown_keys() -> None:
    params = Params({"type": "regex", "pattern": "x", "patern": "y"})
    params.require_str("pattern")
    with pytest.raises(CheckError, match="patern"):
        params.done()


def test_params_type_errors() -> None:
    with pytest.raises(CheckError):
        Params({"n": "1"}).get_int("n", default=0)
    with pytest.raises(CheckError):
        Params({"b": "yes"}).get_bool("b")
    with pytest.raises(CheckError):
        Params({"l": [1]}).get_str_list("l")
    with pytest.raises(CheckError):
        Params({"c": "other"}).get_choice("c", ("a", "b"))
    assert Params({"l": "one"}).get_str_list("l") == ["one"]


def test_build_env_expands_and_validates() -> None:
    env = BuildEnv({"word": "foo|bar"})
    assert env.expand("x{{word}}y") == "x(?:foo|bar)y"
    with pytest.raises(CheckError, match="unknown pattern"):
        env.expand("{{nope}}")
    with pytest.raises(CheckError, match="invalid regex"):
        env.compile("(")
    with pytest.raises(CheckError, match="empty string"):
        env.compile("a*")


@pytest.mark.parametrize(
    ("pattern", "text", "expected"),
    [
        ("abc", "abc", True),
        ("abc", "abcd", False),
        ("*", "", True),
        ("*.executablePath", "go.executablePath", True),
        ("*.executablePath", "executablePath", False),
        ("a?c", "abc", True),
        ("a*b*c", "aXXbYYc", True),
        ("a*b*c", "aXXbYY", False),
        ("*a*a*a*a*b", "a" * 5000, False),
    ],
)
def test_wildcard(pattern: str, text: str, expected: bool) -> None:
    assert Wildcard(pattern).matches(text) is expected


def test_format_value() -> None:
    assert format_value("x") == "x"
    assert format_value(True) == "true"
    assert format_value(None) == "null"
    assert format_value(3) == "3"
    assert format_value(["a", 1, False]) == "a 1 false"
    assert format_value({"a": 1}) is None
    assert format_value([["nested"]]) is None


def test_file_view_lines_and_positions() -> None:
    view = view_of("a.txt", "one\r\ntwo\rthree\nfour")
    assert view.lines() == ["one", "two", "three", "four"]
    assert view.position(0) == (1, 1)
    assert view.position(5) == (2, 1)
    assert view.position(11) == (3, 3)
    assert view.line_text(4) == "four"
    assert view.line_text(9) is None


def test_file_view_records_unreadable_content() -> None:
    coverage = CoverageCollector()
    from helpers import MemFile
    from repovet.engine.checks.base import FileView

    big = FileView(MemFile("big.txt", b"x" * 100), Limits(max_file_size=10), coverage)
    binary = FileView(MemFile("a.bin", b"\x00\x01"), Limits(), coverage)
    latin = FileView(MemFile("l.txt", b"caf\xe9"), Limits(), coverage)
    broken = FileView(MemFile("p.json", b"{"), Limits(), coverage)
    assert big.text() is None
    assert binary.text() is None
    assert latin.text() == "café"
    assert broken.structured("json") is None
    assert broken.structured("json") is None  # recorded once
    statuses = {(c.status, c.sample) for c in coverage.items()}
    assert (CoverageStatus.SKIPPED, ("big.txt",)) in statuses
    assert (CoverageStatus.SKIPPED, ("a.bin",)) in statuses
    assert (CoverageStatus.PARTIAL, ("l.txt",)) in statuses
    assert (CoverageStatus.FAILED, ("p.json",)) in statuses
    assert sum(c.count for c in coverage.items()) == 4


def test_python_module_parse_failure_is_coverage() -> None:
    view = view_of("bad.py", "def (:\n")
    assert view.python_module() is None
    view_ok = view_of("ok.py", "x = '\\d'\n")  # invalid escape warning is silenced
    assert view_ok.python_module() is not None
