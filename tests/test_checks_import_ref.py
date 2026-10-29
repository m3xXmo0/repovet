import re

import pytest

from helpers import run_check
from repocheck.engine.checks.base import CheckError
from repocheck.engine.checks.import_ref import classify, markdown_lines

SECRET = re.compile(r"(?:\A|[\\/])\.env\Z")


@pytest.mark.parametrize(
    ("target", "path", "expected"),
    [
        ("~/.ssh/id_rsa", "CLAUDE.md", "home directory"),
        ("$HOME/notes.md", "CLAUDE.md", "home directory"),
        ("%USERPROFILE%\\x.md", "CLAUDE.md", "home directory"),
        ("/etc/hosts", "CLAUDE.md", "absolute path outside the repository"),
        ("C:\\Users\\x.md", "CLAUDE.md", "absolute path outside the repository"),
        ("../x.md", "CLAUDE.md", "path outside the repository"),
        ("../x.md", "docs/CLAUDE.md", None),
        ("../../x.md", "docs/CLAUDE.md", "path outside the repository"),
        ("a/../../x.md", "CLAUDE.md", "path outside the repository"),
        ("./a/./b.md", "CLAUDE.md", None),
        (".env", "CLAUDE.md", "secret or credential file"),
        ("docs/style.md", "CLAUDE.md", None),
    ],
)
def test_classify(target: str, path: str, expected: str | None) -> None:
    assert classify(target, path, SECRET) == expected


def test_markdown_lines_skip_code() -> None:
    lines = [
        "a `x` b",
        "```py",
        "inside",
        "```",
        "    indented",
        "~~~~",
        "~~~",
        "still",
        "~~~~",
        "c",
    ]
    assert list(markdown_lines(lines)) == [(1, "a     b"), (10, "c")]


def test_matches_report_target_and_reason() -> None:
    text = "Read @~/notes.md, @README.md and @../up.md.\nmail me@example.invalid\n"
    matches = run_check({"type": "import_ref"}, "CLAUDE.md", text)
    assert [(m.line, m.column, m.values["match"], m.values["value"]) for m in matches] == [
        (1, 6, "@~/notes.md", "home directory"),
        (1, 34, "@../up.md", "path outside the repository"),
    ]


def test_code_can_be_included() -> None:
    spec = {"type": "import_ref", "skip_markdown_code": False}
    assert run_check(spec, "CLAUDE.md", "`@~/x.md`\n") == []  # backtick before @ is excluded
    assert run_check(spec, "CLAUDE.md", "```\n@~/x.md\n```\n")


def test_invalid_spec() -> None:
    with pytest.raises(CheckError):
        run_check({"type": "import_ref", "prefix": "#"}, "CLAUDE.md", "x")
