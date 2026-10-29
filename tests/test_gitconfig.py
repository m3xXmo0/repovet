import pytest

from repovet.limits import DEFAULT_LIMITS
from repovet.parsers.gitconfig import loads_gitconfig
from repovet.parsers.structured import ParseError, find_line, parse


def test_sections_subsections_and_case() -> None:
    text = """\
# comment
[Core]
\tHooksPath = .githooks
\tbare
[remote "Origin"]
\turl = https://example.invalid/x.git
[branch.Main]
\tremote = origin
"""
    assert loads_gitconfig(text) == {
        "core": {"hookspath": ".githooks", "bare": True},
        "remote": {"Origin": {"url": "https://example.invalid/x.git"}},
        "branch": {"main": {"remote": "origin"}},
    }


def test_values_quotes_escapes_comments_and_continuation() -> None:
    text = (
        "[alias]\n"
        '\tq = "!echo \\"a;b\\"" # comment\n'
        "\tlong = !echo one \\\n"
        "two\n"
        "\tsemi = value ; comment\n"
    )
    assert loads_gitconfig(text) == {
        "alias": {"q": '!echo "a;b"', "long": "!echo one two", "semi": "value"}
    }


def test_repeated_keys_become_lists() -> None:
    text = '[remote "o"]\n\tfetch = a\n\tfetch = b\n\tfetch = c\n'
    assert loads_gitconfig(text) == {"remote": {"o": {"fetch": ["a", "b", "c"]}}}


def test_key_after_header_on_same_line() -> None:
    assert loads_gitconfig("[core] pager = less\n") == {"core": {"pager": "less"}}


@pytest.mark.parametrize("text", ["key = 1\n", "[core\n", "[core]\n\t= x\n", "[core]\n\tbad key\n"])
def test_invalid_config(text: str) -> None:
    with pytest.raises(ParseError):
        parse(text, "gitconfig", DEFAULT_LIMITS)


def test_find_line_is_case_insensitive_for_git_config() -> None:
    text = (
        '[core]\n\trepositoryformatversion = 0\n\tfsMonitor = ./x\n[filter "demo"]\n\tclean = y\n'
    )
    assert find_line(text, ("core", "fsmonitor"), "./x", ignore_case=True) == 3
    assert find_line(text, ("filter", "demo", "clean"), "y", ignore_case=True) == 5
    assert find_line(text, ("core", "fsmonitor"), "./x") is not None  # falls back to the key path
