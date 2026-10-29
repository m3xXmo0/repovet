import pytest

from repocheck.report.sanitize import ELLIPSIS, is_masked, sanitize, sanitize_path


@pytest.mark.parametrize(
    ("char", "masked"),
    [
        ("\x1b", True),  # ESC
        ("\x00", True),
        ("\n", True),
        ("\x9b", True),  # C1 CSI
        ("\u202e", True),  # bidi override
        ("\u2066", True),  # bidi isolate
        ("\u200b", True),  # zero width space
        ("\u200d", True),  # zero width joiner
        ("\ufeff", True),
        ("\U000e0041", True),  # tag
        ("\ufe0f", True),  # variation selector
        ("\U000e0100", True),  # variation selector supplement
        ("\u2028", True),  # line separator
        ("\ue000", True),  # private use
        ("a", False),
        ("ä", False),
        ("中", False),
        ("\U0001f600", False),
        (" ", False),
    ],
)
def test_masking(char: str, masked: bool) -> None:
    assert is_masked(char) is masked


def test_sanitize_marks_hidden_characters_visibly() -> None:
    assert sanitize("a\x1b[31mb") == "a<U+001B>[31mb"
    assert sanitize("evil\u202etxt.exe") == "evil<U+202E>txt.exe"
    assert sanitize("x\U000e0049") == "x<U+E0049>"


def test_sanitize_truncates() -> None:
    result = sanitize("a" * 500)
    assert result == "a" * 160 + ELLIPSIS
    assert sanitize("a" * 500, None) == "a" * 500
    # A marker is never cut in half.
    cut = sanitize("a" * 157 + "\x1b", 160)
    assert cut == "a" * 157 + ELLIPSIS


def test_sanitize_is_idempotent() -> None:
    once = sanitize("a\u202eb\x07")
    assert sanitize(once) == once


def test_sanitize_path_allows_longer_values() -> None:
    path = "d/" * 150 + "f.txt"
    assert sanitize_path("d/" * 100) == "d/" * 100
    assert sanitize_path(path).endswith(ELLIPSIS)
    assert len(sanitize_path(path)) == 241
