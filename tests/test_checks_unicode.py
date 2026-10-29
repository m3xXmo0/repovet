import pytest

from helpers import run_check
from repocheck.engine.checks.base import CheckError
from repocheck.engine.checks.unicode import decode_tags, parse_ranges

TAGS = {"type": "unicode", "ranges": ["tags"], "decode": "tags"}


def test_tag_run_is_decoded() -> None:
    text = "ok\nhi\U000e0049\U000e0067\U000e006e\U000e006f\U000e0072\U000e0065 there\n"
    (match,) = run_check(TAGS, "CLAUDE.md", text)
    assert (match.line, match.column) == (2, 3)
    assert match.values["decoded"] == "Ignore"
    assert match.values["count"] == "6"


def test_flag_sequences_can_be_allowed() -> None:
    england = "\U0001f3f4\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e007f"
    spec = {**TAGS, "allow_flag_sequences": True}
    assert not run_check(spec, "a.md", f"Hi {england}\n")
    assert run_check(TAGS, "a.md", f"Hi {england}\n")
    # Without the black flag in front, the same tags are reported.
    assert run_check(spec, "a.md", "Hi " + england[1:] + "\n")


def test_min_run() -> None:
    spec = {"type": "unicode", "ranges": ["zero_width"], "min_run": 2}
    assert not run_check(spec, "a.md", "a\u200bb")
    assert run_check(spec, "a.md", "a\u200b\u200bb")


def test_ignore_between() -> None:
    spec = {"type": "unicode", "ranges": ["200D"], "ignore_between": ["emoji"]}
    family = "\U0001f468\u200d\U0001f469"
    assert not run_check(spec, "a.md", f"x {family} y")
    assert run_check(spec, "a.md", "ab\u200dcd")


def test_bidi_range() -> None:
    (match,) = run_check({"type": "unicode", "ranges": ["bidi"]}, "a.md", "x = 1 \u202e// y\n")
    assert match.column == 7


def test_parse_ranges() -> None:
    assert parse_ranges(["E0000-E007F", "200B"]) == ((0xE0000, 0xE007F), (0x200B, 0x200B))
    for bad in ("zz", "20-10", "110000"):
        with pytest.raises(CheckError):
            parse_ranges([bad])


def test_decode_tags_skips_non_ascii_tags() -> None:
    assert decode_tags("\U000e0001\U000e0041\U000e007f") == "A"


def test_invalid_specs() -> None:
    with pytest.raises(CheckError):
        run_check({"type": "unicode"}, "a", "x")
    with pytest.raises(CheckError):
        run_check({"type": "unicode", "ranges": ["tags"], "decode": "rot13"}, "a", "x")
