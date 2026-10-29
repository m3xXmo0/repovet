import pytest

from repovet.limits import DEFAULT_LIMITS, KIB, MIB, format_size, parse_size


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("1048576", 1048576),
        ("2MB", 2 * MIB),
        ("2 mb", 2 * MIB),
        ("512k", 512 * KIB),
        ("1.5MiB", int(1.5 * MIB)),
        ("10b", 10),
    ],
)
def test_parse_size(text: str, expected: int) -> None:
    assert parse_size(text) == expected


@pytest.mark.parametrize("text", ["", "abc", "-1", "0", "2 TB", "1e6"])
def test_parse_size_rejects(text: str) -> None:
    with pytest.raises(ValueError, match="size"):
        parse_size(text)


def test_format_size() -> None:
    assert format_size(2 * MIB) == "2 MB"
    assert format_size(1536 * KIB) == "1.5 MB"
    assert format_size(100) == "100 bytes"


def test_defaults_match_plan() -> None:
    assert DEFAULT_LIMITS.max_file_size == 2 * MIB
    assert DEFAULT_LIMITS.max_files == 50_000
    assert DEFAULT_LIMITS.max_line_length == 20_000
    assert DEFAULT_LIMITS.evidence_length == 160
