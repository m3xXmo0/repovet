import json
import time

import pytest

from repocheck.parsers.jsonc import loads_jsonc, strip_jsonc


def test_comments_and_trailing_commas() -> None:
    text = """// head
{
  "a": 1, // one
  /* block
     comment */
  "b": [1, 2, ],
}
"""
    assert loads_jsonc(text) == {"a": 1, "b": [1, 2]}


def test_comment_markers_inside_strings_are_kept() -> None:
    text = r'{"url": "https://example.invalid/a", "glob": "/*.js", "q": "say \"//hi\",]"}'
    assert loads_jsonc(text) == json.loads(text)


def test_line_and_column_structure_is_preserved() -> None:
    text = '{\n  /* x */ "a": 1,\n  "b": 2, // c\n}'
    stripped = strip_jsonc(text)
    assert stripped.count("\n") == text.count("\n")
    assert [len(line) for line in stripped.split("\n")] == [len(line) for line in text.split("\n")]


def test_unterminated_comment_and_string_fail_cleanly() -> None:
    with pytest.raises(ValueError):
        loads_jsonc('{"a": 1 /* never closed')
    with pytest.raises(ValueError):
        loads_jsonc('{"a": "never closed')


@pytest.mark.parametrize(
    "text",
    ["/*" * 100_000, '"' + "\\" * 200_001, "," + " " * 200_000, "/" * 200_000, "*/" * 100_000],
)
def test_tokenizer_is_linear(text: str) -> None:
    start = time.perf_counter()
    strip_jsonc(text)
    assert time.perf_counter() - start < 2.0
