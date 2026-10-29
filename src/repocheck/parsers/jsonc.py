"""JSON with comments and trailing commas, as used by VS Code and dev containers."""

import json
import re

# Both tokenizers are linear: strings and block comments may be unterminated and then
# simply run to the end of the text.
_STRING = r'"[^"\\]*(?:\\.[^"\\]*)*"?'
_COMMENTS = re.compile(
    rf"(?P<str>{_STRING})|(?P<line>//[^\n]*)|(?P<block>/\*[^*]*(?:\*+[^*/][^*]*)*(?:\*+/)?)",
    re.DOTALL,
)
_TRAILING_COMMA = re.compile(rf"(?P<str>{_STRING})|(?P<comma>,)(?=\s*[\]}}])", re.DOTALL)
_NOT_NEWLINE = re.compile(r"[^\n]")


def _blank_comment(match: re.Match[str]) -> str:
    if match.group("str") is not None:
        return match.group(0)
    # Keep newlines and columns so line lookups on the original text stay valid.
    return _NOT_NEWLINE.sub(" ", match.group(0))


def _drop_comma(match: re.Match[str]) -> str:
    return match.group(0) if match.group("str") is not None else " "


def strip_jsonc(text: str) -> str:
    """Replace comments and trailing commas by spaces, outside of strings."""
    without_comments = _COMMENTS.sub(_blank_comment, text)
    return _TRAILING_COMMA.sub(_drop_comma, without_comments)


def loads_jsonc(text: str) -> object:
    result: object = json.loads(strip_jsonc(text))
    return result
