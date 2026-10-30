"""Comment and string-literal spans in source code, approximately, by file extension.

Not a parser: one regex per language family finds comments and string literals so that
checks can tell identifiers from text. Every alternative ends at a closing delimiter,
a line end or the end of the text, so the scan is linear and never fails on broken code.
Unknown file types return ``None``.
"""

import bisect
import re
from dataclasses import dataclass

# A string that may not span lines; unclosed, it ends at the line end.
_DQ = r"\"(?:[^\"\\\n]|\\[^\n]?)*+(?:\"|(?![^\n]))"
_SQ = r"'(?:[^'\\\n]|\\[^\n]?)*+(?:'|(?![^\n]))"
_BQ = r"`(?:[^`\\]|\\[\s\S]?)*+(?:`|\Z)"
_LINE_SLASH = r"//[^\n]*"
_BLOCK = r"/\*(?:[^*]|\*(?!/))*+(?:\*/|\Z)"
# '#' starts a comment at the line start or after a space (not $# or ${#x} in shells).
_LINE_HASH = r"(?:(?<=[ \t])|^)#[^\n]*"
_PY_TRIPLE = (
    r"\"\"\"(?:[^\"\\]|\\[\s\S]?|\"(?!\"\"))*+(?:\"\"\"|\Z)"
    r"|'''(?:[^'\\]|\\[\s\S]?|'(?!''))*+(?:'''|\Z)"
)

_FAMILIES: dict[str, tuple[str, str]] = {
    # family: (comment alternatives, string alternatives)
    "c": (f"{_LINE_SLASH}|{_BLOCK}", f"{_DQ}|{_SQ}|{_BQ}"),
    "php": (f"{_LINE_SLASH}|{_BLOCK}|{_LINE_HASH}", f"{_DQ}|{_SQ}"),
    "python": (_LINE_HASH, f"{_PY_TRIPLE}|{_DQ}|{_SQ}"),
    "shell": (_LINE_HASH, f"{_DQ}|{_SQ}"),
    "powershell": (rf"<#(?:[^#]|#(?!>))*+(?:#>|\Z)|{_LINE_HASH}", f"{_DQ}|{_SQ}"),
    "lua": (r"--\[\[(?:[^\]]|\](?!\]))*+(?:\]\]|\Z)|--[^\n]*", f"{_DQ}|{_SQ}"),
    "batch": (r"^[ \t]*(?:::|(?i:rem)\b)[^\n]*", _DQ),
    "vb": (r"'[^\n]*|^[ \t]*(?i:rem)\b[^\n]*", _DQ),
}

_C_LIKE = (
    "js mjs cjs jsx ts tsx mts cts vue svelte java kt kts groovy gradle cs c h cc cpp hpp "
    "swift go rs scala dart jse"
)
_EXTENSIONS: dict[str, str] = {
    **dict.fromkeys(_C_LIKE.split(" "), "c"),
    "php": "php",
    "py": "python",
    "pyw": "python",
    **dict.fromkeys(["sh", "bash", "zsh", "ksh", "fish", "rb", "pl", "pm", "dockerfile"], "shell"),
    "ps1": "powershell",
    "psm1": "powershell",
    "lua": "lua",
    "bat": "batch",
    "cmd": "batch",
    "vbs": "vb",
    "vbe": "vb",
}
_NAMES = {"dockerfile": "shell", "containerfile": "shell"}

_COMPILED: dict[str, re.Pattern[str]] = {
    family: re.compile(f"(?P<c>{comments})|(?P<s>{strings})", re.MULTILINE)
    for family, (comments, strings) in _FAMILIES.items()
}


def family_of(path: str) -> str | None:
    name = path.rsplit("/", 1)[-1].lower()
    if name in _NAMES:
        return _NAMES[name]
    _, dot, ext = name.rpartition(".")
    return _EXTENSIONS.get(ext) if dot else None


@dataclass(frozen=True)
class Spans:
    """Sorted, non-overlapping comment (``c``) and string (``s``) spans of a text."""

    starts: list[int]
    ends: list[int]
    kinds: list[str]

    def kind_at(self, offset: int) -> tuple[str, int] | None:
        """``(kind, span start)`` of the span containing ``offset``, else ``None``."""
        index = bisect.bisect_right(self.starts, offset) - 1
        if index >= 0 and offset < self.ends[index]:
            return self.kinds[index], self.starts[index]
        return None


def literal_spans(text: str, path: str) -> Spans | None:
    """Comment and string spans of ``text``; ``None`` for unknown file types."""
    family = family_of(path)
    if family is None:
        return None
    starts: list[int] = []
    ends: list[int] = []
    kinds: list[str] = []
    for found in _COMPILED[family].finditer(text):
        if found.end() > found.start():
            starts.append(found.start())
            ends.append(found.end())
            kinds.append("c" if found.lastgroup == "c" else "s")
    return Spans(starts, ends, kinds)


def patterns() -> list[re.Pattern[str]]:
    """All regexes of this module (for the ReDoS test)."""
    return list(_COMPILED.values())
