"""Check type ``regex``: a pattern per line (default) or over the whole text.

``file_requires`` lists further patterns that must all occur somewhere in the same file
(each searched once, which keeps "A in a line, B anywhere in the file" linear).
``long_lines: true`` also checks lines longer than the line limit; only for patterns
that stay linear on very long input (packer signatures in minified code).
``prefilter`` lists literal strings (case-insensitive); files that contain none of them
are skipped without running the regex. Every match must contain one of the literals.
``demote_regex_literals: true`` reports a match with low confidence when it is clearly a
regular expression inside a string or regex literal (security tools ship the very
patterns they look for). Such matches are not dropped: regex syntax next to a real
command must not hide it.
"""

import re
from collections.abc import Iterable, Iterator

from repovet.engine.checks.base import BuildEnv, Check, CheckError, FileView, Match, Params
from repovet.models import Confidence

_FLAGS = {"ignorecase": re.IGNORECASE, "multiline": re.MULTILINE, "dotall": re.DOTALL}
# Regular-expression syntax that a command line does not contain: a class escape with a
# quantifier (\s+, \d*), a negated class with a quantifier ([^|]*) or a group extension
# ((?:, (?=, (?!, (?<=, (?P<name>).
_REGEX_SYNTAX = re.compile(
    r"\\[sSdDwW][+*?{]|\[\^[^\]\n]{1,40}\][+*?{]|\(\?(?:[:=!]|<[=!]|P?<[A-Za-z_])"
)
_ESCAPED = re.compile(r"\\.")
_QUOTES = ('"', "'", "`")


def looks_like_regex_literal(line: str, start: int, end: int) -> bool:
    """True if ``line[start:end]`` contains regex syntax and starts inside a string
    (an unclosed quote before it) or right after a ``/`` (a JavaScript regex literal)."""
    if _REGEX_SYNTAX.search(line, start, end) is None:
        return False
    before = line[:start]
    if before.endswith("/"):
        return True
    unescaped = _ESCAPED.sub("", before)
    return any(unescaped.count(quote) % 2 == 1 for quote in _QUOTES)


class RegexCheck(Check):
    def __init__(
        self,
        pattern: re.Pattern[str],
        scope: str,
        ignore: re.Pattern[str] | None,
        file_requires: list[re.Pattern[str]] | None = None,
        long_lines: bool = False,
        prefilter: list[str] | None = None,
        demote_regex_literals: bool = False,
    ) -> None:
        self.pattern = pattern
        self.scope = scope
        self.ignore = ignore
        self.file_requires = file_requires or []
        self.long_lines = long_lines
        self.prefilter = [literal.lower() for literal in prefilter or []]
        self.demote_regex_literals = demote_regex_literals

    def _confidence(self, line: str, start: int, end: int) -> Confidence | None:
        if self.demote_regex_literals and looks_like_regex_literal(line, start, end):
            return Confidence.LOW
        return None

    def matches(self, view: FileView) -> Iterator[Match]:
        text = view.text()
        if text is None:
            return
        if self.prefilter and not view.contains_any(self.prefilter):
            return
        if self.file_requires and not all(r.search(text) for r in self.file_requires):
            return
        if self.scope == "text":
            yield from self._text_matches(view, text)
            return
        limit = view.limits.max_line_length
        lines = view.lines()
        numbers: Iterable[int] = range(1, len(lines) + 1)
        candidates = view.lines_containing(self.prefilter) if self.prefilter else None
        if candidates is not None:
            numbers = candidates
        for number in numbers:
            line = lines[number - 1]
            if len(line) > limit and not self.long_lines:
                view.note_long_lines()
                continue
            found = self.pattern.search(line)
            if found is None or (self.ignore is not None and self.ignore.search(line)):
                continue
            yield Match(
                number,
                found.start() + 1,
                line,
                {"match": found.group(0)},
                self._confidence(line, found.start(), found.end()),
            )

    def _text_matches(self, view: FileView, text: str) -> Iterator[Match]:
        if not self.long_lines and view.has_long_lines():
            view.note_long_lines()
            return
        for found in self.pattern.finditer(text):
            if self.ignore is not None and self.ignore.search(found.group(0)):
                continue
            line, column = view.position(found.start())
            text_line = view.line_text(line) or ""
            end = min(len(text_line), column - 1 + len(found.group(0)))
            yield Match(
                line,
                column,
                view.line_text(line),
                {"match": found.group(0)},
                self._confidence(text_line, column - 1, end),
            )

    def regexes(self) -> list[re.Pattern[str]]:
        return [r for r in (self.pattern, self.ignore) if r is not None] + self.file_requires


def build(params: Params, env: BuildEnv) -> Check:
    pattern = params.require_str("pattern")
    scope = params.get_choice("scope", ("line", "text"), default="line")
    ignore = params.get_str("ignore")
    requires = params.get_str_list("file_requires")
    long_lines = params.get_bool("long_lines")
    prefilter = params.get_str_list("prefilter")
    demote = params.get_bool("demote_regex_literals")
    flags = 0
    for name in params.get_str_list("flags"):
        if name not in _FLAGS:
            raise CheckError(f"unknown regex flag {name!r} ({', '.join(_FLAGS)})")
        flags |= _FLAGS[name]
    params.done()
    return RegexCheck(
        env.compile(pattern, flags),
        scope,
        env.compile(ignore, flags) if ignore else None,
        [env.compile(r, flags) for r in requires],
        long_lines,
        prefilter,
        demote,
    )
