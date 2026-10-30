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
``match_requires`` is a further pattern that must occur inside the match itself (an
HTML comment is reported only if its text contains something suspicious).
``skip_markdown_code: true`` ignores matches inside fenced code blocks and inline code
spans: Markdown shows that text literally, so it is not hidden from readers.
``demote_descriptive: true`` reports a match with low severity and low confidence when
the text quotes it to describe it: the match is in quotes or a code span, and the line
introduces it as an example or pattern, calls it an attack, or is a table row, a quote or
a list of code spans. Such matches are not dropped, and a phrase right after a verb like
"run" or "always" stays an instruction.
``join_continuations: true`` joins a line that ends with a backslash with the next one
before matching (shell line continuation); the match is reported at the first line.
"""

import re
from collections.abc import Iterable, Iterator

from repovet.engine.checks.base import BuildEnv, Check, CheckError, FileView, Match, Params
from repovet.models import Confidence, Severity

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


_FENCE = re.compile(r"\A[ \t]*(`{3,}|~{3,})")
_CONTINUATION = re.compile(r"\\\r?\n")


def _continues(line: str) -> bool:
    """True if ``line`` ends with an odd number of backslashes (a line continuation)."""
    return line.endswith("\\") and (len(line) - len(line.rstrip("\\"))) % 2 == 1


def logical_lines(lines: list[str]) -> Iterator[tuple[int, str]]:
    """(first line number, text) with continuation lines joined by a space."""
    first = 1
    parts: list[str] = []
    for number, line in enumerate(lines, start=1):
        if not parts:
            first = number
        if _continues(line):
            parts.append(line[:-1])
            continue
        parts.append(line)
        yield first, " ".join(parts)
        parts = []
    if parts:
        yield first, " ".join(parts)


_CODE_MEMO = "regex:markdown-code"


def markdown_code_lines(view: FileView) -> frozenset[int]:
    """1-based numbers of the lines inside fenced code blocks (fence lines included).
    An unclosed fence runs to the end of the file, as Markdown renders it."""
    cached = view.memo.get(_CODE_MEMO)
    if isinstance(cached, frozenset):
        return cached
    inside: set[int] = set()
    fence: str | None = None
    for number, line in enumerate(view.lines(), start=1):
        found = _FENCE.match(line)
        if fence is None:
            if found is not None and not (found.group(1)[0] == "`" and "`" in line[found.end() :]):
                fence = found.group(1)
                inside.add(number)
            continue
        inside.add(number)
        if (
            found is not None
            and found.group(1)[0] == fence[0]
            and len(found.group(1)) >= len(fence)
            and not line[found.end() :].strip()
        ):
            fence = None
    result = frozenset(inside)
    view.memo[_CODE_MEMO] = result
    return result


def in_code_span(line: str, start: int) -> bool:
    """True if ``line[start]`` lies inside an inline code span (`...`)."""
    return line.count("`", 0, start) % 2 == 1 and "`" in line[start:]


# Words that introduce a quoted phrase as an example, a pattern or an attack.
_DESCRIPTIVE_CUE = re.compile(
    r"(?i:(?<![\w.])(?:e\.g\.|i\.e\.)|\b(?:for example|for instance|examples?|such as|"
    r"says|saying|said|phrases?|patterns?|strings?|text|wording|attempts?|injections?|"
    r"attacks?|attackers?|malicious|untrusted|suspicious|adversarial|jailbreaks?|"
    r"detect(?:s|ed|ion|ing)?|flag(?:s|ged|ging)?|block(?:s|ed|ing)?|"
    r"reject(?:s|ed|ing)?|refuse[sd]?|report(?:s|ed|ing)?|quot(?:e|es|ed|ing)|"
    r"red[ \t]+flags?|anti-?patterns?|signatures?|indicators?|avoid|vermeide[n]?|"
    r"(?:never|do[ \t]+not|don't)[ \t]+(?:follow|obey|execute|run)|not[ \t]+to[ \t]+obey|"
    # The same in German.
    r"(?:zum[ \t]+)?Beispiel\w*|etwa|Muster\w*|Angriff\w*|Angreifer\w*|bösartig\w*|"
    r"verdächtig\w*|erkenn(?:t|en|ung)|blockier(?:t|en)|Zitat\w*|zitier\w*)\b|"
    r"(?<![\w.])z\.[ \t]?B\.)"
)
# A verb right before the opening quote makes the quoted text an instruction.
_IMPERATIVE_BEFORE = re.compile(
    r"(?i:\b(?:run|execute|exec|type|enter|paste|use|call|invoke|say|reply|respond|answer|"
    r"follow|obey|apply|always|must|then|now|first)[ \t]*:?[ \t]*\Z)"
)
_OPENING_QUOTES = ('"', "`", "'", "\u201c", "\u2018")
_CLOSING_QUOTES = {'"': '"', "`": "`", "'": "'", "\u201c": "\u201d", "\u2018": "\u2019"}
_CUE_WINDOW = 200


def _quote_before(line: str, start: int) -> str | None:
    """The quote character that opens the quoted text containing ``line[start]``."""
    before = line[:start]
    stripped = before.rstrip()
    if stripped.endswith(_OPENING_QUOTES) and len(before) - len(stripped) <= 1:
        return stripped[-1]
    for quote in ('"', "`"):
        if before.count(quote) % 2 == 1:
            return quote
    if before.count("\u201c") > before.count("\u201d"):
        return "\u201c"
    return None


def looks_descriptive(line: str, start: int, end: int) -> bool:
    """True if ``line[start:end]`` is quoted to describe it, not given as an instruction."""
    quote = _quote_before(line, start)
    if quote is None or _CLOSING_QUOTES[quote] not in line[end:]:
        return False
    opening = line.rfind(quote, 0, start)
    imperative = _IMPERATIVE_BEFORE.search(line, max(0, opening - 40), max(0, opening))
    if imperative:
        prefix = line[: imperative.start()].lower()
        return prefix.endswith(("never ", "do not ", "don't ", "niemals ", "nicht "))
    stripped = line.lstrip()
    if stripped.startswith(("|", ">")) or line.count("`") >= 6:
        return True
    context = line[max(0, start - _CUE_WINDOW) : start] + " " + line[end : end + _CUE_WINDOW]
    return _DESCRIPTIVE_CUE.search(context) is not None


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
        match_requires: re.Pattern[str] | None = None,
        skip_markdown_code: bool = False,
        demote_descriptive: bool = False,
        join_continuations: bool = False,
    ) -> None:
        self.pattern = pattern
        self.scope = scope
        self.ignore = ignore
        self.file_requires = file_requires or []
        self.long_lines = long_lines
        self.prefilter = [literal.lower() for literal in prefilter or []]
        self.demote_regex_literals = demote_regex_literals
        self.match_requires = match_requires
        self.skip_markdown_code = skip_markdown_code
        self.demote_descriptive = demote_descriptive
        self.join_continuations = join_continuations

    def _make(self, view: FileView, number: int, column: int, line: str, text: str) -> Match | None:
        """The match of ``text`` at ``line[column - 1:]``, or ``None`` if it is skipped."""
        start, end = column - 1, min(len(line), column - 1 + len(text))
        if self.match_requires is not None and self.match_requires.search(text) is None:
            return None
        if self.skip_markdown_code and (
            number in markdown_code_lines(view) or in_code_span(line, start)
        ):
            return None
        confidence: Confidence | None = None
        severity: Severity | None = None
        if self.demote_regex_literals and looks_like_regex_literal(line, start, end):
            confidence = Confidence.LOW
        if self.demote_descriptive and (
            number in markdown_code_lines(view) or looks_descriptive(line, start, end)
        ):
            confidence, severity = Confidence.LOW, Severity.LOW
        return Match(number, column, line, {"match": text}, confidence, severity)

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
        if self.join_continuations and _CONTINUATION.search(text):
            yield from self._joined_matches(view)
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
            match = self._make(view, number, found.start() + 1, line, found.group(0))
            if match is not None:
                yield match

    def _joined_matches(self, view: FileView) -> Iterator[Match]:
        limit = view.limits.max_line_length
        for number, line in logical_lines(view.lines()):
            if len(line) > limit and not self.long_lines:
                view.note_long_lines()
                continue
            found = self.pattern.search(line)
            if found is None or (self.ignore is not None and self.ignore.search(line)):
                continue
            match = self._make(view, number, found.start() + 1, line, found.group(0))
            if match is not None:
                yield match

    def _text_matches(self, view: FileView, text: str) -> Iterator[Match]:
        if not self.long_lines and view.has_long_lines():
            view.note_long_lines()
            return
        for found in self.pattern.finditer(text):
            if self.ignore is not None and self.ignore.search(found.group(0)):
                continue
            line, column = view.position(found.start())
            match = self._make(view, line, column, view.line_text(line) or "", found.group(0))
            if match is not None:
                yield match

    def regexes(self) -> list[re.Pattern[str]]:
        optional = (self.pattern, self.ignore, self.match_requires)
        patterns = [r for r in optional if r is not None] + self.file_requires
        if self.demote_descriptive:
            patterns += [_DESCRIPTIVE_CUE, _IMPERATIVE_BEFORE, _FENCE]
        return patterns


def build(params: Params, env: BuildEnv) -> Check:
    pattern = params.require_str("pattern")
    scope = params.get_choice("scope", ("line", "text"), default="line")
    ignore = params.get_str("ignore")
    requires = params.get_str_list("file_requires")
    long_lines = params.get_bool("long_lines")
    prefilter = params.get_str_list("prefilter")
    demote = params.get_bool("demote_regex_literals")
    match_requires = params.get_str("match_requires")
    skip_code = params.get_bool("skip_markdown_code")
    descriptive = params.get_bool("demote_descriptive")
    joined = params.get_bool("join_continuations")
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
        env.compile(match_requires, flags) if match_requires else None,
        skip_code,
        descriptive,
        joined,
    )
