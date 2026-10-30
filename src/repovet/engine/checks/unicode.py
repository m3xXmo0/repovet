"""Check type ``unicode``: runs of invisible, bidi or tag characters (``mode: runs``),
or words that mix Latin letters with look-alikes from other scripts
(``mode: mixed_script``, optionally ``code_only``)."""

import re
import unicodedata
from collections.abc import Iterator

from repovet.engine.checks.base import BuildEnv, Check, CheckError, FileView, Match, Params
from repovet.parsers.codelex import Spans, literal_spans
from repovet.parsers.codelex import patterns as codelex_patterns

type Ranges = tuple[tuple[int, int], ...]
_SPANS_MEMO = "unicode:literal-spans"

NAMED_RANGES: dict[str, Ranges] = {
    "tags": ((0xE0000, 0xE007F),),
    "bidi": ((0x061C, 0x061C), (0x200E, 0x200F), (0x202A, 0x202E), (0x2066, 0x2069)),
    "zero_width": ((0x180E, 0x180E), (0x200B, 0x200D), (0x2060, 0x2064), (0xFEFF, 0xFEFF)),
    "variation_selectors": ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF)),
    "emoji": (
        (0x00A9, 0x00A9),
        (0x00AE, 0x00AE),
        (0x2190, 0x21FF),
        (0x2300, 0x23FF),
        (0x2600, 0x27BF),
        (0x2B00, 0x2BFF),
        (0xFE0F, 0xFE0F),
        (0x1F000, 0x1FAFF),
    ),
}

_RANGE = re.compile(r"([0-9A-Fa-f]{1,6})(?:-([0-9A-Fa-f]{1,6}))?")
_WAVING_BLACK_FLAG = 0x1F3F4
_CANCEL_TAG = 0xE007F
# ISO 3166-2 subdivision code: two letters plus up to four letters or digits ("gbeng").
_FLAG_TAGS = re.compile(
    "[\U000e0061-\U000e007a]{2}[\U000e0030-\U000e0039\U000e0061-\U000e007a]{1,4}"
)


def parse_ranges(items: list[str]) -> Ranges:
    ranges: list[tuple[int, int]] = []
    for item in items:
        if item in NAMED_RANGES:
            ranges.extend(NAMED_RANGES[item])
            continue
        match = _RANGE.fullmatch(item)
        if match is None:
            names = ", ".join(NAMED_RANGES)
            raise CheckError(f"invalid range {item!r} (hex like E0000-E007F or {names})")
        lo = int(match.group(1), 16)
        hi = int(match.group(2) or match.group(1), 16)
        if lo > hi or hi > 0x10FFFF:
            raise CheckError(f"invalid range {item!r}")
        ranges.append((lo, hi))
    return tuple(ranges)


def char_class(ranges: Ranges) -> str:
    return "".join(f"\\U{lo:08X}-\\U{hi:08X}" for lo, hi in ranges)


def _in_ranges(char: str, ranges: Ranges) -> bool:
    cp = ord(char)
    return any(lo <= cp <= hi for lo, hi in ranges)


def decode_tags(run: str) -> str:
    """Tag characters U+E0020..U+E007E mirror printable ASCII."""
    return "".join(chr(ord(c) - 0xE0000) for c in run if 0xE0020 <= ord(c) <= 0xE007E)


def is_flag_sequence(text: str, start: int, run: str) -> bool:
    """Emoji subdivision flags (England, Scotland, Wales) are 🏴 + tag letters + cancel tag."""
    return (
        start > 0
        and ord(text[start - 1]) == _WAVING_BLACK_FLAG
        and ord(run[-1]) == _CANCEL_TAG
        and _FLAG_TAGS.fullmatch(run[:-1]) is not None
    )


class UnicodeCheck(Check):
    def __init__(
        self,
        ranges: Ranges,
        min_run: int,
        ignore_between: Ranges,
        decode: str | None,
        allow_flag_sequences: bool,
        allow_repeated_char: bool = False,
    ) -> None:
        self.pattern = re.compile(f"[{char_class(ranges)}]{{{min_run},}}")
        self.ignore_between = ignore_between
        self.decode = decode
        self.allow_flag_sequences = allow_flag_sequences
        self.allow_repeated_char = allow_repeated_char

    def _ignored(self, text: str, start: int, end: int) -> bool:
        run = text[start:end]
        if self.allow_flag_sequences and is_flag_sequence(text, start, run):
            return True
        # One character repeated (a doubled emoji selector from copy and paste) can
        # carry no data beyond its length.
        if self.allow_repeated_char and len(set(run)) == 1:
            return True
        if not self.ignore_between or start == 0 or end >= len(text):
            return False
        return _in_ranges(text[start - 1], self.ignore_between) and _in_ranges(
            text[end], self.ignore_between
        )

    def matches(self, view: FileView) -> Iterator[Match]:
        text = view.text()
        if text is None:
            return
        for found in self.pattern.finditer(text):
            if self._ignored(text, found.start(), found.end()):
                continue
            run = found.group(0)
            line, column = view.position(found.start())
            values = {"match": run, "count": str(len(run))}
            if self.decode == "tags":
                values["decoded"] = decode_tags(run)
            yield Match(line, column, view.line_text(line), values)

    def regexes(self) -> list[re.Pattern[str]]:
        return [self.pattern]


# Cyrillic, Greek and Armenian letters that look like Latin letters in common fonts.
LOOKALIKES = frozenset(
    map(
        chr,
        (
            0x0430,
            0x0435,
            0x043E,
            0x0440,
            0x0441,
            0x0443,
            0x0445,
            0x0455,
            0x0456,
            0x0458,
            0x04BB,
            0x04CF,
            0x0501,
            0x051B,
            0x051D,
            0x0405,
            0x0406,
            0x0408,
            0x0410,
            0x0412,
            0x0415,
            0x041A,
            0x041C,
            0x041D,
            0x041E,
            0x0420,
            0x0421,
            0x0422,
            0x0425,
            0x04AE,
            0x04BA,
            0x0391,
            0x0392,
            0x0395,
            0x0396,
            0x0397,
            0x0399,
            0x039A,
            0x039C,
            0x039D,
            0x039F,
            0x03A1,
            0x03A4,
            0x03A5,
            0x03A7,
            0x03BF,
            0x03F2,
            0x03F3,
            0x0570,
            0x057D,
            0x0585,
        ),
    )
)
_NON_ASCII = re.compile(r"[^\x00-\x7f]+")
_MAX_WORD = 200


def _word_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    """Extend ``text[start:end]`` to the surrounding word characters (bounded scan)."""
    lo = start
    while lo > 0 and start - lo < _MAX_WORD and (text[lo - 1].isalnum() or text[lo - 1] == "_"):
        lo -= 1
    hi = end
    while hi < len(text) and hi - end < _MAX_WORD and (text[hi].isalnum() or text[hi] == "_"):
        hi += 1
    return lo, hi


def _describe(char: str) -> str:
    return f"U+{ord(char):04X} {unicodedata.name(char, 'UNKNOWN')}"


_RUN_STOP = frozenset(" \t\r\n\"'`")
_HOST_DOT = re.compile(r"\w\.[A-Za-z]")
# The text before a string literal that makes it a module name.
_MODULE_BEFORE = re.compile(r"(?:\b(?:require|import)[ \t]*\([ \t]*|\b(?:from|import)[ \t]+)\Z")


def _in_address(text: str, lo: int, hi: int) -> bool:
    """True if the word ``text[lo:hi]`` is part of a URL, host name or e-mail address:
    the surrounding run of non-space, non-quote characters has '://', '@' or a dot
    between a word character and a Latin letter ("example.com", not "end.\\nNext")."""
    start = lo
    while start > 0 and lo - start < _MAX_WORD and text[start - 1] not in _RUN_STOP:
        start -= 1
    end = hi
    while end < len(text) and end - hi < _MAX_WORD and text[end] not in _RUN_STOP:
        end += 1
    run = text[start:end]
    return "://" in run or "@" in run or _HOST_DOT.search(run) is not None


class MixedScriptCheck(Check):
    """Words that mix ASCII letters with look-alike letters of another script, such as
    "paypal" spelled with a Cyrillic letter a (U+0430). Each non-ASCII run is extended to
    its word by a bounded scan, so the work stays linear in the text length.

    With ``code_only``, words in comments are skipped, and words in string literals count
    only as part of a URL, host name or e-mail address or as a module name (``import``,
    ``require``): translated text and names in data are written in their own script."""

    def __init__(self, code_only: bool = False) -> None:
        self.code_only = code_only

    def _in_text(self, view: FileView, text: str, lo: int, hi: int) -> bool:
        """True if the word is in a comment or in ordinary string text."""
        spans = view.memo.get(_SPANS_MEMO)
        if not isinstance(spans, Spans):
            spans = literal_spans(text, view.path) or Spans([], [], [])
            view.memo[_SPANS_MEMO] = spans
        found = spans.kind_at(lo)
        if found is None:
            return False
        kind, start = found
        if kind == "c":
            return True
        if _MODULE_BEFORE.search(text, max(0, start - 30), start):
            return False
        return not _in_address(text, lo, hi)

    def matches(self, view: FileView) -> Iterator[Match]:
        text = view.text()
        if text is None or text.isascii():
            return
        last_end = -1
        for found in _NON_ASCII.finditer(text):
            if found.start() < last_end:
                continue
            lo, hi = _word_bounds(text, found.start(), found.end())
            last_end = hi
            word = text[lo:hi]
            lookalikes = sorted({c for c in word if c in LOOKALIKES})
            if not lookalikes or not any(c.isascii() and c.isalpha() for c in word):
                continue
            if self.code_only and self._in_text(view, text, lo, hi):
                continue
            line, column = view.position(lo)
            values = {
                "match": word,
                "count": str(len(lookalikes)),
                "chars": ", ".join(_describe(c) for c in lookalikes),
            }
            yield Match(line, column, view.line_text(line), values)

    def regexes(self) -> list[re.Pattern[str]]:
        return [_NON_ASCII, _MODULE_BEFORE, _HOST_DOT, *codelex_patterns()]


def build(params: Params, env: BuildEnv) -> Check:
    mode = params.get_choice("mode", ("runs", "mixed_script"), default="runs")
    if mode == "mixed_script":
        code_only = params.get_bool("code_only")
        params.done()
        return MixedScriptCheck(code_only)
    ranges = parse_ranges(params.get_str_list("ranges", required=True))
    min_run = params.get_int("min_run", default=1, minimum=1)
    ignore_between = parse_ranges(params.get_str_list("ignore_between"))
    decode = params.get_choice("decode", ("tags", "none"), default="none")
    allow_flags = params.get_bool("allow_flag_sequences")
    allow_repeated = params.get_bool("allow_repeated_char")
    params.done()
    return UnicodeCheck(
        ranges,
        min_run,
        ignore_between,
        None if decode == "none" else decode,
        allow_flags,
        allow_repeated,
    )
