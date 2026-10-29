"""Check type ``unicode``: runs of invisible, bidi or tag characters."""

import re
from collections.abc import Iterator

from repocheck.engine.checks.base import BuildEnv, Check, CheckError, FileView, Match, Params

type Ranges = tuple[tuple[int, int], ...]

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
    ) -> None:
        self.pattern = re.compile(f"[{char_class(ranges)}]{{{min_run},}}")
        self.ignore_between = ignore_between
        self.decode = decode
        self.allow_flag_sequences = allow_flag_sequences

    def _ignored(self, text: str, start: int, end: int) -> bool:
        run = text[start:end]
        if self.allow_flag_sequences and is_flag_sequence(text, start, run):
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


def build(params: Params, env: BuildEnv) -> Check:
    ranges = parse_ranges(params.get_str_list("ranges", required=True))
    min_run = params.get_int("min_run", default=1, minimum=1)
    ignore_between = parse_ranges(params.get_str_list("ignore_between"))
    decode = params.get_choice("decode", ("tags", "none"), default="none")
    allow_flags = params.get_bool("allow_flag_sequences")
    params.done()
    return UnicodeCheck(
        ranges, min_run, ignore_between, None if decode == "none" else decode, allow_flags
    )
