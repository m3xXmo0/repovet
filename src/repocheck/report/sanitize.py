"""Make repository strings harmless for terminals, people and AI agents reading a report.

Control, format (bidi, zero-width, tag), separator, private-use, unassigned and
variation-selector characters are replaced by a visible ``<U+XXXX>`` marker.
"""

import unicodedata
from urllib.parse import quote

EVIDENCE_LENGTH = 160
PATH_LENGTH = 240
ELLIPSIS = "…"

_MASKED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
_VARIATION_SELECTORS = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))


def is_masked(char: str) -> bool:
    cp = ord(char)
    if 0x20 <= cp < 0x7F:
        return False
    if cp < 0x20 or cp <= 0x9F:
        return True
    if any(lo <= cp <= hi for lo, hi in _VARIATION_SELECTORS):
        return True
    return unicodedata.category(char) in _MASKED_CATEGORIES


def sanitize(text: str, max_length: int | None = EVIDENCE_LENGTH) -> str:
    """Mask invisible and control characters; cut to ``max_length`` characters."""
    out: list[str] = []
    length = 0
    for char in text:
        piece = f"<U+{ord(char):04X}>" if is_masked(char) else char
        if max_length is not None and length + len(piece) > max_length:
            out.append(ELLIPSIS)
            break
        out.append(piece)
        length += len(piece)
    return "".join(out)


def sanitize_path(path: str) -> str:
    return sanitize(path, PATH_LENGTH)


def sanitize_uri(path: str) -> str:
    """A relative repository path as a URI reference: every character outside the
    unreserved ASCII set and '/' is percent-encoded (UTF-8), so nothing invisible or
    controlling survives, and the path still names the real file."""
    return quote(path, safe="/")


def sanitize_data(value: object) -> object:
    """Sanitize every string (keys too) in nested lists and mappings, for facts."""
    if isinstance(value, str):
        return sanitize(value, None)
    if isinstance(value, bool | int | float) or value is None:
        return value
    if isinstance(value, dict):
        return {sanitize(str(k), None): sanitize_data(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        items = sorted(value, key=str) if isinstance(value, set | frozenset) else value
        return [sanitize_data(v) for v in items]
    return sanitize(str(value), None)
