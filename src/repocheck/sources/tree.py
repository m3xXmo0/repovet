"""Virtual, read-only file tree shared by all sources, plus glob matching and decoding."""

import enum
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol


class RepoFile(Protocol):
    """A regular file of the repository. ``path`` is posix-style and relative to the root."""

    @property
    def path(self) -> str: ...

    @property
    def size(self) -> int: ...

    def read_bytes(self, limit: int) -> bytes:
        """Return at most ``limit`` bytes from the start of the file."""
        ...


class LinkKind(enum.StrEnum):
    SYMLINK = "symlink"
    JUNCTION = "junction"
    REPARSE_POINT = "reparse_point"


@dataclass(frozen=True)
class LinkEntry:
    """A link that was listed but not followed."""

    path: str
    kind: LinkKind
    target: str | None


class FileTree(Protocol):
    @property
    def label(self) -> str: ...

    def files(self) -> Sequence[RepoFile]: ...

    def links(self) -> Sequence[LinkEntry]: ...


def basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


# --- glob matching -----------------------------------------------------------


def validate_glob(pattern: str) -> None:
    if not pattern or pattern.startswith("/") or "\\" in pattern:
        raise ValueError(f"glob {pattern!r} must be a relative posix path pattern")
    segments = pattern.split("/")
    if any(seg in ("", ".", "..") for seg in segments):
        raise ValueError(f"glob {pattern!r} contains an empty, '.' or '..' segment")
    if any("**" in seg and seg != "**" for seg in segments):
        raise ValueError(f"glob {pattern!r}: '**' must be a whole path segment")


def glob_to_regex(pattern: str) -> str:
    """Translate a glob anchored at the repository root.

    ``**`` matches any number of directories, ``*`` and ``?`` stay within one segment.
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:[^/]*/)*")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return "".join(out)


class GlobSet:
    """A set of globs compiled into one regex. Case-insensitive by default, because
    Windows and macOS file systems are."""

    def __init__(self, patterns: Sequence[str], *, case_sensitive: bool = False) -> None:
        for pattern in patterns:
            validate_glob(pattern)
        self.patterns = tuple(patterns)
        self.case_sensitive = case_sensitive
        flags = 0 if case_sensitive else re.IGNORECASE
        body = "|".join(glob_to_regex(p) for p in self.patterns) or "(?!)"
        self._regex = re.compile(f"(?:{body})", flags | re.DOTALL)

    def matches(self, path: str) -> bool:
        return self._regex.fullmatch(path) is not None

    def __bool__(self) -> bool:
        return bool(self.patterns)


# --- decoding ----------------------------------------------------------------


@dataclass(frozen=True)
class DecodedText:
    text: str
    encoding: str
    fallback: bool


_BINARY_PROBE = 8192


def decode_text(data: bytes) -> DecodedText | None:
    """Decode repository bytes. Returns ``None`` for content that looks binary.

    UTF-8 (with or without BOM) and UTF-16 with BOM are decoded strictly; anything else
    falls back to Latin-1 so that every byte stays visible to the checks.
    """
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return DecodedText(data.decode("utf-16"), "utf-16", fallback=False)
        except UnicodeDecodeError:
            return None
    if b"\x00" in data[:_BINARY_PROBE]:
        return None
    try:
        return DecodedText(data.decode("utf-8-sig"), "utf-8", fallback=False)
    except UnicodeDecodeError:
        return DecodedText(data.decode("latin-1"), "latin-1", fallback=True)
