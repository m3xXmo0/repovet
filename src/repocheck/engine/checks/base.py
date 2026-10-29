"""Shared infrastructure for check types: parameters, lazy file view, matches."""

import abc
import ast
import bisect
import re
import warnings
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field

from repocheck.limits import Limits, format_size
from repocheck.models import CoverageCollector, CoverageStatus
from repocheck.parsers.structured import FORMAT_LABELS, ParseError, parse
from repocheck.sources.tree import FileTree, RepoFile, basename, decode_text

_PLACEHOLDER_REF = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}")
_LINE_BREAK = re.compile(r"\r\n|\r|\n")


class CheckError(ValueError):
    """Invalid check parameters in a rule file."""


@dataclass(frozen=True)
class Match:
    line: int | None = None
    column: int | None = None
    evidence: str | None = None
    values: Mapping[str, str] = field(default_factory=dict)


# --- parameters ----------------------------------------------------------------


class Params:
    """Typed access to a rule's ``check`` mapping; ``done`` rejects unknown keys."""

    def __init__(self, data: Mapping[str, object]) -> None:
        self._data = dict(data)
        self._used: set[str] = {"type"}

    def _get(self, name: str) -> object:
        self._used.add(name)
        return self._data.get(name)

    def has(self, name: str) -> bool:
        return name in self._data

    def get_str(self, name: str, *, required: bool = False) -> str | None:
        value = self._get(name)
        if value is None:
            if required:
                raise CheckError(f"'{name}' is required")
            return None
        if not isinstance(value, str) or not value:
            raise CheckError(f"'{name}' must be a non-empty string")
        return value

    def require_str(self, name: str) -> str:
        value = self.get_str(name, required=True)
        if value is None:  # pragma: no cover - get_str raised already
            raise CheckError(f"'{name}' is required")
        return value

    def get_choice(self, name: str, choices: Sequence[str], default: str | None = None) -> str:
        value = self.get_str(name, required=default is None) or default
        if value is None or value not in choices:
            raise CheckError(f"'{name}' must be one of {', '.join(choices)}")
        return value

    def get_bool(self, name: str, default: bool = False) -> bool:
        value = self._get(name)
        if value is None:
            return default
        if not isinstance(value, bool):
            raise CheckError(f"'{name}' must be true or false")
        return value

    def get_int(self, name: str, default: int, minimum: int = 0) -> int:
        value = self._get(name)
        if value is None:
            return default
        if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
            raise CheckError(f"'{name}' must be an integer >= {minimum}")
        return value

    def get_float(
        self, name: str, default: float, minimum: float = 0.0, maximum: float | None = None
    ) -> float:
        value = self._get(name)
        if value is None:
            return default
        if (
            not isinstance(value, int | float)
            or isinstance(value, bool)
            or value < minimum
            or (maximum is not None and value > maximum)
        ):
            upper = f" and <= {maximum}" if maximum is not None else ""
            raise CheckError(f"'{name}' must be a number >= {minimum}{upper}")
        return float(value)

    def get_str_list(self, name: str, *, required: bool = False) -> list[str]:
        value = self._get(name)
        if value is None:
            if required:
                raise CheckError(f"'{name}' is required")
            return []
        if isinstance(value, str):
            value = [value]
        if (
            not isinstance(value, list)
            or not value
            or not all(isinstance(v, str) and v for v in value)
        ):
            raise CheckError(f"'{name}' must be a non-empty list of strings")
        return list(value)

    def get_raw(self, name: str) -> object:
        return self._get(name)

    def done(self) -> None:
        unknown = sorted(set(self._data) - self._used)
        if unknown:
            raise CheckError(f"unknown check parameter(s): {', '.join(unknown)}")


@dataclass(frozen=True)
class BuildEnv:
    """What a check builder needs from the loader."""

    patterns: Mapping[str, str]
    case_sensitive: bool = False

    def expand(self, regex: str) -> str:
        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in self.patterns:
                raise CheckError(f"unknown pattern '{{{{{name}}}}}'")
            return f"(?:{self.patterns[name]})"

        return _PLACEHOLDER_REF.sub(replace, regex)

    def compile(self, regex: str, flags: int = 0, *, allow_empty: bool = False) -> re.Pattern[str]:
        try:
            compiled = re.compile(self.expand(regex), flags)
        except re.error as exc:
            raise CheckError(f"invalid regex {regex!r}: {exc}") from None
        if not allow_empty and compiled.search("") is not None:
            raise CheckError(f"regex {regex!r} matches the empty string")
        return compiled


# --- file view -------------------------------------------------------------------


class FileView:
    """Lazy, cached access to one file's content for all rules that apply to it.

    Whatever cannot be read, decoded or parsed is recorded as coverage, once per file.
    """

    def __init__(self, file: RepoFile, limits: Limits, coverage: CoverageCollector) -> None:
        self.file = file
        self.path = file.path
        self.name = basename(file.path)
        self.limits = limits
        self._coverage = coverage
        self._text_loaded = False
        self._text: str | None = None
        self._lower: str | None = None
        self._raw: bytes | None = None
        self._full: bytes | None = None
        self._full_loaded = False
        # Per-file results that several rules of one check type share (e.g. blob runs).
        self.memo: dict[str, object] = {}
        self._line_starts: list[int] | None = None
        self._lines: list[str] | None = None
        self._structured: dict[str, object] = {}
        self._structured_failed: set[str] = set()
        self._module_loaded = False
        self._module: ast.Module | None = None

    def note(self, status: CoverageStatus, reason: str) -> None:
        self._coverage.add("file", status, reason, self.path)

    def text(self) -> str | None:
        if not self._text_loaded:
            self._text_loaded = True
            self._text = self._load_text()
        return self._text

    def head(self, size: int) -> bytes | None:
        """The first ``size`` bytes, raw (for signatures); ``None`` if unreadable."""
        size = min(size, self.file.size)
        if self._raw is None or len(self._raw) < size:
            try:
                self._raw = self.file.read_bytes(size)
            except OSError:
                self.note(CoverageStatus.FAILED, "Files that could not be read")
                self._raw = b""
                return None
        return self._raw[:size]

    def _read_full(self) -> bytes | None:
        """Up to ``max_file_size + 1`` bytes, read once; ``None`` if unreadable."""
        if not self._full_loaded:
            self._full_loaded = True
            try:
                self._full = self.file.read_bytes(self.limits.max_file_size + 1)
                self._raw = self._full
            except OSError:
                self._full = None
        return self._full

    def content(self) -> bytes | None:
        """The whole file as bytes (shared with ``text``); ``None`` if it is larger than
        ``max_file_size`` or unreadable. Records no coverage: for profiling, not rules."""
        limit = self.limits.max_file_size
        if self.file.size > limit:
            return None
        data = self._read_full()
        return data if data is not None and len(data) <= limit else None

    def contains_any(self, literals: Sequence[str]) -> bool:
        """True if the text contains one of the lowercase ``literals`` (case-insensitive).

        A cheap prefilter: substring search runs at C speed, while case-insensitive
        regex alternations cost a fraction of a microsecond per character.
        """
        lower = self._lowered()
        return any(literal in lower for literal in literals)

    def _lowered(self) -> str:
        if self._lower is None:
            self._lower = (self.text() or "").lower()
        return self._lower

    def lines_containing(self, literals: Sequence[str]) -> list[int] | None:
        """Sorted 1-based numbers of the lines that contain one of the lowercase
        ``literals``; ``None`` if offsets cannot be mapped (lowercasing changed the
        length, as for 'İ'), so the caller checks every line."""
        text, lower = self.text() or "", self._lowered()
        if len(lower) != len(text):
            return None
        starts = self.line_starts()
        found: set[int] = set()
        for literal in literals:
            index = lower.find(literal)
            while index != -1:
                line = bisect.bisect_right(starts, index)
                found.add(line)
                # Continue after this line: one hit per line is enough.
                next_start = starts[line] if line < len(starts) else len(lower)
                index = lower.find(literal, max(next_start, index + 1))
        return sorted(found)

    def _load_text(self) -> str | None:
        limit = self.limits.max_file_size
        if self.file.size > limit:
            self.note(
                CoverageStatus.SKIPPED,
                f"Files larger than {format_size(limit)}, content not checked",
            )
            return None
        data = self._read_full()
        if data is None:
            self.note(CoverageStatus.FAILED, "Files that could not be read")
            return None
        if len(data) > limit:
            self.note(CoverageStatus.SKIPPED, "Files that grew during the scan")
            return None
        decoded = decode_text(data)
        if decoded is None:
            self.note(
                CoverageStatus.SKIPPED,
                "Binary files, content not checked (only file signatures are checked)",
            )
            return None
        if decoded.fallback:
            self.note(CoverageStatus.PARTIAL, "Not UTF-8 or UTF-16, decoded as Latin-1")
        return decoded.text

    def line_starts(self) -> list[int]:
        if self._line_starts is None:
            text = self.text() or ""
            self._line_starts = [0, *(m.end() for m in _LINE_BREAK.finditer(text))]
        return self._line_starts

    def lines(self) -> list[str]:
        if self._lines is None:
            self._lines = _LINE_BREAK.split(self.text() or "")
        return self._lines

    def position(self, offset: int) -> tuple[int, int]:
        """1-based line and column of a character offset."""
        starts = self.line_starts()
        index = bisect.bisect_right(starts, offset) - 1
        return index + 1, offset - starts[index] + 1

    def line_text(self, line: int) -> str | None:
        lines = self.lines()
        return lines[line - 1] if 0 < line <= len(lines) else None

    def has_long_lines(self) -> bool:
        limit = self.limits.max_line_length
        return any(len(line) > limit for line in self.lines())

    def note_long_lines(self) -> None:
        self.note(
            CoverageStatus.PARTIAL,
            f"Lines longer than {self.limits.max_line_length:,} characters "
            "not checked by pattern rules",
        )

    def structured(self, fmt: str) -> object | None:
        if fmt in self._structured:
            return self._structured[fmt]
        if fmt in self._structured_failed:
            return None
        text = self.text()
        if text is None:
            return None
        try:
            data = parse(text, fmt, self.limits)
        except ParseError:
            self._structured_failed.add(fmt)
            self.note(
                CoverageStatus.FAILED, f"Files that could not be parsed as {FORMAT_LABELS[fmt]}"
            )
            return None
        self._structured[fmt] = data
        return data

    def python_module(self) -> ast.Module | None:
        if not self._module_loaded:
            self._module_loaded = True
            text = self.text()
            if text is not None:
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        self._module = ast.parse(text, filename=self.name)
                except (SyntaxError, ValueError, RecursionError, MemoryError):
                    self.note(CoverageStatus.FAILED, "Files that could not be parsed as Python")
        return self._module


# --- check base ------------------------------------------------------------------


class Check(abc.ABC):
    needs_text: bool = True

    @abc.abstractmethod
    def matches(self, view: FileView) -> Iterator[Match]:
        """Yield every match of this check in ``view``."""

    def regexes(self) -> list[re.Pattern[str]]:
        """All regexes of this check (for the ReDoS test)."""
        return []


class TreeCheck(Check):
    """A check of the whole file tree; runs once per scan instead of once per file.
    The rule's ``files``/``exclude`` globs apply to the reported paths."""

    needs_text = False

    def matches(self, view: FileView) -> Iterator[Match]:
        return iter(())

    @abc.abstractmethod
    def tree_matches(self, tree: FileTree) -> Iterator[tuple[str, Match]]:
        """Yield (path, match) for every finding in ``tree``."""


class FactCheck(Check):
    """A check of the facts that analyzers computed (provenance, later trust); runs once
    per scan and reports repository-wide findings (no file location)."""

    needs_text = False

    def matches(self, view: FileView) -> Iterator[Match]:
        return iter(())

    @abc.abstractmethod
    def fact_matches(self, facts: Mapping[str, object]) -> Iterator[Match]:
        """Yield one match if the facts meet the rule's conditions."""


class Wildcard:
    """``*`` and ``?`` wildcards for key and call names, matched without regex
    backtracking (O(len(pattern) * len(text)) even for hostile names)."""

    def __init__(self, pattern: str) -> None:
        self.pattern = pattern
        self._literal = "*" not in pattern and "?" not in pattern

    def matches(self, text: str) -> bool:
        if self._literal:
            return text == self.pattern
        p, s = self.pattern, text
        pi = si = 0
        star, mark = -1, 0
        while si < len(s):
            if pi < len(p) and p[pi] in ("?", s[si]) and p[pi] != "*":
                pi += 1
                si += 1
            elif pi < len(p) and p[pi] == "*":
                star, mark = pi, si
                pi += 1
            elif star != -1:
                pi = star + 1
                mark += 1
                si = mark
            else:
                return False
        while pi < len(p) and p[pi] == "*":
            pi += 1
        return pi == len(p)


def format_value(value: object) -> str | None:
    """Scalar (or list of scalars) as text; ``None`` for nested structures."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, str | int | float):
        return str(value)
    if isinstance(value, list) and all(
        isinstance(v, str | int | float | bool) or v is None for v in value
    ):
        return " ".join(format_value(v) or "" for v in value)
    return None
