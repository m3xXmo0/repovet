"""Apply shared regex checks to YAML commands, Markdown code, or scripts."""

import re
from collections.abc import Iterator
from dataclasses import dataclass, replace

from repovet.engine.checks import regex
from repovet.engine.checks.base import BuildEnv, Check, CheckError, FileView, Match, Params
from repovet.engine.checks.keypath import Path, parse_path, walk
from repovet.models import Confidence, CoverageCollector, CoverageStatus, Severity
from repovet.parsers.structured import find_line


@dataclass(frozen=True)
class _Fragment:
    path: str
    data: bytes

    @property
    def size(self) -> int:
        return len(self.data)

    def read_bytes(self, limit: int) -> bytes:
        return self.data[:limit]


class _AnyRegex(Check):
    def __init__(self, checks: list[Check]) -> None:
        self.checks = checks

    def matches(self, view: FileView) -> Iterator[Match]:
        for check in self.checks:
            yield from check.matches(view)

    def regexes(self) -> list[re.Pattern[str]]:
        return [pattern for check in self.checks for pattern in check.regexes()]


def _inline_spans(line: str) -> Iterator[tuple[int, int, str]]:
    """Content start, delimiter width and text; double ticks can contain shell ticks."""
    index = 0
    while index < len(line):
        opening = line.find("`", index)
        if opening < 0:
            return
        start = opening
        while start < len(line) and line[start] == "`":
            start += 1
        width = start - opening
        marker = "`" * width
        closing = line.find(marker, start)
        while closing >= 0 and (
            line[closing - 1 : closing] == "`" or line[closing + width : closing + width + 1] == "`"
        ):
            closing = line.find(marker, closing + width)
        if closing >= 0:
            yield start, width, line[start:closing]
            index = closing + width
        else:
            index = start


class EmbeddedRegexCheck(Check):
    def __init__(
        self, paths: list[Path], inner: Check, source: str = "yaml", plain: Check | None = None
    ) -> None:
        self.paths = paths
        self.inner = inner
        self.source = source
        self.plain = plain

    def _fragment(self, view: FileView, value: str, coverage: CoverageCollector) -> FileView | None:
        try:
            encoded = value.encode("utf-8")
        except UnicodeError:
            view.note(
                CoverageStatus.PARTIAL, "Command values with invalid Unicode were not checked"
            )
            return None
        return FileView(_Fragment(view.path, encoded), view.limits, coverage)

    def matches(self, view: FileView) -> Iterator[Match]:
        if self.source == "markdown":
            yield from self._markdown_matches(view)
            if self.plain:
                yield from self.plain.matches(view)
            return
        if not view.path.lower().endswith((".yml", ".yaml")):
            yield from self.inner.matches(view)
            return
        data = view.structured("yaml")
        if data is None:
            return
        raw = view.text() or ""
        for path in self.paths:
            for trail, value in walk(data, path):
                if not isinstance(value, str):
                    continue
                # Parse through FileView once; each scalar then gets exactly the same
                # continuation, comment and pattern handling as a standalone script.
                first = value.splitlines()[0] if value.splitlines() else ""
                line = find_line(raw, trail, first)
                coverage = CoverageCollector()
                block = self._fragment(view, value, coverage)
                if block is None:
                    continue
                for match in self.inner.matches(block):
                    actual = (line + match.line - 1) if line and match.line else line
                    yield replace(
                        match, line=actual, evidence=view.line_text(actual) if actual else None
                    )
                for note in coverage.items():
                    view.note(note.status, note.reason)

    def _markdown_matches(self, view: FileView) -> Iterator[Match]:
        code = regex.markdown_code_lines(view)
        parts: list[str] = []
        first = 1

        def fenced() -> Iterator[Match]:
            coverage = CoverageCollector()
            block = self._fragment(view, "\n".join(parts), coverage)
            if block is not None:
                for match in self.inner.matches(block):
                    line = first + (match.line or 1) - 1
                    yield replace(
                        match,
                        line=line,
                        evidence=view.line_text(line),
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                    )
                for note in coverage.items():
                    view.note(note.status, note.reason)

        for number, line in enumerate(view.lines(), 1):
            if number in code and not line.lstrip().startswith(("```", "~~~")):
                if not parts:
                    first = number
                parts.append(line)
                continue
            if parts:
                yield from fenced()
                parts = []
            if number in code:
                continue
            if len(line) > view.limits.max_line_length:
                view.note_long_lines()
                continue
            for start, width, content in _inline_spans(line):
                coverage = CoverageCollector()
                block = self._fragment(view, content, coverage)
                if block is None:
                    continue
                # Delimiter ticks and shell substitution ticks have different roles.
                # Normalize only the context used for quotation classification.
                context = (
                    line[: start - width]
                    + "`"
                    + content.replace("`", " ")
                    + "`"
                    + line[start + len(content) + width :]
                )
                for match in self.inner.matches(block):
                    offset = start - width + (match.column or 1)
                    descriptive = regex.looks_descriptive(
                        context,
                        offset,
                        min(len(context), offset + len(match.values.get("match", ""))),
                    )
                    yield replace(
                        match,
                        line=number,
                        column=start + (match.column or 1),
                        evidence=line,
                        severity=Severity.LOW if descriptive else match.severity,
                        confidence=Confidence.LOW if descriptive else match.confidence,
                    )
                for note in coverage.items():
                    view.note(note.status, note.reason)
        if parts:
            yield from fenced()

    def regexes(self) -> list[re.Pattern[str]]:
        return self.inner.regexes() + (self.plain.regexes() if self.plain else [])


def build(params: Params, env: BuildEnv) -> Check:
    source = params.get_choice("source", ("yaml", "markdown"), default="yaml")
    paths = [parse_path(p) for p in params.get_str_list("paths", required=source == "yaml")]
    raw = params.get_raw("regex")
    specs = raw if isinstance(raw, list) else [raw]
    if not specs or not all(isinstance(spec, dict) for spec in specs):
        raise CheckError("'regex' must be a mapping or non-empty list of regex check parameters")
    checks = [regex.build(Params(spec), env) for spec in specs if isinstance(spec, dict)]
    inner = checks[0] if len(checks) == 1 else _AnyRegex(checks)
    raw_plain = params.get_raw("plain_regex")
    plain = None
    if raw_plain is not None:
        if source != "markdown" or not isinstance(raw_plain, dict):
            raise CheckError("'plain_regex' requires Markdown and a mapping of regex parameters")
        plain = regex.build(Params(raw_plain), env)
    params.done()
    return EmbeddedRegexCheck(paths, inner, source, plain)
