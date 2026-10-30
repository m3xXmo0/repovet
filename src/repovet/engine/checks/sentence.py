"""Check type ``sentence``: a combination of signals in one sentence of prose.

The text is cut into paragraphs and the paragraphs into sentences. A paragraph ends at a
blank line, a heading, a list item, a table row or a fenced code block; fenced code is
skipped (it is shown as code, not given as an instruction), while inline code spans stay
part of their sentence. ``signals`` are named regexes, matched against one sentence at a
time (an anchor at the start of the text matches at the start of the sentence);
``combinations`` is a list of signal-name lists, each with an optional ``severity`` that
lowers the rule's. A sentence is reported once, with the first combination whose signals
all occur in it.

``prefilter`` lists literal strings (case-insensitive); files that contain none of them
are skipped. ``demote_descriptive: true`` reports a sentence with low severity and low
confidence when its signals are quoted to describe them (the same test as the regex
check: in quotes or a code span, with a word like "example" or "attack" nearby, or in a
table row or quote).
"""

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from repovet.engine.checks.base import BuildEnv, Check, CheckError, FileView, Match, Params
from repovet.engine.checks.regex import looks_descriptive, markdown_code_lines
from repovet.models import Confidence, Severity

_NAME = re.compile(r"[a-z][a-z0-9_]*")
# Lines that start a paragraph of their own: headings, list items, table rows, quotes.
_BLOCK_START = re.compile(r"[ \t]*(?:#{1,6}[ \t]|[-*+][ \t]|\d{1,3}[.)][ \t]|\||>)")
# A sentence ends at '.', '!' or '?' followed by white space or the end of the text.
_SENTENCE_END = re.compile(r"[.!?]+(?:[ \t]+|\Z)")
_EVIDENCE = 300
# Paragraphs longer than this are not checked (prose is not that long; data might be).
_MAX_PARAGRAPH = 20_000


@dataclass(frozen=True)
class Combination:
    signals: tuple[str, ...]
    severity: Severity | None


@dataclass(frozen=True)
class _Paragraph:
    text: str
    # (offset in text, 1-based line number) for the start of every joined line.
    starts: tuple[tuple[int, int], ...]

    def line_at(self, offset: int) -> int:
        line = self.starts[0][1]
        for start, number in self.starts:
            if start > offset:
                break
            line = number
        return line


def _paragraphs(view: FileView) -> Iterator[_Paragraph]:
    code = markdown_code_lines(view)
    parts: list[str] = []
    starts: list[tuple[int, int]] = []
    length = 0

    def flush() -> _Paragraph | None:
        nonlocal parts, starts, length
        paragraph = _Paragraph(" ".join(parts), tuple(starts)) if parts else None
        parts, starts, length = [], [], 0
        return paragraph

    for number, line in enumerate(view.lines(), start=1):
        stripped = line.strip()
        if number in code or not stripped or _BLOCK_START.match(line):
            done = flush()
            if done is not None:
                yield done
            if number in code or not stripped:
                continue
        starts.append((length, number))
        parts.append(stripped)
        length += len(stripped) + 1
    done = flush()
    if done is not None:
        yield done


def _sentences(text: str) -> Iterator[tuple[int, int]]:
    start = 0
    for end in _SENTENCE_END.finditer(text):
        yield start, end.end()
        start = end.end()
    if start < len(text):
        yield start, len(text)


class SentenceCheck(Check):
    def __init__(
        self,
        signals: dict[str, re.Pattern[str]],
        combinations: Sequence[Combination],
        prefilter: Sequence[str],
        demote_descriptive: bool,
    ) -> None:
        self.signals = signals
        self.combinations = list(combinations)
        self.prefilter = [literal.lower() for literal in prefilter]
        self.demote_descriptive = demote_descriptive

    def matches(self, view: FileView) -> Iterator[Match]:
        if view.text() is None:
            return
        if self.prefilter and not view.contains_any(self.prefilter):
            return
        for paragraph in _paragraphs(view):
            if len(paragraph.text) > _MAX_PARAGRAPH:
                view.note_long_lines()
                continue
            for start, end in _sentences(paragraph.text):
                match = self._sentence(view, paragraph, start, end)
                if match is not None:
                    yield match

    def _sentence(
        self, view: FileView, paragraph: _Paragraph, start: int, end: int
    ) -> Match | None:
        # Signals see the sentence alone: anchors match at its start.
        text = paragraph.text[start:end]
        found: dict[str, re.Match[str]] = {}
        for name, pattern in self.signals.items():
            hit = pattern.search(text)
            if hit is not None:
                found[name] = hit
        for combination in self.combinations:
            if not all(name in found for name in combination.signals):
                continue
            first = start + min(found[name].start() for name in combination.signals)
            last = start + max(found[name].end() for name in combination.signals)
            sentence = text.strip()
            severity, confidence = combination.severity, None
            if self.demote_descriptive and looks_descriptive(paragraph.text, first, last):
                severity, confidence = Severity.LOW, Confidence.LOW
            evidence = sentence if len(sentence) <= _EVIDENCE else sentence[:_EVIDENCE]
            return Match(
                paragraph.line_at(first),
                None,
                evidence,
                {"match": evidence},
                confidence,
                severity,
            )
        return None

    def regexes(self) -> list[re.Pattern[str]]:
        return list(self.signals.values())


def build(params: Params, env: BuildEnv) -> Check:
    raw_signals = params.get_raw("signals")
    if not isinstance(raw_signals, dict) or not raw_signals:
        raise CheckError("'signals' must be a mapping of names to regexes")
    signals: dict[str, re.Pattern[str]] = {}
    for name, regex in raw_signals.items():
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise CheckError(f"invalid signal name {name!r}")
        if not isinstance(regex, str) or not regex:
            raise CheckError(f"signal {name!r} must be a non-empty regex")
        signals[name] = env.compile(regex, re.IGNORECASE)
    raw_combinations = params.get_raw("combinations")
    if not isinstance(raw_combinations, list) or not raw_combinations:
        raise CheckError("'combinations' must be a non-empty list")
    combinations: list[Combination] = []
    for raw in raw_combinations:
        if not isinstance(raw, dict) or not set(raw) <= {"signals", "severity"}:
            raise CheckError("each combination needs 'signals' and may have 'severity'")
        names = raw.get("signals")
        if not isinstance(names, list) or not names or not all(n in signals for n in names):
            raise CheckError(f"combination {names!r} must name defined signals")
        severity = raw.get("severity")
        if severity is not None and not isinstance(severity, str):
            raise CheckError("combination 'severity' must be a severity name")
        try:
            level = None if severity is None else Severity.parse(severity)
        except ValueError as exc:
            raise CheckError(str(exc)) from None
        combinations.append(Combination(tuple(names), level))
    prefilter = params.get_str_list("prefilter")
    descriptive = params.get_bool("demote_descriptive")
    params.done()
    return SentenceCheck(signals, combinations, prefilter, descriptive)
