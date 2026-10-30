"""Check type ``keypath``: values at key paths in JSON, JSONC, TOML, YAML or Git config.

A path is a dot-separated list of segments; ``\\.`` is a literal dot (VS Code setting
names contain dots). Segments may use ``*`` and ``?``; ``*`` also matches list indexes.

Conditions (at most one): ``exists`` (default), ``equals`` (type-exact), ``value_regex``,
``not_in``. A ``paths`` entry may be a mapping ``{path: ..., <condition>}`` with its own
condition. ``where`` lists conditions on paths relative to the matched node; all must
hold. Objects and arrays are matched by ``value_regex`` as the text of all their values.
``file_requires`` lists patterns that must all occur in the raw text; other files are not
parsed at all (a file named ``config`` is a Git config only if it has a ``[core]``
section, a workflow matters only with certain triggers).
"""

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field

from repovet.engine.checks.base import (
    BuildEnv,
    Check,
    CheckError,
    FileView,
    Match,
    Params,
    Wildcard,
    format_value,
)
from repovet.parsers.structured import CASE_INSENSITIVE_KEYS, FORMATS, find_line

_SEGMENT_SPLIT = re.compile(r"(?<!\\)\.")
_CONDITIONS = ("exists", "equals", "value_regex", "not_in")
_FLATTEN_BUDGET = 5_000

type Trail = tuple[str | int, ...]
type Path = tuple[Wildcard, ...]


def parse_path(path: str) -> Path:
    segments = [seg.replace("\\.", ".") for seg in _SEGMENT_SPLIT.split(path)]
    if any(not seg for seg in segments):
        raise CheckError(f"key path {path!r} has an empty segment")
    return tuple(Wildcard(seg) for seg in segments)


def walk(node: object, segments: Path, trail: Trail = ()) -> Iterator[tuple[Trail, object]]:
    if len(trail) == len(segments):
        yield trail, node
        return
    segment = segments[len(trail)]
    if isinstance(node, dict):
        for key, value in node.items():
            if (
                isinstance(key, str | int)
                and not isinstance(key, bool)
                and segment.matches(str(key))
            ):
                yield from walk(value, segments, (*trail, key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            if segment.matches(str(index)):
                yield from walk(value, segments, (*trail, index))


def flatten(value: object, budget: int = _FLATTEN_BUDGET) -> str:
    """All scalar values of a nested structure, space-separated, in document order."""
    parts: list[str] = []
    stack: list[object] = [value]
    while stack and budget > 0:
        budget -= 1
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(reversed(list(node.values())))
        elif isinstance(node, list):
            stack.extend(reversed(node))
        else:
            text = format_value(node)
            if text:
                parts.append(text)
    return " ".join(parts)


def value_text(value: object) -> str:
    text = format_value(value)
    return text if text is not None else flatten(value)


@dataclass(frozen=True)
class Condition:
    mode: str = "exists"
    equals: object = None
    regex: re.Pattern[str] | None = None
    not_in: frozenset[str] = field(default_factory=frozenset)

    def accepts(self, value: object, text: str) -> str | None:
        """The matched text if ``value`` satisfies the condition, else ``None``."""
        scalar = isinstance(value, str | int | float | bool) or value is None
        if self.mode == "exists":
            return text
        if self.mode == "equals":
            return text if type(value) is type(self.equals) and value == self.equals else None
        if self.mode == "value_regex":
            found = self.regex.search(text) if self.regex is not None else None
            return found.group(0) if found else None
        return text if scalar and value is not None and text not in self.not_in else None


def parse_condition(params: Params, env: BuildEnv, default: Condition | None = None) -> Condition:
    present = [name for name in _CONDITIONS if params.has(name)]
    if len(present) > 1:
        raise CheckError(f"use only one of {', '.join(present)}")
    if not present:
        return default or Condition()
    mode = present[0]
    if mode == "exists":
        if not params.get_bool("exists", default=True):
            raise CheckError("'exists: false' is not supported")
        return Condition()
    if mode == "equals":
        equals = params.get_raw("equals")
        if not isinstance(equals, str | int | float | bool):
            raise CheckError("'equals' must be a scalar value")
        return Condition("equals", equals=equals)
    if mode == "value_regex":
        return Condition("value_regex", regex=env.compile(params.require_str("value_regex")))
    return Condition("not_in", not_in=frozenset(params.get_str_list("not_in", required=True)))


def _sub_params(raw: object, what: str) -> Params:
    if not isinstance(raw, Mapping) or not all(isinstance(k, str) for k in raw):
        raise CheckError(f"'{what}' entries must be key paths or mappings")
    return Params(raw)


class KeypathCheck(Check):
    def __init__(
        self,
        fmt: str,
        paths: list[tuple[Path, Condition]],
        where: list[tuple[Path, Condition]] | None = None,
        file_requires: list[re.Pattern[str]] | None = None,
    ) -> None:
        self.fmt = fmt
        self.paths = paths
        self.where = where or []
        self.file_requires = file_requires or []
        self.ignore_case = fmt in CASE_INSENSITIVE_KEYS

    def _where_holds(self, node: object) -> bool:
        return all(
            any(cond.accepts(v, value_text(v)) is not None for _, v in walk(node, segments))
            for segments, cond in self.where
        )

    def matches(self, view: FileView) -> Iterator[Match]:
        if self.file_requires:
            raw = view.text()
            if raw is None or not all(r.search(raw) for r in self.file_requires):
                return
        data = view.structured(self.fmt)
        if data is None:
            return
        text = view.text() or ""
        for segments, condition in self.paths:
            for trail, value in walk(data, segments):
                shown = value_text(value)
                matched = condition.accepts(value, shown)
                if matched is None or not self._where_holds(value):
                    continue
                line = find_line(text, trail, matched or shown, ignore_case=self.ignore_case)
                key = next((str(k) for k in reversed(trail) if isinstance(k, str)), "")
                yield Match(
                    line=line,
                    evidence=view.line_text(line) if line else None,
                    values={"key": key, "value": shown, "match": matched or key},
                )

    def regexes(self) -> list[re.Pattern[str]]:
        conditions = [c for _, c in self.paths] + [c for _, c in self.where]
        return [c.regex for c in conditions if c.regex is not None] + self.file_requires


def build(params: Params, env: BuildEnv) -> Check:
    fmt = params.get_choice("format", FORMATS)
    default = parse_condition(params, env)
    raw_paths = params.get_raw("paths")
    if not isinstance(raw_paths, list) or not raw_paths:
        raise CheckError("'paths' must be a non-empty list")
    paths: list[tuple[Path, Condition]] = []
    for entry in raw_paths:
        if isinstance(entry, str) and entry:
            paths.append((parse_path(entry), default))
            continue
        sub = _sub_params(entry, "paths")
        path = parse_path(sub.require_str("path"))
        condition = parse_condition(sub, env, default)
        sub.done()
        paths.append((path, condition))
    where: list[tuple[Path, Condition]] = []
    raw_where = params.get_raw("where")
    if raw_where is not None:
        if not isinstance(raw_where, list) or not raw_where:
            raise CheckError("'where' must be a non-empty list")
        for entry in raw_where:
            sub = _sub_params(entry, "where")
            path = parse_path(sub.require_str("path"))
            condition = parse_condition(sub, env)
            sub.done()
            where.append((path, condition))
    requires = [env.compile(r) for r in params.get_str_list("file_requires")]
    params.done()
    return KeypathCheck(fmt, paths, where, requires)
