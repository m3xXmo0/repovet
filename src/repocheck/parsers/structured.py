"""JSON, JSONC, TOML, YAML and Git config from the repository into plain data, with limits."""

import json
import re
import tomllib
from collections.abc import Sequence

import yaml
from yaml.nodes import MappingNode, Node, SequenceNode

from repocheck.limits import Limits
from repocheck.parsers.gitconfig import loads_gitconfig
from repocheck.parsers.jsonc import loads_jsonc

FORMATS = ("json", "jsonc", "toml", "yaml", "gitconfig")
FORMAT_LABELS = {
    "json": "JSON",
    "jsonc": "JSON",
    "toml": "TOML",
    "yaml": "YAML",
    "gitconfig": "Git config",
}
# Formats whose key names are case-insensitive (keys are stored lower-cased).
CASE_INSENSITIVE_KEYS = frozenset({"gitconfig"})


class ParseError(ValueError):
    pass


class _LimitedSafeLoader(yaml.SafeLoader):
    """SafeLoader that refuses documents with too many nodes or aliases.

    Aliases are what makes "billion laughs" documents explode once they are walked,
    so ``load_yaml`` also checks the size with every alias expanded.
    """

    def __init__(self, stream: str, limits: Limits) -> None:
        super().__init__(stream)
        self._max_nodes = limits.yaml_max_nodes
        self._max_aliases = limits.yaml_max_aliases
        self._nodes = 0
        self._aliases = 0

    def compose_node(self, parent: Node | None, index: int) -> Node | None:
        if self.check_event(yaml.AliasEvent):
            self._aliases += 1
            if self._aliases > self._max_aliases:
                raise ParseError(f"YAML has more than {self._max_aliases} aliases")
        self._nodes += 1
        if self._nodes > self._max_nodes:
            raise ParseError(f"YAML has more than {self._max_nodes} nodes")
        return super().compose_node(parent, index)


def _children(node: Node) -> list[Node]:
    if isinstance(node, SequenceNode):
        return list(node.value)
    if isinstance(node, MappingNode):
        return [part for pair in node.value for part in pair]
    return []


def expanded_size(node: Node, limit: int) -> int:
    """Node count with aliases expanded; raises once ``limit`` is exceeded or on cycles."""
    sizes: dict[int, int] = {}
    on_stack: set[int] = set()
    stack: list[tuple[Node, bool]] = [(node, False)]
    while stack:
        current, children_done = stack.pop()
        key = id(current)
        if children_done:
            on_stack.discard(key)
            size = 1 + sum(sizes[id(child)] for child in _children(current))
            if size > limit:
                raise ParseError(f"YAML is too large with aliases expanded (> {limit} nodes)")
            sizes[key] = size
            continue
        if key in sizes:
            continue
        if key in on_stack:
            raise ParseError("YAML contains recursive aliases")
        on_stack.add(key)
        stack.append((current, True))
        stack.extend((child, False) for child in _children(current) if id(child) not in sizes)
    return sizes[id(node)]


def load_yaml(text: str, limits: Limits) -> object:
    loader = _LimitedSafeLoader(text, limits)
    try:
        node = loader.get_single_node()
        if node is None:
            return None
        expanded_size(node, limits.yaml_max_nodes)
        result: object = loader.construct_document(node)
        return result
    finally:
        loader.dispose()


def parse(text: str, fmt: str, limits: Limits) -> object:
    """Parse ``text``. Every failure, including too deep nesting, is a ``ParseError``."""
    try:
        if fmt == "json":
            result: object = json.loads(text)
            return result
        if fmt == "jsonc":
            return loads_jsonc(text)
        if fmt == "toml":
            return tomllib.loads(text)
        if fmt == "yaml":
            return load_yaml(text, limits)
        if fmt == "gitconfig":
            return loads_gitconfig(text)
    except ParseError:
        raise
    except (ValueError, RecursionError, yaml.YAMLError) as exc:
        raise ParseError(f"{type(exc).__name__}: {_first_line(str(exc))}") from None
    raise ValueError(f"unknown format {fmt!r}")


def _first_line(message: str) -> str:
    return message.strip().splitlines()[0] if message.strip() else "invalid document"


def _key_regex(key: str, ignore_case: bool) -> re.Pattern[str]:
    # A key followed by ':' (JSON/YAML), '=' (TOML, Git config), ']'/'.' (TOML table
    # headers) or a quoted subsection (Git config: [filter "lfs"]).
    return re.compile(
        rf"(?<![\w.-])[\"']?{re.escape(key)}[\"']?(?=[ \t]*[:=\].]|[ \t]+\")",
        re.IGNORECASE if ignore_case else 0,
    )


def line_of_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def find_line(
    text: str,
    keys: Sequence[str | int],
    value: str | None = None,
    *,
    ignore_case: bool = False,
) -> int | None:
    """Best-effort line of a key path; the parsers do not report positions.

    Walks the string keys in order. For the last key, an occurrence whose line also
    contains ``value`` is preferred; otherwise the first occurrence of ``value`` after
    the key (values of nested objects and arrays), otherwise the key itself. The value
    is looked up as a quoted string first, so ``Bash`` does not land on ``"Bash(x)"``.
    """
    names = [k for k in keys if isinstance(k, str)]
    if not names:
        return None
    pos = 0
    for name in names[:-1]:
        match = _key_regex(name, ignore_case).search(text, pos)
        if match is None:
            break
        pos = match.end()
    leaves = [m.start() for m in _key_regex(names[-1], ignore_case).finditer(text, pos)]
    if not leaves:
        return line_of_offset(text, pos) if pos else None
    needles = [json.dumps(value, ensure_ascii=False), value] if value else []
    for needle in needles:
        for start in leaves:
            line_end = text.find("\n", start)
            if needle in text[start : line_end if line_end != -1 else len(text)]:
                return line_of_offset(text, start)
    for needle in needles:
        found = text.find(needle, leaves[0])
        if found != -1:
            return line_of_offset(text, found)
    return line_of_offset(text, leaves[0])
