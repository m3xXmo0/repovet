"""Check type ``dependency``: dependencies and package sources declared in manifests.

Modes:
- ``typosquat``: a registry dependency whose name is a small edit away from a popular
  package but is not itself a known popular package (local lists in ``data/``, no
  registry queries).
- ``source``: dependencies installed from Git, a URL or a local path instead of the
  registry (``kinds``).
- ``index``: package indexes and registries that a manifest adds or replaces
  (``--index-url``, ``--extra-index-url``, Poetry/uv/Pipfile sources), except
  ``allow_hosts``.
"""

import functools
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

from repovet.engine.checks.base import BuildEnv, Check, CheckError, FileView, Match, Params
from repovet.models import CoverageStatus
from repovet.parsers.manifests import Dependency, Manifest, normalize, parse_manifest

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
POPULAR_LISTS = {"pypi": "pypi-top.txt", "npm": "npm-top.txt"}
ECOSYSTEMS = tuple(POPULAR_LISTS)
MODES = ("typosquat", "source", "index")
KINDS = ("git", "url", "path")
_MEMO_KEY = "dependency:manifest"


@functools.cache
def popular(ecosystem: str) -> dict[str, int]:
    """Normalized package name -> rank (1 = most downloaded)."""
    path = DATA_DIR / POPULAR_LISTS[ecosystem]
    ranks: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        name = line.strip()
        if name and not name.startswith("#"):
            ranks.setdefault(normalize(ecosystem, name), len(ranks) + 1)
    return ranks


def distance(a: str, b: str, limit: int) -> int:
    """Optimal string alignment distance (insert, delete, substitute, swap neighbours);
    stops early and returns ``limit + 1`` once the distance must exceed ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    previous2: list[int] = []
    previous = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        current = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                current[j] = min(current[j], previous2[j - 2] + 1)
        if min(current) > limit:
            return limit + 1
        previous2, previous = previous, current
    return previous[-1]


def manifest_of(view: FileView) -> Manifest | None:
    """Parsed manifest, shared by all dependency rules for this file."""
    if _MEMO_KEY not in view.memo:
        text = view.text()
        manifest = None
        if text is not None:
            try:
                manifest = parse_manifest(view.name, text, view.structured)
            except ValueError:
                view.note(CoverageStatus.FAILED, "Files that could not be parsed as setup.cfg")
        view.memo[_MEMO_KEY] = manifest
    cached = view.memo[_MEMO_KEY]
    return cached if isinstance(cached, Manifest) else None


class DependencyCheck(Check):
    def __init__(
        self,
        mode: str,
        ecosystems: set[str],
        top: int,
        rank_from: int,
        max_distance: int,
        min_length: int,
        kinds: set[str],
        allow_hosts: set[str],
    ) -> None:
        self.mode = mode
        self.ecosystems = ecosystems
        self.top = top
        self.rank_from = rank_from
        self.max_distance = max_distance
        self.min_length = min_length
        self.kinds = kinds
        self.allow_hosts = allow_hosts
        self._target_cache: dict[str, list[tuple[str, int]]] = {}

    def matches(self, view: FileView) -> Iterator[Match]:
        manifest = manifest_of(view)
        if manifest is None:
            return
        if self.mode == "index":
            yield from self._indexes(view, manifest)
            return
        for dep in manifest.dependencies:
            if dep.ecosystem not in self.ecosystems:
                continue
            if self.mode == "source":
                if dep.kind in self.kinds:
                    yield self._match(view, dep.line, dep.spec, dep.name, dep.kind)
                continue
            if dep.kind == "registry":
                target = self._lookalike(dep)
                if target is not None:
                    yield self._match(view, dep.line, target[0], dep.name, f"{target[1]:,}")

    def _lookalike(self, dep: Dependency) -> tuple[str, int] | None:
        """The most popular package that ``dep`` is a near miss of, with its rank."""
        name = dep.normalized
        ranks = popular(dep.ecosystem)
        if name in ranks:
            return None
        for target, rank in self._targets(dep.ecosystem):
            if distance(name, target, self.max_distance) <= self.max_distance:
                return target, rank
        return None

    def _targets(self, ecosystem: str) -> list[tuple[str, int]]:
        if ecosystem not in self._target_cache:
            self._target_cache[ecosystem] = [
                (name, rank)
                for name, rank in popular(ecosystem).items()
                if self.rank_from <= rank <= self.top and len(name) >= self.min_length
            ]
        return self._target_cache[ecosystem]

    def _indexes(self, view: FileView, manifest: Manifest) -> Iterator[Match]:
        for index in manifest.indexes:
            if index.ecosystem not in self.ecosystems:
                continue
            value = index.url.strip()
            host = value if index.option == "--trusted-host" else urlsplit(value).hostname
            if host and host.lower() in self.allow_hosts:
                continue
            yield self._match(view, index.line, value, value, index.option)

    @staticmethod
    def _match(view: FileView, line: int | None, match: str, value: str, key: str) -> Match:
        evidence = view.line_text(line) if line else None
        values = {"match": match, "value": value, "key": key, "count": key}
        return Match(line, None, evidence, values)


def build(params: Params, env: BuildEnv) -> Check:
    mode = params.get_choice("mode", MODES)
    ecosystems = params.get_str_list("ecosystems") or list(ECOSYSTEMS)
    unknown = [e for e in ecosystems if e not in ECOSYSTEMS]
    if unknown:
        raise CheckError(f"unknown ecosystem(s) {', '.join(unknown)} ({', '.join(ECOSYSTEMS)})")
    top = params.get_int("top", default=1000, minimum=1)
    rank_from = params.get_int("rank_from", default=1, minimum=1)
    max_distance = params.get_int("max_distance", default=1, minimum=1)
    min_length = params.get_int("min_length", default=5, minimum=1)
    kinds = params.get_str_list("kinds")
    allow_hosts = {h.lower() for h in params.get_str_list("allow_hosts")}
    params.done()
    if max_distance > 2:
        raise CheckError("'max_distance' must be 1 or 2")
    if rank_from > top:
        raise CheckError("'rank_from' must not be greater than 'top'")
    if not set(kinds) <= set(KINDS):
        raise CheckError(f"'kinds' must be from {', '.join(KINDS)}")
    if mode == "source" and not kinds:
        raise CheckError("mode 'source' needs 'kinds'")
    return DependencyCheck(
        mode, set(ecosystems), top, rank_from, max_distance, min_length, set(kinds), allow_hosts
    )
