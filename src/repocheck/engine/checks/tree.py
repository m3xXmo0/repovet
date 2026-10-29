"""Check type ``tree``: properties of the whole file tree instead of single files.

- ``case_collision``: paths (files, links or folders) that differ only in upper/lower
  case or Unicode normalization. On Windows and macOS only one of them can exist in a
  checkout, so what you see may not be what Git or a case-sensitive tool uses.
- ``link_outside``: symlinks and junctions whose target lies outside the repository
  (absolute targets, or relative targets that climb above the root).
- ``orphan_bytecode``: Python bytecode in ``__pycache__`` whose source module
  (``../<name>.py``) is missing. Caches next to their source are created by every run
  and are not reported.
"""

import posixpath
import re
import unicodedata
from collections.abc import Iterator

from repocheck.engine.checks.base import BuildEnv, Match, Params, TreeCheck
from repocheck.sources.tree import FileTree, LinkKind

PROPERTIES = ("case_collision", "link_outside", "orphan_bytecode")
_ABSOLUTE = re.compile(r"[A-Za-z]:|/|\\\\\?\\")


def _key(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def case_collisions(paths: list[str]) -> Iterator[tuple[str, list[str]]]:
    """(first path, other spellings) for every group of colliding paths or folders."""
    names: set[str] = set()
    for path in paths:
        parts = path.split("/")
        names.update("/".join(parts[:i]) for i in range(1, len(parts) + 1))
    groups: dict[str, list[str]] = {}
    for name in sorted(names):
        groups.setdefault(_key(name), []).append(name)
    for spellings in groups.values():
        if len(spellings) > 1:
            yield spellings[0], spellings[1:]


def orphan_bytecode(paths: list[str]) -> Iterator[str]:
    """``__pycache__/<module>.<tag>.pyc`` files without ``<module>.py``/``.pyw`` next to
    the ``__pycache__`` folder (compared case-insensitively)."""
    existing = {p.casefold() for p in paths}
    for path in paths:
        folder, _, name = path.rpartition("/")
        parent, _, cache = folder.rpartition("/")
        if cache.casefold() != "__pycache__" or not name.casefold().endswith((".pyc", ".pyo")):
            continue
        module = name.split(".", 1)[0]
        source = f"{parent}/{module}" if parent else module
        if not {f"{source}.py".casefold(), f"{source}.pyw".casefold()} & existing:
            yield path


def leaves_repository(link_path: str, target: str) -> bool:
    target = target.replace("\\", "/") if not target.startswith("\\\\?\\") else target
    if _ABSOLUTE.match(target):
        return True
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(link_path), target))
    return joined == ".." or joined.startswith("../")


class TreePropertyCheck(TreeCheck):
    def __init__(self, prop: str) -> None:
        self.prop = prop

    def tree_matches(self, tree: FileTree) -> Iterator[tuple[str, Match]]:
        if self.prop == "case_collision":
            paths = [f.path for f in tree.files()] + [link.path for link in tree.links()]
            for first, others in case_collisions(paths):
                values = {"match": ", ".join(others), "count": str(len(others) + 1)}
                yield first, Match(values=values)
            return
        if self.prop == "orphan_bytecode":
            for path in orphan_bytecode([f.path for f in tree.files()]):
                yield path, Match(values={"match": path})
            return
        for link in tree.links():
            if link.target is None:
                continue
            if link.kind == LinkKind.JUNCTION or leaves_repository(link.path, link.target):
                yield link.path, Match(values={"match": link.target, "value": link.kind.value})


def build(params: Params, env: BuildEnv) -> TreeCheck:
    prop = params.get_choice("property", PROPERTIES)
    params.done()
    return TreePropertyCheck(prop)
