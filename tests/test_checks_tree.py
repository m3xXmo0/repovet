from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from helpers import MemFile, builtin_rules, materialize, run_check, scan
from repocheck.engine.checks import BUILDERS
from repocheck.engine.checks.base import BuildEnv, Params, TreeCheck
from repocheck.engine.checks.tree import case_collisions, leaves_repository, orphan_bytecode
from repocheck.models import CoverageStatus
from repocheck.sources.tree import LinkEntry, LinkKind


@dataclass
class MemTree:
    paths: list[str]
    link_entries: list[LinkEntry] = field(default_factory=list)
    label: str = "mem"

    def files(self) -> Sequence[MemFile]:
        return [MemFile(p, b"") for p in self.paths]

    def links(self) -> Sequence[LinkEntry]:
        return self.link_entries


def tree_check(prop: str) -> TreeCheck:
    check = BUILDERS["tree"](Params({"type": "tree", "property": prop}), BuildEnv({}))
    assert isinstance(check, TreeCheck)
    return check


def test_case_collisions_of_files_and_folders() -> None:
    found = dict(case_collisions(["README.md", "docs/a.md", "Docs/b.md", "readme.md"]))
    assert found == {"Docs": ["docs"], "README.md": ["readme.md"]}
    # Unicode normalization: precomposed and decomposed umlaut.
    assert list(case_collisions(["\u00fc.md", "u\u0308.md"])) == [("u\u0308.md", ["\u00fc.md"])]


def test_case_collision_check() -> None:
    matches = list(tree_check("case_collision").tree_matches(MemTree(["A.txt", "a.txt"])))
    assert [(path, m.values["match"]) for path, m in matches] == [("A.txt", "a.txt")]


def test_leaves_repository() -> None:
    assert leaves_repository("docs/x", "../../etc")
    assert leaves_repository("x", "/etc/passwd")
    assert leaves_repository("x", "C:\\Users\\me")
    assert leaves_repository("x", "\\\\?\\C:\\data")
    assert leaves_repository("x", "\\\\server\\share")
    assert not leaves_repository("docs/x", "../AGENTS.md")
    assert not leaves_repository("a/b/c", "../../d")


def test_link_check_reports_junctions_and_outside_links() -> None:
    links = [
        LinkEntry("in", LinkKind.SYMLINK, "AGENTS.md"),
        LinkEntry("out", LinkKind.SYMLINK, "../x"),
        LinkEntry("junction", LinkKind.JUNCTION, "D:\\repo\\sub"),
        LinkEntry("unknown", LinkKind.REPARSE_POINT, None),
    ]
    matches = list(tree_check("link_outside").tree_matches(MemTree([], links)))
    assert [path for path, _ in matches] == ["out", "junction"]


def test_tree_rules_respect_file_globs(tmp_path: Path) -> None:
    rule = builtin_rules().get("RC-BIN-010")
    assert rule is not None
    repo = materialize(tmp_path / "repo", {"a.txt": "x"})
    assert scan(repo, [rule]).findings == []


def test_filename_target_path() -> None:
    spec = {"type": "filename", "target": "path", "name_regex": "(?:\\A|/)aux(?:/|\\Z)"}
    assert len(run_check(spec, "aux/readme.md", "x")) == 1
    assert run_check(spec, "auxiliary/readme.md", "x") == []
    assert run_check({**spec, "target": "name"}, "aux/readme.md", "x") == []


def test_lfs_pointers_are_listed_as_not_checked(tmp_path: Path) -> None:
    pointer = "version https://git-lfs.github.com/spec/v1\noid sha256:00\nsize 12\n"
    repo = materialize(tmp_path / "repo", {"assets/big.bin": pointer, ".gitmodules": ""})
    from repocheck.analyzers import run_all
    from repocheck.engine.context import ScanContext
    from repocheck.limits import DEFAULT_LIMITS
    from repocheck.models import CoverageCollector
    from repocheck.sources.local import LocalTree

    coverage = CoverageCollector()
    tree = LocalTree(repo, DEFAULT_LIMITS, coverage)
    run_all(ScanContext(tree, builtin_rules(), DEFAULT_LIMITS, coverage))
    unsupported = {
        c.scope: c.sample for c in coverage.items() if c.status == CoverageStatus.UNSUPPORTED
    }
    assert unsupported["git:lfs"] == ("assets/big.bin",)
    assert unsupported["git:submodules"] == (".gitmodules",)


def test_orphan_bytecode() -> None:
    paths = [
        "a.py",
        "__pycache__/a.cpython-312.pyc",
        "__pycache__/b.cpython-312.pyc",
        "pkg/C.py",
        "pkg/__pycache__/c.cpython-312.opt-1.pyc",
        "pkg/__pycache__/d.cpython-312.pyc",
        "pkg/__pycache__/notes.txt",
    ]
    assert list(orphan_bytecode(paths)) == [
        "__pycache__/b.cpython-312.pyc",
        "pkg/__pycache__/d.cpython-312.pyc",
    ]
