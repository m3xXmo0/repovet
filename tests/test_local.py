import sys
from pathlib import Path

import pytest

from helpers import materialize
from repocheck.limits import DEFAULT_LIMITS, Limits
from repocheck.models import CoverageCollector, CoverageItem, CoverageStatus
from repocheck.sources import local
from repocheck.sources.local import (
    REASON_ENV_DIR,
    REASON_GITFILE,
    REASON_LINK,
    FileChangedError,
    LocalTree,
)
from repocheck.sources.tree import LinkKind


def walk(root: Path, limits: Limits = DEFAULT_LIMITS) -> tuple[LocalTree, list[CoverageItem]]:
    coverage = CoverageCollector()
    tree = LocalTree(root, limits, coverage)
    return tree, coverage.items()


def paths(tree: LocalTree) -> list[str]:
    return [f.path for f in tree.files()]


def test_walk_lists_files_in_order_with_posix_paths(tmp_path: Path) -> None:
    root = materialize(tmp_path / "r", {"b.txt": "b", "a/z.txt": "z", "a/b/c.txt": "c"})
    tree, coverage = walk(root)
    # Files of a folder first, then its subfolders, each in name order.
    assert paths(tree) == ["b.txt", "a/z.txt", "a/b/c.txt"]
    assert coverage == []


def test_git_dir_only_exposes_whitelist(tmp_path: Path) -> None:
    root = materialize(
        tmp_path / "r",
        {
            ".git/config": "[core]\n",
            ".git/HEAD": "ref: refs/heads/main\n",
            ".git/hooks/pre-commit": "#!/bin/sh\n",
            ".git/hooks/pre-push.sample": "#!/bin/sh\n",
            ".git/hooks/sub/inner": "x",
            ".git/info/attributes": "* text\n",
            ".git/info/exclude": "x\n",
            ".git/objects/ab/cdef": "blob",
            "vendor/lib/.git/config": "[core]\n",
            "vendor/lib/.git/objects/x": "blob",
            "src/main.py": "print(1)\n",
        },
    )
    tree, _ = walk(root)
    assert sorted(paths(tree)) == [
        ".git/config",
        ".git/hooks/pre-commit",
        ".git/hooks/pre-push.sample",
        ".git/info/attributes",
        "src/main.py",
        "vendor/lib/.git/config",
    ]


def test_gitfile_is_listed_and_noted(tmp_path: Path) -> None:
    root = materialize(tmp_path / "r", {"sub/.git": "gitdir: ../../elsewhere\n"})
    tree, coverage = walk(root)
    assert paths(tree) == ["sub/.git"]
    assert any(c.reason == REASON_GITFILE and c.sample == ("sub/.git",) for c in coverage)


def test_symlinks_are_listed_not_followed(tmp_path: Path) -> None:
    outside = materialize(tmp_path / "outside", {"secret.txt": "s"})
    root = materialize(tmp_path / "r", {"a.txt": "a"})
    try:
        (root / "link_dir").symlink_to(outside, target_is_directory=True)
        (root / "link_file").symlink_to(outside / "secret.txt")
    except OSError:
        pytest.skip("creating symlinks needs extra rights on this system")
    tree, coverage = walk(root)
    assert paths(tree) == ["a.txt"]
    assert {(link.path, link.kind) for link in tree.links()} == {
        ("link_dir", LinkKind.SYMLINK),
        ("link_file", LinkKind.SYMLINK),
    }
    (item,) = [c for c in coverage if c.reason == REASON_LINK]
    assert item.count == 2


@pytest.mark.skipif(sys.platform != "win32", reason="junctions exist only on Windows")
def test_junctions_are_listed_not_followed(tmp_path: Path) -> None:
    # if/else instead of an early skip: mypy checks reachability per platform and would
    # report the rest as unreachable on Linux and macOS.
    if sys.platform == "win32":
        import _winapi

        outside = materialize(tmp_path / "outside", {"secret.txt": "s"})
        root = materialize(tmp_path / "r", {"a.txt": "a"})
        _winapi.CreateJunction(str(outside), str(root / "junction"))
        tree, coverage = walk(root)
        assert paths(tree) == ["a.txt"]
        assert [(link.path, link.kind) for link in tree.links()] == [
            ("junction", LinkKind.JUNCTION)
        ]
        assert any(c.reason == REASON_LINK for c in coverage)


def test_max_files_limit(tmp_path: Path) -> None:
    root = materialize(tmp_path / "r", {f"f{i}.txt": "x" for i in range(10)})
    tree, coverage = walk(root, Limits(max_files=3))
    assert len(tree.files()) == 3
    assert any(c.status == CoverageStatus.PARTIAL and "3 files" in c.reason for c in coverage)


def test_max_depth_limit(tmp_path: Path) -> None:
    root = materialize(tmp_path / "r", {"a/b/c/d.txt": "x", "top.txt": "y"})
    tree, coverage = walk(root, Limits(max_depth=2))
    assert paths(tree) == ["top.txt"]
    assert any("deeper than 2" in c.reason and c.sample == ("a/b/c",) for c in coverage)


def test_env_dirs_are_skipped_and_reported(tmp_path: Path) -> None:
    root = materialize(
        tmp_path / "r",
        {
            ".venv/lib/x.py": "x",
            "venv/pyvenv.cfg": "x",
            "web/node_modules/dep/package.json": "{}",
            "api/Node_Modules/other/index.js": "x",
            ".tox/py312/x": "x",
            "src/venvs/keep.py": "x",
            "app.py": "x",
        },
    )
    tree, coverage = walk(root)
    assert paths(tree) == ["app.py", "src/venvs/keep.py"]
    (item,) = [c for c in coverage if c.reason == REASON_ENV_DIR]
    assert item.status == CoverageStatus.SKIPPED
    assert item.sample == (".tox", ".venv", "api/Node_Modules", "venv", "web/node_modules")


def test_env_dirs_can_be_included(tmp_path: Path) -> None:
    root = materialize(tmp_path / "r", {".venv/x.py": "x", "node_modules/a/b.js": "y"})
    tree, coverage = walk(root, Limits(skip_env_dirs=False))
    assert paths(tree) == [".venv/x.py", "node_modules/a/b.js"]
    assert coverage == []


def test_read_bytes_respects_limit(tmp_path: Path) -> None:
    root = materialize(tmp_path / "r", {"a.txt": "0123456789"})
    tree, _ = walk(root)
    (file,) = tree.files()
    assert file.size == 10
    assert file.read_bytes(4) == b"0123"
    assert file.read_bytes(100) == b"0123456789"


def test_read_bytes_refuses_a_swapped_file(tmp_path: Path) -> None:
    root = materialize(tmp_path / "r", {"a.txt": "original", "b.txt": "other"})
    tree, _ = walk(root)
    first = tree.files()[0]
    (root / "b.txt").replace(root / "a.txt")
    with pytest.raises(FileChangedError):
        first.read_bytes(100)


def test_walk_does_not_modify_the_folder(tmp_path: Path) -> None:
    root = materialize(tmp_path / "r", {".git/config": "x", "a/b.txt": "y"})
    before = {p: p.stat().st_mtime_ns for p in root.rglob("*")}
    tree, _ = walk(root)
    for file in tree.files():
        file.read_bytes(10)
    assert {p: p.stat().st_mtime_ns for p in root.rglob("*")} == before


def test_git_folder_name_follows_the_file_system_case_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = materialize(tmp_path / "r", {".GIT/config": "[core]\n", ".GIT/run.sh": "echo\n"})
    monkeypatch.setattr(local, "_GIT_NAME_ANY_CASE", True)
    assert paths(walk(root)[0]) == [".GIT/config"]
    # Linux: ".GIT" is not Git's folder, so everything in it is ordinary content.
    monkeypatch.setattr(local, "_GIT_NAME_ANY_CASE", False)
    assert paths(walk(root)[0]) == [".GIT/config", ".GIT/run.sh"]
    assert local.is_git_name(".git")
    assert not local.is_git_name(".Git")
