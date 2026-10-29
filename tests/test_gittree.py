"""File tree straight from Git objects, and bounded object reads."""

import zlib
from pathlib import Path

import pytest

from gitrepo import CommitSpec, build_repo, local_transport
from helpers import builtin_rules
from repovet.engine.context import ScanContext
from repovet.engine.runner import run_rules
from repovet.limits import DEFAULT_LIMITS, Limits
from repovet.models import CoverageCollector
from repovet.sources.gitobjects import GitObjectError, GitObjects, is_hex_id
from repovet.sources.gittree import (
    REASON_DOT_GIT,
    REASON_SUBMODULE,
    GitTree,
)
from repovet.sources.local import REASON_ENV_DIR, REASON_LINK
from repovet.sources.remote import GitHubRepo, clone
from repovet.sources.tree import LinkKind

SUB = "a" * 40


def _tree(
    tmp_path: Path, files: dict[str, object], limits: Limits = DEFAULT_LIMITS
) -> tuple[GitTree, CoverageCollector, GitObjects]:
    origin = tmp_path / "repo.git"
    ids = build_repo(origin, [CommitSpec(files)])
    objects = GitObjects(str(origin / "objects"))
    coverage = CoverageCollector()
    return GitTree(objects, ids[-1].encode(), limits, coverage, "label"), coverage, objects


def test_files_links_submodules_and_skipped_entries(tmp_path: Path) -> None:
    tree, coverage, objects = _tree(
        tmp_path,
        {
            "b.txt": "bbb",
            "a/z.txt": "zzz",
            "a/sub/x.txt": "x",
            "link": {"symlink": "../outside"},
            "vendor-mod": {"submodule": SUB},
            ".GIT/config": "[core]\n\tfsmonitor = x\n",
            "node_modules/p/index.js": "x",
        },
    )
    with objects:
        assert [f.path for f in tree.files()] == ["b.txt", "a/z.txt", "a/sub/x.txt"]
        assert tree.files()[0].size == 3
        assert tree.files()[0].read_bytes(2) == b"bb"
        assert [(lk.path, lk.kind, lk.target) for lk in tree.links()] == [
            ("link", LinkKind.SYMLINK, "../outside")
        ]
    reasons = {(c.scope, c.reason): c.sample for c in coverage.items()}
    assert reasons[("git:submodules", REASON_SUBMODULE)] == ("vendor-mod",)
    assert reasons[("file", REASON_DOT_GIT)] == (".GIT",)
    assert reasons[("file", REASON_LINK)] == ("link",)
    assert reasons[("file", REASON_ENV_DIR)] == ("node_modules",)


def test_rules_see_links_from_git(tmp_path: Path) -> None:
    tree, coverage, objects = _tree(tmp_path, {"docs/link": {"symlink": "../../etc/passwd"}})
    with objects:
        ctx = ScanContext(tree, builtin_rules(), DEFAULT_LIMITS, coverage)
        rule = builtin_rules().get("RC-BIN-011")
        assert rule is not None
        findings = run_rules([rule], ctx)
    assert [f.location.path for f in findings if f.location] == ["docs/link"]


def test_file_limit_and_depth(tmp_path: Path) -> None:
    files: dict[str, object] = {f"f{i}.txt": "x" for i in range(5)}
    files["d1/d2/d3/deep.txt"] = "x"
    tree, coverage, objects = _tree(tmp_path, files, Limits(max_files=3, max_depth=2))
    with objects:
        assert len(tree.files()) == 3
    reasons = " ".join(c.reason for c in coverage.items())
    assert "Scan stopped after 3 files" in reasons


def test_depth_limit(tmp_path: Path) -> None:
    tree, coverage, objects = _tree(tmp_path, {"d1/d2/d3/deep.txt": "x"}, Limits(max_depth=2))
    with objects:
        assert tree.files() == []
    assert any("deeper than 2" in c.reason for c in coverage.items())


def test_large_blob_is_read_from_the_start_only(tmp_path: Path) -> None:
    data = "MZ" + "A" * 5000
    tree, _, objects = _tree(tmp_path, {"big.bin": data})
    with objects:
        objects.full_read_limit = 1000
        file = tree.files()[0]
        assert file.size == 5002
        assert file.read_bytes(10) == b"MZAAAAAAAA"
        with pytest.raises(GitObjectError, match="larger than"):
            objects.read_raw(objects_sha(tree), max_size=100)


def objects_sha(tree: GitTree) -> bytes:
    return tree.files()[0]._sha


def test_packed_objects_and_deltas(tmp_path: Path) -> None:
    origin = tmp_path / "origin.git"
    base = "line\n" * 2000
    build_repo(origin, [CommitSpec({"a.txt": base}), CommitSpec({"a.txt": base + "more\n"})])
    with clone(GitHubRepo("o", "r"), transport=local_transport({"o/r": origin})) as cloned:
        objects = cloned.objects
        commit = objects.commit(cloned.commit)
        tree = GitTree(objects, cloned.commit, DEFAULT_LIMITS, CoverageCollector(), "x")
        assert tree.files()[0].read_bytes(100_000) == (base + "more\n").encode()
        parent = objects.commit(commit.parents[0])
        assert parent.tree != commit.tree
        objects.full_read_limit = 10
        assert tree.files()[0].size == len(base) + 5


def test_damaged_loose_object(tmp_path: Path) -> None:
    objects_dir = tmp_path / "objects"
    sha = "ab" + "c" * 38
    (objects_dir / "ab").mkdir(parents=True)
    (objects_dir / "ab" / sha[2:]).write_bytes(zlib.compress(b"nonsense"))
    with GitObjects(str(objects_dir)) as objects:
        with pytest.raises(GitObjectError, match="damaged"):
            objects.size(sha.encode())
        with pytest.raises(GitObjectError, match="not found"):
            objects.size(b"d" * 40)


def test_bomb_guard_on_loose_objects(tmp_path: Path) -> None:
    objects_dir = tmp_path / "objects"
    sha = "ef" + "0" * 38
    (objects_dir / "ef").mkdir(parents=True)
    payload = b"blob 50000000\0" + b"\0" * 1000
    (objects_dir / "ef" / sha[2:]).write_bytes(zlib.compress(payload))
    with GitObjects(str(objects_dir)) as objects:
        assert objects.size(sha.encode()) == 50_000_000
        with pytest.raises(GitObjectError, match="larger than"):
            objects.read_raw(sha.encode(), max_size=1_000_000)


def test_hex_ids() -> None:
    assert is_hex_id("0" * 40)
    assert not is_hex_id("0" * 39)
    assert not is_hex_id("g" * 40)


def test_delta_chains_are_size_checked(tmp_path: Path) -> None:
    from dulwich.object_format import SHA1
    from dulwich.objects import Blob
    from dulwich.pack import write_pack

    objects_dir = tmp_path / "objects"
    (objects_dir / "pack").mkdir(parents=True)
    big = Blob.from_string(b"0123456789abcdef\n" * 3000)
    small = Blob.from_string(b"0123456789abcdef\n" * 2990 + b"tail\n")
    write_pack(str(objects_dir / "pack" / "pack-test"), [big, small], SHA1, deltify=True)
    with GitObjects(str(objects_dir)) as objects:
        entries = []
        for pack in objects._packs():
            for packed in pack:
                entries.append(objects._pack_entry(pack, pack.index.object_offset(packed)))
        assert any(base is not None for _, _, base, _ in entries), "test pack has no delta"
        for blob in (big, small):
            sha = bytes(blob.id)
            assert objects.size(sha) == len(blob.data)
            assert objects.read_raw(sha, max_size=1 << 20)[1] == blob.data
        by_size = {len(b.data): b for b in (big, small)}
        target_size, base_offset = next(
            (size, base) for _, size, base, _ in entries if base is not None
        )
        delta = by_size[target_size]
        base_blob = small if delta is big else big
        assert isinstance(base_offset, int)
        # The check covers the base too: a limit between both sizes refuses the read
        # if the base is the larger object, otherwise the object's own size does.
        limit = min(len(delta.data), len(base_blob.data))
        objects._cache = None
        with pytest.raises(GitObjectError, match="larger than"):
            objects.read_raw(bytes(delta.id), max_size=limit)
        objects.full_read_limit = 10
        with pytest.raises(GitObjectError, match="delta"):
            objects.read_prefix(bytes(delta.id), 4)
