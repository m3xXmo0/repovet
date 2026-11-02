"""Two local Git revisions, without checkout or untrusted configuration."""

from pathlib import Path

import pytest
from dulwich.object_store import DiskObjectStore
from dulwich.objects import Commit, ObjectID

from gitrepo import CommitSpec, build_repo
from repovet.limits import DEFAULT_LIMITS, Limits
from repovet.models import CoverageCollector
from repovet.sources.gittree import GitTree
from repovet.sources.revisions import (
    RevisionError,
    RevisionIncomplete,
    ensure_ancestor,
    open_pair,
    resolve_revision,
    snapshot,
)


def _repo(tmp_path: Path, specs: list[CommitSpec], **kwargs: object) -> tuple[Path, list[str]]:
    root = tmp_path / "repo"
    root.mkdir()
    return root, build_repo(root / ".git", specs, **kwargs)  # type: ignore[arg-type]


def test_revision_names_and_same_commit(tmp_path: Path) -> None:
    root, ids = _repo(
        tmp_path,
        [CommitSpec({"a.txt": "first"}), CommitSpec({"a.txt": "second"})],
        tags={"start": 0},
        annotated=True,
    )
    with open_pair(root, "start", "main", DEFAULT_LIMITS) as pair:
        assert pair.base == ids[0].encode()
        assert pair.head == ids[1].encode()
        assert resolve_revision(pair.source, "HEAD") == pair.head
        assert resolve_revision(pair.source, "refs/heads/main") == pair.head
        assert resolve_revision(pair.source, ids[0]) == pair.base
        ensure_ancestor(pair.source, pair.head, pair.head, DEFAULT_LIMITS)


def test_packed_ref(tmp_path: Path) -> None:
    root, ids = _repo(tmp_path, [CommitSpec({"a.txt": "first"})])
    (root / ".git/packed-refs").write_text(f"{ids[0]} refs/tags/base\n", encoding="ascii")
    with open_pair(root, "base", "HEAD", DEFAULT_LIMITS) as pair:
        assert pair.base == pair.head


@pytest.mark.parametrize("ref", ["../outside", "refs/../outside", "HEAD~1", "-main", "a//b"])
def test_revision_syntax_rejected(tmp_path: Path, ref: str) -> None:
    root, _ = _repo(tmp_path, [CommitSpec({"a.txt": "a"})])
    with (
        pytest.raises(RevisionError, match="revision"),
        open_pair(root, ref, "HEAD", DEFAULT_LIMITS),
    ):
        pytest.fail("invalid revision accepted")


def test_missing_ref_and_ambiguous_name(tmp_path: Path) -> None:
    root, ids = _repo(
        tmp_path,
        [CommitSpec({"a.txt": "a"}), CommitSpec({"a.txt": "b"})],
        tags={"main": 0},
    )
    with (
        pytest.raises(RevisionError, match="not found"),
        open_pair(root, "missing", "HEAD", DEFAULT_LIMITS),
    ):
        pytest.fail("missing revision accepted")
    with (
        pytest.raises(RevisionError, match="ambiguous"),
        open_pair(root, "main", "HEAD", DEFAULT_LIMITS),
    ):
        pytest.fail("ambiguous revision accepted")
    with open_pair(root, ids[0], "HEAD", DEFAULT_LIMITS) as pair:
        assert pair.head == ids[1].encode()


def test_non_repository(tmp_path: Path) -> None:
    with (
        pytest.raises(RevisionError, match="Git repository"),
        open_pair(tmp_path, "HEAD", "HEAD", DEFAULT_LIMITS),
    ):
        pytest.fail("ordinary folder accepted")


@pytest.mark.parametrize("name", ["commondir", "objects/info/alternates"])
def test_redirecting_repository_is_incomplete(tmp_path: Path, name: str) -> None:
    root, _ = _repo(tmp_path, [CommitSpec({"a.txt": "a"})])
    target = root / ".git" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("../outside\n", encoding="utf-8")
    with (
        pytest.raises(RevisionIncomplete, match="not read"),
        open_pair(root, "HEAD", "HEAD", DEFAULT_LIMITS),
    ):
        pytest.fail("redirecting store accepted")


def test_base_must_be_ancestor(tmp_path: Path) -> None:
    root, ids = _repo(tmp_path, [CommitSpec({"a.txt": "a"}), CommitSpec({"a.txt": "b"})])
    with (
        pytest.raises(RevisionIncomplete, match="not an ancestor"),
        open_pair(root, ids[1], ids[0], DEFAULT_LIMITS),
    ):
        pytest.fail("reverse ancestry accepted")


def test_ancestry_limit_and_missing_commit(tmp_path: Path) -> None:
    root, ids = _repo(
        tmp_path,
        [CommitSpec({"a.txt": str(i)}) for i in range(4)],
    )
    with (
        pytest.raises(RevisionIncomplete, match="limit"),
        open_pair(root, ids[0], "HEAD", Limits(max_commits=1)),
    ):
        pytest.fail("ancestry budget ignored")
    obj = root / ".git/objects" / ids[2][:2] / ids[2][2:]
    obj.chmod(0o644)
    obj.unlink()
    with (
        pytest.raises(RevisionIncomplete, match="missing"),
        open_pair(root, ids[0], "HEAD", DEFAULT_LIMITS),
    ):
        pytest.fail("missing intermediate commit ignored")


def test_shallow_with_proven_path_is_accepted(tmp_path: Path) -> None:
    root, ids = _repo(tmp_path, [CommitSpec({"a.txt": "a"}), CommitSpec({"a.txt": "b"})])
    (root / ".git/shallow").write_text(ids[0] + "\n", encoding="ascii")
    with open_pair(root, ids[0], "HEAD", DEFAULT_LIMITS) as pair:
        assert pair.source.shallow


def test_shallow_without_proven_path_is_incomplete(tmp_path: Path) -> None:
    root, ids = _repo(tmp_path, [CommitSpec({"a.txt": "a"}), CommitSpec({"a.txt": "b"})])
    (root / ".git/shallow").write_text(ids[0] + "\n", encoding="ascii")
    with (
        pytest.raises(RevisionIncomplete, match="shallow"),
        open_pair(root, ids[1], ids[0], DEFAULT_LIMITS),
    ):
        pytest.fail("unproven shallow ancestry accepted")


def test_snapshot_keeps_skipped_directories_links_modes_and_submodules(tmp_path: Path) -> None:
    root, ids = _repo(
        tmp_path,
        [
            CommitSpec(
                {
                    "a.txt": "a",
                    "script.sh": {"executable": "echo example\n"},
                    "node_modules/pkg/a.js": "first",
                    "pointer": {"symlink": "a.txt"},
                    "sub": {"submodule": "a" * 40},
                }
            ),
            CommitSpec(
                {
                    "a.txt": "a",
                    "script.sh": "echo example\n",
                    "node_modules/pkg/a.js": "changed",
                    "pointer": {"symlink": "script.sh"},
                    "sub": {"submodule": "b" * 40},
                }
            ),
        ],
    )
    with open_pair(root, ids[0], ids[1], DEFAULT_LIMITS) as pair:
        before = GitTree(pair.source.objects, pair.base, DEFAULT_LIMITS, CoverageCollector(), "b")
        after = GitTree(pair.source.objects, pair.head, DEFAULT_LIMITS, CoverageCollector(), "h")
        old, new = snapshot(before), snapshot(after)
        assert old["a.txt"] == new["a.txt"]
        assert old["script.sh"] != new["script.sh"]
        assert old["node_modules"] != new["node_modules"]
        assert old["pointer"] != new["pointer"]
        assert old["sub"] != new["sub"]
        assert "node_modules/pkg/a.js" not in old
        assert not (root / "script.sh").exists()


def test_independent_history_is_not_compared(tmp_path: Path) -> None:
    root, ids = _repo(tmp_path, [CommitSpec({"a.txt": "a"})])
    store = DiskObjectStore(str(root / ".git/objects"))
    try:
        original = store[ObjectID(ids[0].encode())]
        assert isinstance(original, Commit)
        unrelated = Commit()
        unrelated.tree = original.tree
        unrelated.parents = []
        unrelated.author = unrelated.committer = original.author
        unrelated.author_time = unrelated.commit_time = original.author_time
        unrelated.author_timezone = unrelated.commit_timezone = 0
        unrelated.message = b"An independent history\n"
        store.add_object(unrelated)
        head = unrelated.id.decode()
    finally:
        store.close()
    with (
        pytest.raises(RevisionIncomplete, match="not an ancestor"),
        open_pair(root, ids[0], head, DEFAULT_LIMITS),
    ):
        pytest.fail("independent histories accepted")


def test_missing_merge_sibling_does_not_hide_a_proven_parent(tmp_path: Path) -> None:
    root, ids = _repo(
        tmp_path,
        [
            CommitSpec({"a.txt": "a"}),
            CommitSpec({"a.txt": "b"}),
            CommitSpec({"a.txt": "c"}, extra_parents=[0]),
        ],
    )
    obj = root / ".git/objects" / ids[1][:2] / ids[1][2:]
    obj.chmod(0o644)
    obj.unlink()
    with open_pair(root, ids[0], "HEAD", DEFAULT_LIMITS) as pair:
        assert pair.base == ids[0].encode()


def test_ancestry_time_limit(tmp_path: Path) -> None:
    root, ids = _repo(tmp_path, [CommitSpec({"a.txt": "a"}), CommitSpec({"a.txt": "b"})])
    with (
        pytest.raises(RevisionIncomplete, match="time limit"),
        open_pair(root, ids[0], "HEAD", Limits(max_scan_seconds=0.0)),
    ):
        pytest.fail("time limit ignored")


def test_missing_commit_object_is_incomplete(tmp_path: Path) -> None:
    root, _ = _repo(tmp_path, [CommitSpec({"a.txt": "a"})])
    with (
        pytest.raises(RevisionIncomplete, match="missing"),
        open_pair(root, "0" * 40, "HEAD", DEFAULT_LIMITS),
    ):
        pytest.fail("missing commit accepted")


def test_invalid_tree_names_do_not_replace_root_identity(tmp_path: Path) -> None:
    root, _ = _repo(tmp_path, [CommitSpec({".": "example", "..": "example"})])
    with open_pair(root, "HEAD", "HEAD", DEFAULT_LIMITS) as pair:
        tree = GitTree(pair.source.objects, pair.head, DEFAULT_LIMITS, CoverageCollector(), "h")
        identities = snapshot(tree)
        assert identities["."].startswith("40000:")
        assert ".." not in identities
