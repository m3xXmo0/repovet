"""Build Git repositories for tests with dulwich, only under tmp_path.

Each commit lists its complete file tree (not a diff). Nothing is checked out: blobs,
trees and commits go straight into the object store, so fixture file names never
appear on disk.
"""

import base64
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from dulwich.client import GitClient, LocalGitClient
from dulwich.objects import Blob, Commit, ObjectID, Tag, Tree
from dulwich.refs import Ref
from dulwich.repo import Repo

from repovet.sources.remote import GitHubRepo

AUTHOR = "Test Author <author@example.invalid>"
BASE_TIME = 1_700_000_000
_REG = 0o100644
_EXEC = 0o100755
_LINK = 0o120000
_GITLINK = 0o160000
_DIR = 0o040000
SIGNATURE = b"-----BEGIN PGP SIGNATURE-----\n\ndummy\n-----END PGP SIGNATURE-----\n"


@dataclass
class CommitSpec:
    files: Mapping[str, object]
    message: str = "Change files\n"
    author: str = AUTHOR
    committer: str | None = None
    # Default: one commit per hour from BASE_TIME; commit_time defaults to author_time.
    author_time: int | None = None
    commit_time: int | None = None
    timezone: int = 0
    gpgsig: bool = False
    extra_parents: Sequence[int] = field(default_factory=list)


def _content(rel: str, value: object) -> tuple[int, bytes]:
    if isinstance(value, str):
        return _REG, value.encode("utf-8")
    if isinstance(value, bytes):
        return _REG, value
    if isinstance(value, dict) and set(value) == {"base64"}:
        return _REG, base64.b64decode(str(value["base64"]))
    if isinstance(value, dict) and set(value) == {"executable"}:
        return _EXEC, str(value["executable"]).encode("utf-8")
    if isinstance(value, dict) and set(value) == {"symlink"}:
        return _LINK, str(value["symlink"]).encode("utf-8")
    if isinstance(value, dict) and set(value) == {"submodule"}:
        return _GITLINK, str(value["submodule"]).encode("ascii")
    if isinstance(value, dict) and {"repeat", "count"} <= set(value):
        text = (
            str(value.get("prefix", ""))
            + str(value["repeat"]) * int(str(value["count"]))
            + str(value.get("suffix", ""))
        )
        return _REG, text.encode("utf-8")
    raise TypeError(f"unsupported fixture content for {rel!r}")


def _tree(repo: Repo, files: Mapping[str, object]) -> bytes:
    nested: dict[str, object] = {}
    for rel, value in files.items():
        parts = rel.split("/")
        node = nested
        for part in parts[:-1]:
            child = node.setdefault(part, {})
            assert isinstance(child, dict)
            node = child
        node[parts[-1]] = _content(rel, value)

    def build(node: Mapping[str, object]) -> bytes:
        tree = Tree()
        for name, child in node.items():
            if isinstance(child, dict):
                tree.add(name.encode("utf-8"), _DIR, ObjectID(build(child)))
                continue
            assert isinstance(child, tuple)
            mode, data = child
            if mode == _GITLINK:
                tree.add(name.encode("utf-8"), mode, ObjectID(data))
                continue
            blob = Blob.from_string(data)
            repo.object_store.add_object(blob)
            tree.add(name.encode("utf-8"), mode, blob.id)
        repo.object_store.add_object(tree)
        return bytes(tree.id)

    return build(nested)


def expand_history(entries: Sequence[Mapping[str, object]]) -> list[CommitSpec]:
    """Rule-case history: CommitSpec fields plus ``repeat`` (number of commits),
    ``step`` and ``commit_step`` (seconds between their author and commit dates) and
    ``generated_files`` (that many small files ``src/mod_<i>.py`` in the tree)."""
    specs: list[CommitSpec] = []
    for raw in entries:
        entry = dict(raw)
        files = dict(entry.pop("files", None) or {})  # type: ignore[call-overload]
        for i in range(int(str(entry.pop("generated_files", 0)))):
            files[f"src/mod_{i}.py"] = f"x = {i}\n"
        entry["files"] = files
        repeat = int(str(entry.pop("repeat", 1)))
        step = int(str(entry.pop("step", 3600)))
        commit_step = int(str(entry.pop("commit_step", step)))
        for i in range(repeat):
            spec = CommitSpec(**entry)  # type: ignore[arg-type]
            if spec.author_time is not None:
                spec.author_time += i * step
            if spec.commit_time is not None:
                spec.commit_time += i * commit_step
            specs.append(spec)
    return specs


def build_repo(
    path: Path,
    commits: Sequence[CommitSpec | Mapping[str, object]],
    *,
    bare: bool = True,
    branch: str = "main",
    tags: Mapping[str, int] | None = None,
    annotated: bool = False,
) -> list[str]:
    """Create a repository at ``path`` (bare, or a folder with ``.git``) with a linear
    history; returns the commit ids, oldest first. ``tags`` maps names to commit
    indexes."""
    path.mkdir(parents=True, exist_ok=True)
    repo = Repo.init_bare(str(path)) if bare else Repo.init(str(path))
    ids: list[bytes] = []
    try:
        for index, raw in enumerate(commits):
            spec = raw if isinstance(raw, CommitSpec) else CommitSpec(**raw)  # type: ignore[arg-type]
            commit = Commit()
            commit.tree = ObjectID(_tree(repo, spec.files))
            commit.parents = [ObjectID(ids[-1])] if ids else []
            commit.parents += [ObjectID(ids[i]) for i in spec.extra_parents]
            commit.author = spec.author.encode("utf-8")
            commit.committer = (spec.committer or spec.author).encode("utf-8")
            commit.author_time = (
                spec.author_time if spec.author_time is not None else BASE_TIME + index * 3600
            )
            commit.commit_time = (
                spec.commit_time if spec.commit_time is not None else commit.author_time
            )
            commit.author_timezone = commit.commit_timezone = spec.timezone
            commit.message = spec.message.encode("utf-8")
            if spec.gpgsig:
                commit.gpgsig = (
                    b"-----BEGIN PGP SIGNATURE-----\n\ndummy\n-----END PGP SIGNATURE-----\n"
                )
            repo.object_store.add_object(commit)
            ids.append(bytes(commit.id))
        if ids:
            repo.refs[Ref(f"refs/heads/{branch}".encode())] = ObjectID(ids[-1])
            repo.refs.set_symbolic_ref(Ref(b"HEAD"), Ref(f"refs/heads/{branch}".encode()))
        for name, index in (tags or {}).items():
            target = ids[index]
            if annotated:
                tag = Tag()
                tag.name = name.encode("utf-8")
                tag.object = (Commit, ObjectID(target))
                tag.tagger = AUTHOR.encode("utf-8")
                tag.tag_time = BASE_TIME
                tag.tag_timezone = 0
                tag.message = b"release\n"
                repo.object_store.add_object(tag)
                target = bytes(tag.id)
            repo.refs[Ref(f"refs/tags/{name}".encode())] = ObjectID(target)
    finally:
        repo.close()
    return [sha.decode("ascii") for sha in ids]


type Transport = Callable[[GitHubRepo, float], tuple[GitClient, str]]


def local_transport(repos: Mapping[str, Path]) -> Transport:
    """A transport that serves ``owner/name`` from local repositories (no network)."""

    def transport(repo: GitHubRepo, timeout: float) -> tuple[GitClient, str]:
        return LocalGitClient(), str(repos[f"{repo.owner}/{repo.name}"])

    return transport
