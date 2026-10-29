"""Git history for the provenance profile: from a URL clone or a local ``.git`` folder.

A local ``.git`` is read only, and only if nothing in it leads elsewhere: the folder,
``objects``, ``refs`` and everything below them must not be links, and there must be no
``commondir`` (worktrees) or alternates file (objects in another repository). HEAD and
refs are read here, not by dulwich, so a crafted ref cannot point outside ``.git``.
Commits are parsed through ``GitObjects`` (sizes checked before inflating).
"""

import os
import re
import stat
import time
from collections import Counter, deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from repocheck.limits import Limits
from repocheck.parsers.gitconfig import loads_gitconfig
from repocheck.sources.gitobjects import GitObjectError, GitObjects, is_hex_id

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
_REF_NAME = re.compile(r"refs/[A-Za-z0-9._/@+-]{1,250}")
_SMALL_FILE = 4096
_PACKED_REFS_LIMIT = 16 * 1024 * 1024
_CONFIG_LIMIT = 256 * 1024
_MESSAGE_LIMIT = 64 * 1024
_MAX_TREES = 100_000
_MODE_DIR = 0o040000

REASON_NO_GIT = "No .git folder; the Git history was not checked"


@dataclass
class GitSource:
    """Where the history comes from. ``objects`` must stay open while it is used."""

    objects: GitObjects
    head: bytes
    origin: str
    shallow: bool = False


def _is_link(path: str, st: os.stat_result) -> bool:
    return (
        stat.S_ISLNK(st.st_mode)
        or os.path.isjunction(path)
        or bool(getattr(st, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT)
    )


def _plain(path: str, *, folder: bool) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if _is_link(path, st):
        return False
    return stat.S_ISDIR(st.st_mode) if folder else stat.S_ISREG(st.st_mode)


def _contains_link(folder: str, max_entries: int = 1_000_000) -> bool:
    """True if anything below ``folder`` is a link or a special file."""
    stack = [folder]
    seen = 0
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    seen += 1
                    if seen > max_entries:
                        return True
                    st = entry.stat(follow_symlinks=False)
                    if _is_link(entry.path, st):
                        return True
                    if stat.S_ISDIR(st.st_mode):
                        stack.append(entry.path)
                    elif not stat.S_ISREG(st.st_mode):
                        return True
        except OSError:
            return True
    return False


def _read_small(path: str, limit: int = _SMALL_FILE) -> bytes | None:
    if not _plain(path, folder=False):
        return None
    try:
        fd = os.open(path, _OPEN_FLAGS)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(limit + 1)
    return None if len(data) > limit else data


def _resolve_ref(git_dir: str, name: str) -> str | None:
    if not _REF_NAME.fullmatch(name) or ".." in name or "//" in name or name.endswith("/"):
        return None
    loose = _read_small(os.path.join(git_dir, *name.split("/")))
    if loose is not None:
        value = loose.decode("ascii", "replace").strip()
        return value if is_hex_id(value) else None
    packed = _read_small(os.path.join(git_dir, "packed-refs"), _PACKED_REFS_LIMIT)
    for line in (packed or b"").decode("utf-8", "replace").splitlines():
        sha, _, ref = line.partition(" ")
        if ref.strip() == name and is_hex_id(sha):
            return sha
    return None


def open_local(root: Path) -> GitSource | str:
    """The history of ``root/.git``, or the reason why it is not read."""
    git_dir = os.path.join(str(root), ".git")
    try:
        st = os.lstat(git_dir)
    except OSError:
        return REASON_NO_GIT
    if _is_link(git_dir, st):
        return ".git is a link; the Git history was not read"
    if not stat.S_ISDIR(st.st_mode):
        return ".git is a file that points elsewhere; the Git history was not read"
    objects_dir = os.path.join(git_dir, "objects")
    for name in ("commondir", "objects/info/alternates", "objects/info/http-alternates"):
        if os.path.lexists(os.path.join(git_dir, *name.split("/"))):
            return f".git uses '{name}' (objects or refs elsewhere); the Git history was not read"
    if not _plain(objects_dir, folder=True):
        return ".git has no plain 'objects' folder; the Git history was not read"
    for folder in (objects_dir, os.path.join(git_dir, "refs")):
        if os.path.lexists(folder) and _contains_link(folder):
            return ".git contains links or special files; the Git history was not read"
    head = _read_small(os.path.join(git_dir, "HEAD"))
    if head is None:
        return ".git has no readable HEAD; the Git history was not read"
    text = head.decode("utf-8", "replace").strip()
    if text.startswith("ref:"):
        sha = _resolve_ref(git_dir, text[4:].strip())
        if sha is None:
            return "HEAD does not point to a commit (empty repository or reftable); not read"
    elif is_hex_id(text):
        sha = text
    else:
        return "HEAD is not a SHA-1 commit id (SHA-256 repositories are not supported)"
    shallow = os.path.lexists(os.path.join(git_dir, "shallow"))
    return GitSource(GitObjects(objects_dir), sha.encode("ascii"), ".git folder", shallow)


def remote_urls(root: Path) -> dict[str, str]:
    """Remote name -> URL from ``root/.git/config`` (read as a plain file, never through
    git). These are claims made by whoever prepared the folder, not facts."""
    git_dir = os.path.join(str(root), ".git")
    if not _plain(git_dir, folder=True):
        return {}
    data = _read_small(os.path.join(git_dir, "config"), _CONFIG_LIMIT)
    if data is None:
        return {}
    try:
        config = loads_gitconfig(data.decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        return {}
    remotes = config.get("remote")
    urls: dict[str, str] = {}
    if isinstance(remotes, dict):
        for name, section in remotes.items():
            url = section.get("url") if isinstance(section, dict) else None
            if isinstance(url, list):
                url = url[0] if url else None
            if isinstance(url, str) and url:
                urls[str(name)] = url
    return urls


# --- history ---------------------------------------------------------------------


@dataclass
class CommitInfo:
    sha: bytes
    author: str
    committer: str
    author_time: int
    author_tz: int
    commit_time: int
    parents: int
    signed: bool
    message: str


@dataclass
class History:
    commits: list[CommitInfo] = field(default_factory=list)
    truncated: bool = False
    missing: int = 0
    unreadable: int = 0
    roots: list[CommitInfo] = field(default_factory=list)


def _text(value: bytes) -> str:
    return value.decode("utf-8", "replace")


def walk(source: GitSource, limits: Limits, deadline: float) -> History:
    """Every commit reachable from HEAD (all parents), breadth first."""
    history = History()
    seen: set[bytes] = {source.head}
    queue = deque([source.head])
    while queue:
        if len(history.commits) >= limits.max_commits or time.monotonic() > deadline:
            history.truncated = True
            break
        sha = queue.popleft()
        try:
            commit = source.objects.commit(sha)
        except GitObjectError as exc:
            if "not found" in str(exc):
                history.missing += 1
            else:
                history.unreadable += 1
            continue
        info = CommitInfo(
            sha=sha,
            author=_text(commit.author),
            committer=_text(commit.committer),
            author_time=int(commit.author_time),
            author_tz=int(commit.author_timezone),
            commit_time=int(commit.commit_time),
            parents=len(commit.parents),
            signed=bool(commit.gpgsig),
            message=_text(commit.message[:_MESSAGE_LIMIT]),
        )
        history.commits.append(info)
        if not commit.parents:
            history.roots.append(info)
        for parent in commit.parents:
            key = bytes(parent)
            if key not in seen:
                seen.add(key)
                queue.append(key)
    return history


def count_files(objects: GitObjects, commit: bytes, limit: int) -> int | None:
    """Regular files and links in the tree of ``commit`` (``None`` if unreadable)."""
    try:
        stack = [bytes(objects.commit(commit).tree)]
        files = trees = 0
        while stack:
            trees += 1
            if trees > _MAX_TREES or files > limit:
                return None
            for entry in objects.tree(stack.pop()).items():
                if entry.mode == _MODE_DIR:
                    stack.append(bytes(entry.sha))
                elif stat.S_ISREG(entry.mode) or stat.S_ISLNK(entry.mode):
                    files += 1
    except GitObjectError:
        return None
    return files


def identities(commits: list[CommitInfo]) -> Iterator[tuple[str, str]]:
    """(name, lowercase email) of each commit's author."""
    for info in commits:
        name, _, rest = info.author.partition("<")
        yield name.strip(), rest.rstrip(">").strip().lower()


def top(counter: Counter[str], n: int) -> list[tuple[str, int]]:
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]
