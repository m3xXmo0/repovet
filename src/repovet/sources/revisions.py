"""Read two local commit trees through the guarded Git object reader.

Revision lookup reads bounded ref files directly. Repository configuration, hooks,
working-tree contents and the Git executable are never used.
"""

import re
import time
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from repovet.limits import Limits
from repovet.sources import gitmeta
from repovet.sources.gitmeta import GitSource
from repovet.sources.gitobjects import GitObjectError, is_hex_id
from repovet.sources.gittree import GitTree

_REVISION = re.compile(r"[A-Za-z0-9._/@+-]{1,250}")


class RevisionError(ValueError):
    """The requested local repository or revision is not valid input."""


class RevisionIncomplete(Exception):
    """Revision data or the ancestry proof could not be read completely."""


@dataclass(frozen=True)
class RevisionPair:
    source: GitSource
    base: bytes
    head: bytes


def resolve_revision(source: GitSource, ref: str) -> bytes:
    """Resolve HEAD, a complete SHA-1, branch, tag or full ref to a commit.

    ``source`` must have been opened by ``gitmeta.open_local``. Names remain inside
    the already validated refs tree; no revision expressions or short object ids.
    """
    if ref == "HEAD":
        sha = source.head
    elif is_hex_id(ref.lower()):
        sha = ref.lower().encode("ascii")
    else:
        if (
            not _REVISION.fullmatch(ref)
            or ".." in ref
            or "//" in ref
            or ref.startswith(("/", "-"))
            or ref.endswith("/")
        ):
            raise RevisionError(
                f"invalid revision {ref!r}; use HEAD, a branch, tag or full commit id"
            )
        names = (
            [ref]
            if ref.startswith("refs/")
            else [f"refs/heads/{ref}", f"refs/tags/{ref}", f"refs/remotes/{ref}"]
        )
        git_dir = str(Path(source.objects.path).parent)
        # This is the same bounded, no-final-link ref reader as local history uses.
        found = {value for name in names if (value := gitmeta._resolve_ref(git_dir, name))}
        if not found:
            raise RevisionError(f"revision {ref!r} not found in the local repository")
        if len(found) != 1:
            raise RevisionError(f"revision {ref!r} is ambiguous; use its full refs/... name")
        sha = found.pop().encode("ascii")
    try:
        return source.objects.peel(sha)
    except GitObjectError:
        raise RevisionIncomplete(
            f"revision {ref!r} has missing, damaged or oversized Git objects"
        ) from None


def ensure_ancestor(source: GitSource, base: bytes, head: bytes, limits: Limits) -> None:
    """Prove that Base is an ancestor of Head, within commit and time limits.

    A shallow marker does not prevent a proof using objects that are present. If
    no proof is found, missing objects and a shallow boundary remain inconclusive.
    """
    try:
        source.objects.commit(base)
        source.objects.commit(head)
    except GitObjectError:
        raise RevisionIncomplete("ancestry has missing, damaged or oversized commits") from None
    if base == head:
        return
    deadline = time.monotonic() + limits.max_scan_seconds
    queue = deque([head])
    seen = {head}
    missing = limited = False
    while queue:
        if time.monotonic() >= deadline:
            raise RevisionIncomplete("ancestry proof reached the scan time limit")
        sha = queue.popleft()
        try:
            commit = source.objects.commit(sha)
        except GitObjectError:
            missing = True
            continue
        for parent in commit.parents:
            value = bytes(parent)
            if value == base:
                return
            if value in seen:
                continue
            if len(seen) >= limits.max_commits:
                limited = True
                continue
            seen.add(value)
            queue.append(value)
    if limited:
        raise RevisionIncomplete("ancestry proof reached the commit limit")
    if missing or source.shallow:
        raise RevisionIncomplete("ancestry is incomplete: shallow history or missing commits")
    raise RevisionIncomplete("Base is not an ancestor of Head; revisions were not compared")


@contextmanager
def open_pair(root: Path, base: str, head: str, limits: Limits) -> Iterator[RevisionPair]:
    """Open a guarded local Git store until both immutable trees have been scanned."""
    source = gitmeta.open_local(root)
    if isinstance(source, str):
        if source == gitmeta.REASON_NO_GIT:
            raise RevisionError(f"local Git repository required: {root}")
        raise RevisionIncomplete(source)
    try:
        before = resolve_revision(source, base)
        after = resolve_revision(source, head)
        ensure_ancestor(source, before, after, limits)
        yield RevisionPair(source, before, after)
    finally:
        source.objects.close()


def snapshot(tree: GitTree) -> dict[str, str]:
    """Path to mode/object identity, including skipped directories and links."""
    return dict(tree.snapshot)
