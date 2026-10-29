"""File tree of one commit, read straight from the Git objects.

Nothing is checked out: file contents stay in the object store and are inflated in
memory when a rule reads them, so no repository path is ever created on disk (no
``.git`` look-alikes, NTFS streams, case collisions or symlink tricks). The same limits
and skipped folders apply as for a local folder.
"""

import stat
from collections.abc import Sequence

from repovet.limits import ENV_DIR_NAMES, Limits
from repovet.models import CoverageCollector, CoverageStatus
from repovet.sources.gitobjects import GitObjectError, GitObjects
from repovet.sources.local import REASON_ENV_DIR, REASON_LINK
from repovet.sources.tree import LinkEntry, LinkKind

REASON_SUBMODULE = "Git submodules are listed but not fetched; their content is not checked"
REASON_DOT_GIT = "Entries named '.git' inside the repository tree (Git refuses to check them out)"
REASON_BAD_NAME = "Tree entries with an empty, '.' or '..' name (damaged or crafted tree)"
REASON_BAD_OBJECT = "Git objects that are missing, damaged or too large"
REASON_MODE = "Tree entries with an unknown file mode"
_LINK_TARGET_LIMIT = 4096
_MAX_TREES = 100_000
_MODE_GITLINK = 0o160000


class GitFile:
    __slots__ = ("_objects", "_sha", "path", "size")

    def __init__(self, objects: GitObjects, sha: bytes, path: str, size: int) -> None:
        self._objects = objects
        self._sha = sha
        self.path = path
        self.size = size

    def read_bytes(self, limit: int) -> bytes:
        try:
            return self._objects.read_prefix(self._sha, limit)
        except GitObjectError as exc:
            raise OSError(str(exc)) from None


class GitTree:
    """Snapshot of the tree of ``commit``, taken once when the object is created."""

    def __init__(
        self,
        objects: GitObjects,
        commit: bytes,
        limits: Limits,
        coverage: CoverageCollector,
        label: str,
    ) -> None:
        self.objects = objects
        self.commit = commit
        self.label = label
        self._limits = limits
        self._coverage = coverage
        self._files: list[GitFile] = []
        self._links: list[LinkEntry] = []
        self._full = False
        self._walk(objects.commit(commit).tree)

    def files(self) -> Sequence[GitFile]:
        return self._files

    def links(self) -> Sequence[LinkEntry]:
        return self._links

    def _skip(self, status: CoverageStatus, reason: str, path: str | None = None) -> None:
        self._coverage.add("file", status, reason, path)

    def _add_file(self, sha: bytes, rel: str) -> None:
        if len(self._files) >= self._limits.max_files:
            if not self._full:
                self._full = True
                self._skip(
                    CoverageStatus.PARTIAL,
                    f"Scan stopped after {self._limits.max_files:,} files; "
                    "the remaining files were not checked",
                )
            return
        try:
            size = self.objects.size(sha)
        except GitObjectError:
            self._skip(CoverageStatus.FAILED, REASON_BAD_OBJECT, rel)
            return
        self._files.append(GitFile(self.objects, sha, rel, size))

    def _add_link(self, sha: bytes, rel: str) -> None:
        try:
            target: str | None = self.objects.read_prefix(sha, _LINK_TARGET_LIMIT).decode(
                "utf-8", "surrogateescape"
            )
        except GitObjectError:
            target = None
        self._links.append(LinkEntry(rel, LinkKind.SYMLINK, target))
        self._skip(CoverageStatus.SKIPPED, REASON_LINK, rel)

    def _walk(self, root: bytes) -> None:
        # Same order as the local walker: a folder's files first, then its subfolders
        # in name order.
        stack: list[tuple[bytes, str, int]] = [(root, "", 0)]
        trees = 0
        while stack and not self._full:
            tree_sha, rel_dir, depth = stack.pop()
            trees += 1
            if trees > _MAX_TREES:
                self._skip(
                    CoverageStatus.PARTIAL,
                    f"Scan stopped after {_MAX_TREES:,} folders; the rest was not checked",
                )
                return
            try:
                entries = self.objects.tree(tree_sha).items()
            except GitObjectError:
                self._skip(CoverageStatus.FAILED, REASON_BAD_OBJECT, rel_dir or ".")
                continue
            named = sorted(
                (entry.path.decode("utf-8", "surrogateescape"), entry) for entry in entries
            )
            subdirs: list[tuple[bytes, str, int]] = []
            for name, entry in named:
                rel = f"{rel_dir}/{name}" if rel_dir else name
                mode = entry.mode
                if name in ("", ".", "..") or "/" in name or "\0" in name:
                    self._skip(CoverageStatus.SKIPPED, REASON_BAD_NAME, rel)
                elif name.casefold() == ".git":
                    self._skip(CoverageStatus.SKIPPED, REASON_DOT_GIT, rel)
                elif stat.S_ISDIR(mode):
                    if self._limits.skip_env_dirs and name.casefold() in ENV_DIR_NAMES:
                        self._skip(CoverageStatus.SKIPPED, REASON_ENV_DIR, rel)
                    elif depth + 1 > self._limits.max_depth:
                        self._skip(
                            CoverageStatus.SKIPPED,
                            f"Folders nested deeper than {self._limits.max_depth} levels",
                            rel,
                        )
                    else:
                        subdirs.append((entry.sha, rel, depth + 1))
                elif mode == _MODE_GITLINK:
                    self._coverage.add(
                        "git:submodules", CoverageStatus.UNSUPPORTED, REASON_SUBMODULE, rel
                    )
                elif stat.S_ISLNK(mode):
                    self._add_link(entry.sha, rel)
                elif stat.S_ISREG(mode):
                    self._add_file(entry.sha, rel)
                else:
                    self._skip(CoverageStatus.SKIPPED, REASON_MODE, rel)
            stack.extend(reversed(subdirs))
