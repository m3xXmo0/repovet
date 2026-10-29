"""Read-only walker for a local folder.

Links (symlinks, junctions, other reparse points) are listed but never entered or read.
Inside ``.git`` only ``config``, ``hooks/*`` and ``info/attributes`` are visible.
Environment folders (``.venv``, ``node_modules``, ...) are skipped unless the limits say
otherwise; they are reported as not checked.
"""

import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path

from repovet.limits import ENV_DIR_NAMES, Limits
from repovet.models import CoverageCollector, CoverageStatus
from repovet.sources.tree import LinkEntry, LinkKind

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_BINARY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOCTTY", 0)
)

REASON_LINK = "Symlinks, junctions and reparse points are not followed"
REASON_GITFILE = "'.git' is a file that points to a repository elsewhere; not followed"
REASON_SPECIAL = "Special files (devices, pipes, sockets) are not read"
REASON_UNREADABLE_DIR = "Folders that could not be read"
REASON_UNREADABLE = "Entries that could not be read"
REASON_ENV_DIR = (
    "Environment and tool cache folders (.venv, venv, node_modules, .tox, .nox, "
    ".mypy_cache, .ruff_cache, .pytest_cache) skipped; use --include-env-dirs to check them"
)


# Git opens its folder as ".git". On case-insensitive file systems (default on Windows
# and macOS) any spelling such as ".GIT" is that folder; on Linux only ".git" is, and a
# ".GIT" folder is ordinary content that must be checked like any other.
_GIT_NAME_ANY_CASE = sys.platform in ("win32", "darwin")


def is_git_name(name: str) -> bool:
    return name.casefold() == ".git" if _GIT_NAME_ANY_CASE else name == ".git"


class FileChangedError(OSError):
    pass


class LocalFile:
    __slots__ = ("_abs", "_ident", "path", "size")

    def __init__(self, abs_path: str, path: str, st: os.stat_result) -> None:
        self._abs = abs_path
        self._ident = (st.st_dev, st.st_ino)
        self.path = path
        self.size = st.st_size

    def read_bytes(self, limit: int) -> bytes:
        fd = os.open(self._abs, _OPEN_FLAGS)
        try:
            st = os.fstat(fd)
            # The file must still be the regular file seen while walking (no swap for a
            # link, pipe or other file in between).
            if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != self._ident:
                raise FileChangedError(f"file changed during the scan: {self.path}")
            chunks: list[bytes] = []
            remaining = limit
            # Ask for the known size plus one byte (to notice growth); avoids allocating
            # a large buffer for every small file.
            expected = st.st_size + 1
            while remaining > 0:
                wanted = min(remaining, expected, 1 << 20)
                expected = 1 << 20
                chunk = os.read(fd, wanted)
                chunks.append(chunk)
                remaining -= len(chunk)
                # A short read on a regular file means end of file; this saves a second
                # read call per file.
                if len(chunk) < wanted:
                    break
            return b"".join(chunks)
        finally:
            os.close(fd)


def _is_link(abs_path: str, st: os.stat_result) -> LinkKind | None:
    if stat.S_ISLNK(st.st_mode):
        return LinkKind.SYMLINK
    if os.path.isjunction(abs_path):
        return LinkKind.JUNCTION
    if getattr(st, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
        return LinkKind.REPARSE_POINT
    return None


def _read_link(abs_path: str) -> str | None:
    try:
        return os.readlink(abs_path)
    except (OSError, ValueError):
        return None


class LocalTree:
    """Snapshot of a local folder, taken once when the object is created."""

    def __init__(self, root: Path, limits: Limits, coverage: CoverageCollector) -> None:
        self.root = root
        self.label = str(root)
        self._limits = limits
        self._coverage = coverage
        self._files: list[LocalFile] = []
        self._links: list[LinkEntry] = []
        self._full = False
        self._walk()

    def files(self) -> Sequence[LocalFile]:
        return self._files

    def links(self) -> Sequence[LinkEntry]:
        return self._links

    # --- walking --------------------------------------------------------------

    def _skip(self, status: CoverageStatus, reason: str, path: str | None = None) -> None:
        self._coverage.add("file", status, reason, path)

    def _add_file(self, abs_path: str, rel: str, st: os.stat_result) -> None:
        if len(self._files) >= self._limits.max_files:
            if not self._full:
                self._full = True
                self._skip(
                    CoverageStatus.PARTIAL,
                    f"Scan stopped after {self._limits.max_files:,} files; "
                    "the remaining files were not checked",
                )
            return
        self._files.append(LocalFile(abs_path, rel, st))

    def _lstat(self, abs_path: str, rel: str) -> os.stat_result | None:
        try:
            return os.lstat(abs_path)
        except OSError:
            self._skip(CoverageStatus.FAILED, REASON_UNREADABLE, rel)
            return None

    def _classify(self, abs_path: str, rel: str, st: os.stat_result) -> str:
        """Return 'dir', 'file' or 'skip' and record links and special files."""
        kind = _is_link(abs_path, st)
        if kind is not None:
            self._links.append(LinkEntry(rel, kind, _read_link(abs_path)))
            self._skip(CoverageStatus.SKIPPED, REASON_LINK, rel)
            return "skip"
        if stat.S_ISDIR(st.st_mode):
            return "dir"
        if stat.S_ISREG(st.st_mode):
            return "file"
        self._skip(CoverageStatus.SKIPPED, REASON_SPECIAL, rel)
        return "skip"

    def _list_dir(self, abs_dir: str, rel_dir: str) -> list[str]:
        try:
            with os.scandir(abs_dir) as it:
                return sorted(entry.name for entry in it)
        except OSError:
            self._skip(CoverageStatus.FAILED, REASON_UNREADABLE_DIR, rel_dir or ".")
            return []

    def _walk(self) -> None:
        stack: list[tuple[str, str, int]] = [(str(self.root), "", 0)]
        while stack and not self._full:
            abs_dir, rel_dir, depth = stack.pop()
            subdirs: list[tuple[str, str, int]] = []
            for name in self._list_dir(abs_dir, rel_dir):
                abs_path = os.path.join(abs_dir, name)
                rel = f"{rel_dir}/{name}" if rel_dir else name
                st = self._lstat(abs_path, rel)
                if st is None:
                    continue
                kind = self._classify(abs_path, rel, st)
                if kind == "dir":
                    if is_git_name(name):
                        self._walk_git_dir(abs_path, rel)
                    elif self._limits.skip_env_dirs and name.casefold() in ENV_DIR_NAMES:
                        self._skip(CoverageStatus.SKIPPED, REASON_ENV_DIR, rel)
                    elif depth + 1 > self._limits.max_depth:
                        self._skip(
                            CoverageStatus.SKIPPED,
                            f"Folders nested deeper than {self._limits.max_depth} levels",
                            rel,
                        )
                    else:
                        subdirs.append((abs_path, rel, depth + 1))
                elif kind == "file":
                    if is_git_name(name):
                        self._skip(CoverageStatus.SKIPPED, REASON_GITFILE, rel)
                    self._add_file(abs_path, rel, st)
            # Reverse so the stack yields folders in name order (deterministic output).
            stack.extend(reversed(subdirs))

    def _walk_git_dir(self, abs_git: str, rel_git: str) -> None:
        self._git_file(abs_git, rel_git, ("config",))
        self._git_file(abs_git, rel_git, ("info", "attributes"))
        hooks_abs = os.path.join(abs_git, "hooks")
        hooks_rel = f"{rel_git}/hooks"
        st = self._lstat_quiet(hooks_abs)
        if st is None or self._classify(hooks_abs, hooks_rel, st) != "dir":
            return
        for name in self._list_dir(hooks_abs, hooks_rel):
            abs_path = os.path.join(hooks_abs, name)
            rel = f"{hooks_rel}/{name}"
            hook_st = self._lstat(abs_path, rel)
            if hook_st is not None and self._classify(abs_path, rel, hook_st) == "file":
                self._add_file(abs_path, rel, hook_st)

    def _git_file(self, abs_git: str, rel_git: str, parts: tuple[str, ...]) -> None:
        abs_path, rel = abs_git, rel_git
        for index, part in enumerate(parts):
            abs_path = os.path.join(abs_path, part)
            rel = f"{rel}/{part}"
            st = self._lstat_quiet(abs_path)
            if st is None:
                return
            kind = self._classify(abs_path, rel, st)
            last = index == len(parts) - 1
            if kind != ("file" if last else "dir"):
                return
            if last:
                self._add_file(abs_path, rel, st)

    @staticmethod
    def _lstat_quiet(abs_path: str) -> os.stat_result | None:
        try:
            return os.lstat(abs_path)
        except OSError:
            return None
