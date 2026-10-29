"""Working tree for ``repovet clone``, written from the Git objects that were checked.

The tree comes from the same temporary object store the scan read, so what is written
is exactly what was checked (no second download). Every path is validated before the
first byte is written; one unsafe path aborts the clone, on every platform alike:
absolute paths, ``..``, ``.git`` in any spelling (case, trailing dots or spaces,
ignorable Unicode characters, the NTFS short name ``git~1``), Windows device names,
alternate data streams and other characters Windows does not allow, trailing dots and
spaces, and paths that differ only in case or Unicode normalization.

Regular files are written; symbolic links and submodules are not created (they are
listed). No hooks, filters, LFS or submodules run or get fetched: nothing reads
``.gitattributes`` or ``.gitmodules`` here, and the ``.git`` folder holds only the pack
of the clone, refs, ``HEAD``, a fixed minimal config and an index.

Everything is written into a private staging folder next to the target and moved into
place with one rename once it is complete, so the target never holds a partial clone.
Right before the rename the target is checked again (still missing or an empty, real
folder, not a link or junction). The staging folder is removed on any error or
interruption.
"""

import contextlib
import hashlib
import os
import re
import shutil
import stat
import struct
import sys
import tempfile
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath

from repovet.sources.gitobjects import GitObjectError, GitObjects

MODE_FILE = 0o100644
MODE_EXEC = 0o100755
MODE_LINK = 0o120000
MODE_GITLINK = 0o160000
# Limits for what is written (sizes are known from the object headers before writing).
MAX_FILES = 200_000
MAX_FILE_SIZE = 512 * 1024 * 1024
MAX_TOTAL_SIZE = 4 * 1024 * 1024 * 1024
_MAX_TREES = 100_000
_MAX_DEPTH = 64
_RESERVED = re.compile(
    r"(?:con|prn|aux|nul|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3]|conin\$|conout\$)"
    r"[ ]*(?:\..*)?",
    re.IGNORECASE | re.DOTALL,
)
_WINDOWS_INVALID = frozenset('<>:"/\\|?*')
# Characters HFS+ ignores when it compares names (Git's protectHFS list) plus other
# invisible format characters.
_IGNORABLE = frozenset(
    "\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e"
    "\u206a\u206b\u206c\u206d\u206e\u206f\ufeff"
)
# Branch names written into refs and the config: no leading '-' or '.', no spaces,
# quotes or brackets.
_SAFE_BRANCH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]*(?:/[A-Za-z0-9_][A-Za-z0-9._-]*)*")
STAGING_PREFIX = ".repovet-checkout-"


class CheckoutError(Exception):
    """The working tree could not be written (the clone is aborted)."""


@dataclass(frozen=True)
class Entry:
    path: str
    mode: int
    sha: bytes
    size: int = 0


@dataclass
class Plan:
    files: list[Entry] = field(default_factory=list)
    links: list[Entry] = field(default_factory=list)
    submodules: list[Entry] = field(default_factory=list)

    @property
    def total_size(self) -> int:
        return sum(e.size for e in self.files)


@dataclass(frozen=True)
class Written:
    files: int
    bytes: int
    links: list[str]
    submodules: list[str]
    branch: str | None


def unsafe_component(name: str) -> str | None:
    """Why ``name`` must not be written as a file or folder name, or None."""
    if name in ("", ".", ".."):
        return "empty, '.' or '..' name"
    if any(ord(c) < 0x20 or c == "\x7f" for c in name):
        return "control character in the name"
    if any(c in _WINDOWS_INVALID for c in name):
        return "character not allowed on Windows (< > : \" / \\ | ? *; ':' names a data stream)"
    if name.endswith((".", " ")):
        return "name ends with a dot or a space"
    folded = "".join(c for c in name if c not in _IGNORABLE and unicodedata.category(c) != "Cf")
    folded = folded.rstrip(". ").casefold()
    if folded in (".git", "git~1"):
        return "'.git' in another spelling"
    if _RESERVED.fullmatch(name):
        return "Windows device name"
    return None


def unsafe_paths(paths: list[str]) -> list[str]:
    """Every path that must not be written, with the reason."""
    problems: list[str] = []
    seen: dict[str, str] = {}
    for path in paths:
        if (
            PurePosixPath(path).is_absolute()
            or PureWindowsPath(path).is_absolute()
            or (PureWindowsPath(path).drive)
        ):
            problems.append(f"{path}: absolute path")
            continue
        parts = path.split("/")
        reasons = [r for r in (unsafe_component(p) for p in parts) if r is not None]
        if reasons:
            problems.append(f"{path}: {reasons[0]}")
            continue
        # The path and every folder on it must be unique ignoring case and Unicode
        # normalization (Windows and macOS file systems would merge them).
        for depth in range(1, len(parts) + 1):
            prefix = "/".join(parts[:depth])
            key = unicodedata.normalize("NFC", prefix).casefold()
            other = seen.setdefault(key, prefix)
            if other != prefix:
                problems.append(f"{path}: collides with {other} (case or Unicode normalization)")
                break
    return problems


def plan(objects: GitObjects, commit: bytes) -> Plan:
    """Every entry of the commit's tree; sizes from the object headers."""
    result = Plan()
    stack: list[tuple[bytes, str, int]] = [(objects.commit(commit).tree, "", 0)]
    trees = 0
    while stack:
        tree_sha, prefix, depth = stack.pop()
        trees += 1
        if trees > _MAX_TREES or depth > _MAX_DEPTH:
            raise CheckoutError("the tree has too many or too deeply nested folders")
        for entry in objects.tree(tree_sha).items():
            name = entry.path.decode("utf-8", "surrogateescape")
            path = f"{prefix}{name}"
            mode = entry.mode
            if stat.S_ISDIR(mode):
                stack.append((entry.sha, f"{path}/", depth + 1))
            elif mode == MODE_GITLINK:
                result.submodules.append(Entry(path, mode, entry.sha))
            elif stat.S_ISLNK(mode):
                result.links.append(Entry(path, mode, entry.sha))
            elif stat.S_ISREG(mode):
                normal = MODE_EXEC if mode & 0o111 else MODE_FILE
                result.files.append(Entry(path, normal, entry.sha, objects.size(entry.sha)))
            else:
                raise CheckoutError(f"tree entry with an unknown file mode: {path}")
    if len(result.files) > MAX_FILES:
        raise CheckoutError(f"more than {MAX_FILES:,} files")
    big = [e.path for e in result.files if e.size > MAX_FILE_SIZE]
    if big:
        raise CheckoutError(f"file larger than {MAX_FILE_SIZE:,} bytes: {big[0]}")
    if result.total_size > MAX_TOTAL_SIZE:
        raise CheckoutError(f"the files add up to more than {MAX_TOTAL_SIZE:,} bytes")
    return result


def check_destination(dest: Path) -> None:
    """The target folder must not exist or must be an empty, real folder whose parent
    exists."""
    if dest.is_symlink() or (sys.platform == "win32" and _is_junction(dest)):
        raise CheckoutError(f"target is a link: {dest}")
    if dest.exists():
        if not dest.is_dir():
            raise CheckoutError(f"target exists and is not a folder: {dest}")
        if any(dest.iterdir()):
            raise CheckoutError(f"target folder is not empty: {dest}")
    elif not dest.parent.is_dir():
        raise CheckoutError(f"parent folder not found: {dest.parent}")
    reason = unsafe_component(dest.name) if dest.name else None
    if reason is not None:
        raise CheckoutError(f"target folder name not allowed ({reason}): {dest.name}")


def _is_junction(path: Path) -> bool:
    try:
        return path.is_junction()
    except OSError:
        return False


def write(
    objects: GitObjects,
    commit: bytes,
    pack_dir: Path,
    dest: Path,
    *,
    url: str,
    ref: str | None,
    progress: Callable[[int, int], None] | None = None,
) -> Written:
    """Write the working tree of ``commit`` and a minimal ``.git`` into ``dest``.
    ``ref`` is the full ref that was fetched (``refs/heads/...``) or None (detached)."""
    entries = plan(objects, commit)
    problems = unsafe_paths([e.path for e in entries.files + entries.links + entries.submodules])
    if problems:
        shown = "; ".join(problems[:10])
        more = f" (and {len(problems) - 10} more)" if len(problems) > 10 else ""
        raise CheckoutError(f"unsafe paths in the repository, nothing written: {shown}{more}")
    check_destination(dest)
    branch = _branch(ref)
    parent = dest.absolute().parent
    stage = _create_stage(parent)
    try:
        _write_tree(objects, entries, stage, progress)
        _write_git(entries, commit, pack_dir, stage, url, branch)
        _move_into_place(stage, dest)
    finally:
        if stage.exists() or stage.is_symlink():
            _remove_stage(stage, parent)
    return Written(
        files=len(entries.files),
        bytes=entries.total_size,
        links=sorted(e.path for e in entries.links),
        submodules=sorted(e.path for e in entries.submodules),
        branch=branch,
    )


def _branch(ref: str | None) -> str | None:
    if ref is None or not ref.startswith("refs/heads/"):
        return None
    name = ref.removeprefix("refs/heads/")
    if not _SAFE_BRANCH.fullmatch(name) or ".." in name or name.endswith(".lock"):
        return None
    return name


def _create_file(path: Path, data: bytes, executable: bool) -> None:
    """Create a new file; fails if anything already exists under that name."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o777 if executable else 0o666)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def _write_tree(
    objects: GitObjects,
    entries: Plan,
    dest: Path,
    progress: Callable[[int, int], None] | None,
) -> None:
    folders: set[Path] = set()
    for number, entry in enumerate(entries.files, 1):
        target = dest.joinpath(*entry.path.split("/"))
        if target.parent not in folders:
            target.parent.mkdir(parents=True, exist_ok=True)
            folders.add(target.parent)
        try:
            type_num, data = objects.read_raw(entry.sha, MAX_FILE_SIZE)
        except GitObjectError as exc:
            raise CheckoutError(f"cannot read {entry.path}: {exc}") from None
        if type_num != 3 or len(data) != entry.size:
            raise CheckoutError(f"{entry.path} is not a readable file object")
        try:
            _create_file(target, data, entry.mode == MODE_EXEC)
        except OSError as exc:
            raise CheckoutError(f"cannot write {entry.path}: {exc.strerror or exc}") from None
        if progress is not None:
            progress(number, len(entries.files))


def _config(url: str, branch: str | None) -> str:
    lines = [
        "[core]",
        "\trepositoryformatversion = 0",
        f"\tfilemode = {'false' if sys.platform == 'win32' else 'true'}",
        "\tbare = false",
        "\tlogallrefupdates = true",
    ]
    if sys.platform == "win32":
        lines += ["\tsymlinks = false", "\tignorecase = true"]
    elif sys.platform == "darwin":
        lines += ["\tignorecase = true", "\tprecomposeunicode = true"]
    lines += [
        '[remote "origin"]',
        f"\turl = {url}",
        "\tfetch = +refs/heads/*:refs/remotes/origin/*",
    ]
    if branch is not None:
        lines += [f'[branch "{branch}"]', "\tremote = origin", f"\tmerge = refs/heads/{branch}"]
    return "\n".join(lines) + "\n"


def _write_git(
    entries: Plan, commit: bytes, pack_dir: Path, dest: Path, url: str, branch: str | None
) -> None:
    git = dest / ".git"
    for folder in ("objects/pack", "objects/info", "refs/heads", "refs/tags", "info"):
        (git / folder).mkdir(parents=True)
    for pack in sorted(pack_dir.glob("pack-*")):
        if pack.suffix in (".pack", ".idx") and pack.is_file() and not pack.is_symlink():
            shutil.copyfile(pack, git / "objects" / "pack" / pack.name)
    sha = commit.decode("ascii")
    files = {"config": _config(url, branch), "description": "repovet clone\n"}
    if branch is None:
        files["HEAD"] = f"{sha}\n"
    else:
        files["HEAD"] = f"ref: refs/heads/{branch}\n"
        for ref in (f"refs/heads/{branch}", f"refs/remotes/origin/{branch}"):
            files[ref] = f"{sha}\n"
    for name, text in files.items():
        target = git.joinpath(*name.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        _create_file(target, text.encode("ascii"), executable=False)
    _create_file(git / "index", _index(entries, dest), executable=False)


def _index_entry(path: str, mode: int, sha: bytes, st: os.stat_result | None) -> bytes:
    name = path.encode("utf-8", "surrogateescape")
    if st is None:
        times = (0, 0, 0, 0)
        ids = (0, 0, 0, 0)
        size = 0
    else:
        times = (
            int(st.st_ctime) & 0xFFFFFFFF,
            st.st_ctime_ns % 1_000_000_000,
            int(st.st_mtime) & 0xFFFFFFFF,
            st.st_mtime_ns % 1_000_000_000,
        )
        ids = (st.st_dev & 0xFFFFFFFF, st.st_ino & 0xFFFFFFFF, st.st_uid, st.st_gid)
        size = st.st_size & 0xFFFFFFFF
    head = struct.pack(">10I", *times, ids[0], ids[1], mode, ids[2], ids[3], size)
    body = head + bytes.fromhex(sha.decode("ascii")) + struct.pack(">H", min(len(name), 0xFFF))
    body += name
    return body + b"\0" * (8 - len(body) % 8)


def _index(entries: Plan, dest: Path) -> bytes:
    """A Git index (version 2) for the tree. Links and submodules are listed with their
    commit values but no file data, so Git shows them as missing, not as new."""
    rows: list[tuple[bytes, bytes]] = []
    for entry in entries.files:
        st = dest.joinpath(*entry.path.split("/")).stat()
        rows.append(
            (
                entry.path.encode("utf-8", "surrogateescape"),
                _index_entry(entry.path, entry.mode, entry.sha, st),
            )
        )
    for entry in entries.links + entries.submodules:
        rows.append(
            (
                entry.path.encode("utf-8", "surrogateescape"),
                _index_entry(entry.path, entry.mode, entry.sha, None),
            )
        )
    rows.sort(key=lambda row: row[0])
    data = b"DIRC" + struct.pack(">II", 2, len(rows)) + b"".join(row[1] for row in rows)
    return data + hashlib.sha1(data, usedforsecurity=False).digest()


def _create_stage(parent: Path) -> Path:
    """A new, owner-only staging folder next to the target (same file system, so the
    final rename does not copy)."""
    try:
        return Path(tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=parent))
    except OSError as exc:
        raise CheckoutError(
            f"cannot create a staging folder in {parent}: {exc.strerror or exc}"
        ) from None


def _move_into_place(stage: Path, dest: Path) -> None:
    """Rename the complete staging folder to ``dest``, which must still be missing or an
    empty, real folder."""
    try:
        check_destination(dest)
    except CheckoutError as exc:
        raise CheckoutError(f"target changed while writing: {exc}") from None
    if sys.platform != "win32":
        # mkdtemp creates the folder for the owner only; a clone gets the usual mode.
        mask = os.umask(0)
        os.umask(mask)
        stage.chmod(0o777 & ~mask)
    try:
        if sys.platform == "win32" and dest.exists():
            # Windows does not rename onto an existing folder. rmdir refuses a folder
            # that is no longer empty, and the rename refuses anything created since.
            dest.rmdir()
            try:
                stage.rename(dest)
            except BaseException:
                if not dest.exists() and not dest.is_symlink():
                    dest.mkdir()
                raise
        else:
            # rename(2) replaces an empty folder in one step and refuses a folder that
            # is not empty, a file or a link.
            stage.rename(dest)
    except OSError as exc:
        raise CheckoutError(f"cannot move the clone into {dest}: {exc.strerror or exc}") from None


def _remove_stage(stage: Path, parent: Path) -> None:
    """Remove the staging folder this module created, and nothing else."""
    if stage.parent != parent or not stage.name.startswith(STAGING_PREFIX):
        return
    if stage.is_symlink() or (sys.platform == "win32" and _is_junction(stage)):
        return

    def make_writable(func: Callable[[str], object], name: str, _exc: BaseException) -> None:
        entry = Path(name)
        for target in (entry.parent, entry):
            if target.is_relative_to(stage) and not target.is_symlink():
                target.chmod(stat.S_IRWXU if target.is_dir() else stat.S_IREAD | stat.S_IWRITE)
        func(name)

    with contextlib.suppress(OSError):
        shutil.rmtree(stage, onexc=make_writable)
