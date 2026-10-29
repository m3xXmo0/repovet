"""Read-only, bounded access to a Git object store (packs and loose objects).

dulwich parses the objects. Before anything is inflated, this module reads the object
size from the pack or loose-object header, including every base of a delta chain, so a
small compressed object cannot inflate into gigabytes (decompression bomb). It never
writes. The caller vouches for the directory: repocheck's own clone, or a local
``.git/objects`` that ``gitmeta`` checked for links and alternates first.
"""

import errno
import os
import stat
import zlib
from collections.abc import Iterator
from typing import BinaryIO

from dulwich.object_store import DiskObjectStore
from dulwich.objects import Blob, Commit, ObjectID, ShaFile, Tag, Tree
from dulwich.pack import Pack

OBJECT_TYPES: dict[int, str] = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}
_OFS_DELTA = 6
_REF_DELTA = 7
_HEX = frozenset("0123456789abcdef")
_HEADER_PROBE = 64
_MAX_CHAIN = 128
_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_BINARY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOCTTY", 0)
)


def open_regular(path: str) -> BinaryIO:
    """Open ``path`` for reading if it is a regular file, without following a final
    link. O_NONBLOCK keeps a pipe that replaced the file after an earlier check from
    blocking the open on POSIX; the type is checked again on the open file."""
    fd = os.open(path, _OPEN_FLAGS)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, "rb")


# Objects up to this size are inflated completely (and the last one is cached); larger
# blobs can only be read from the start, and only when they are not stored as a delta.
FULL_READ_LIMIT = 64 * 1024 * 1024
COMMIT_LIMIT = 1024 * 1024
TREE_LIMIT = 16 * 1024 * 1024


class GitObjectError(Exception):
    """An object is missing, damaged or larger than allowed."""


def is_hex_id(text: str) -> bool:
    return len(text) == 40 and set(text) <= _HEX


def _varint(data: bytes, pos: int) -> tuple[int, int]:
    """Little-endian base-128 number (delta headers); returns (value, next position)."""
    value = shift = 0
    while True:
        if pos >= len(data) or shift > 63:
            raise GitObjectError("damaged delta header")
        byte = data[pos]
        value |= (byte & 0x7F) << shift
        shift += 7
        pos += 1
        if not byte & 0x80:
            return value, pos


class GitObjects:
    """Objects of one repository. Use as a context manager or call ``close``."""

    def __init__(self, objects_dir: str, *, full_read_limit: int = FULL_READ_LIMIT) -> None:
        self.path = objects_dir
        self.full_read_limit = full_read_limit
        self._store = DiskObjectStore(objects_dir)
        self._handles: dict[str, BinaryIO] = {}
        self._cache: tuple[bytes, int, bytes] | None = None

    def __enter__(self) -> "GitObjects":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        for handle in self._handles.values():
            handle.close()
        self._handles.clear()
        self._cache = None
        self._store.close()

    # --- sizes -----------------------------------------------------------------

    def _packs(self) -> list[Pack]:
        return list(self._store.packs)

    def _locate(self, sha: bytes) -> tuple[Pack, int] | None:
        for pack in self._packs():
            try:
                return pack, pack.index.object_offset(ObjectID(sha))
            except KeyError:
                continue
        return None

    def _pack_handle(self, pack: Pack) -> BinaryIO:
        path = os.fspath(pack.data.path)
        handle = self._handles.get(path)
        if handle is None:
            handle = open_regular(path)
            self._handles[path] = handle
        return handle

    def _pack_entry(self, pack: Pack, offset: int) -> tuple[int, int, int | bytes | None, int]:
        """(type, size, delta base, offset of the zlib data) of the entry at ``offset``.

        For deltas, ``size`` is the size of the resulting object (from the delta header).
        """
        handle = self._pack_handle(pack)
        handle.seek(offset)
        head = handle.read(_HEADER_PROBE)
        if not head:
            raise GitObjectError("object offset outside the pack")
        byte = head[0]
        type_num = (byte >> 4) & 7
        size = byte & 0x0F
        shift, pos = 4, 1
        while byte & 0x80:
            if pos >= len(head) or shift > 63:
                raise GitObjectError("damaged pack entry header")
            byte = head[pos]
            size |= (byte & 0x7F) << shift
            shift += 7
            pos += 1
        base: int | bytes | None = None
        if type_num == _OFS_DELTA:
            byte = head[pos]
            distance = byte & 0x7F
            pos += 1
            while byte & 0x80:
                if pos >= len(head):
                    raise GitObjectError("damaged delta offset")
                byte = head[pos]
                distance = ((distance + 1) << 7) | (byte & 0x7F)
                pos += 1
            if distance <= 0 or distance > offset:
                raise GitObjectError("delta base outside the pack")
            base = offset - distance
        elif type_num == _REF_DELTA:
            base = head[pos : pos + 20]
            pos += 20
            if len(base) != 20:
                raise GitObjectError("damaged delta reference")
        elif type_num not in OBJECT_TYPES:
            raise GitObjectError(f"unknown pack entry type {type_num}")
        data_offset = offset + pos
        if base is not None:
            size = self._delta_result_size(handle, data_offset)
        return type_num, size, base, data_offset

    @staticmethod
    def _delta_result_size(handle: BinaryIO, data_offset: int) -> int:
        handle.seek(data_offset)
        inflater = zlib.decompressobj()
        out = b""
        # A delta starts with two small varints (base size, result size).
        for _ in range(64):
            chunk = handle.read(256)
            if not chunk:
                break
            try:
                out += inflater.decompress(chunk, 32 - len(out))
            except zlib.error:
                raise GitObjectError("damaged delta data") from None
            if len(out) >= 20 or inflater.eof:
                break
        _, pos = _varint(out, 0)
        result, _ = _varint(out, pos)
        return result

    def _loose_path(self, hexsha: str) -> str:
        return os.path.join(self.path, hexsha[:2], hexsha[2:])

    def _loose_header(self, hexsha: str) -> tuple[str, int] | None:
        try:
            opened = open_regular(self._loose_path(hexsha))
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise GitObjectError(f"loose object not readable: {exc.strerror}") from None
        with opened as handle:
            try:
                head = zlib.decompressobj().decompress(handle.read(512), 64)
            except zlib.error:
                raise GitObjectError("damaged loose object") from None
        kind, _, rest = head.partition(b" ")
        size_text, nul, _ = rest.partition(b"\0")
        if (
            not nul
            or not size_text.isdigit()
            or kind.decode("ascii", "replace") not in {*OBJECT_TYPES.values()}
        ):
            raise GitObjectError("damaged loose object header")
        return kind.decode("ascii"), int(size_text)

    def _chain(self, sha: bytes) -> Iterator[int]:
        """Sizes of the object and of every delta base it needs."""
        hexsha = sha.decode("ascii")
        found = self._locate(sha)
        steps = 0
        while found is not None:
            pack, offset = found
            _, size, base, _ = self._pack_entry(pack, offset)
            yield size
            if base is None:
                return
            steps += 1
            if steps > _MAX_CHAIN:
                raise GitObjectError("delta chain too long")
            if isinstance(base, int):
                found = (pack, base)
                continue
            hexsha = base.hex()
            found = self._locate(hexsha.encode("ascii"))
        loose = self._loose_header(hexsha)
        if loose is None:
            raise GitObjectError(f"object {hexsha} not found")
        yield loose[1]

    def size(self, sha: bytes) -> int:
        """Size of the object itself (inflated)."""
        return next(self._chain(sha))

    def _check(self, sha: bytes, max_size: int) -> int:
        sizes = list(self._chain(sha))
        if max(sizes) > max_size:
            raise GitObjectError(
                f"object {sha.decode('ascii')} (or a delta base) is larger than {max_size:,} bytes"
            )
        return sizes[0]

    # --- reading ---------------------------------------------------------------

    def read_raw(self, sha: bytes, max_size: int) -> tuple[int, bytes]:
        """(type number, content) after checking the size of the whole delta chain."""
        if self._cache is not None and self._cache[0] == sha and len(self._cache[2]) <= max_size:
            return self._cache[1], self._cache[2]
        self._check(sha, max_size)
        try:
            type_num, data = self._store.get_raw(ObjectID(sha))
        except (KeyError, ValueError, AssertionError, zlib.error, OSError) as exc:
            raise GitObjectError(f"object {sha.decode('ascii')} not readable: {exc}") from None
        self._cache = (sha, type_num, data)
        return type_num, data

    def read_object(self, sha: bytes, max_size: int) -> ShaFile:
        type_num, data = self.read_raw(sha, max_size)
        try:
            return ShaFile.from_raw_string(type_num, data, ObjectID(sha))
        except Exception as exc:  # dulwich raises several types for malformed objects
            raise GitObjectError(f"object {sha.decode('ascii')} is damaged: {exc}") from None

    def commit(self, sha: bytes) -> Commit:
        obj = self.read_object(sha, COMMIT_LIMIT)
        if not isinstance(obj, Commit):
            raise GitObjectError(f"{sha.decode('ascii')} is not a commit")
        return obj

    def tree(self, sha: bytes) -> Tree:
        obj = self.read_object(sha, TREE_LIMIT)
        if not isinstance(obj, Tree):
            raise GitObjectError(f"{sha.decode('ascii')} is not a tree")
        return obj

    def peel(self, sha: bytes) -> bytes:
        """Follow annotated tags to the commit they point to."""
        for _ in range(16):
            obj = self.read_object(sha, COMMIT_LIMIT)
            if isinstance(obj, Commit):
                return sha
            if not isinstance(obj, Tag):
                raise GitObjectError(f"{sha.decode('ascii')} does not point to a commit")
            sha = obj.object[1]
        raise GitObjectError("too many nested tags")

    def read_prefix(self, sha: bytes, limit: int) -> bytes:
        """At most ``limit`` bytes from the start of a blob."""
        size = self.size(sha)
        if size <= self.full_read_limit:
            type_num, data = self.read_raw(sha, self.full_read_limit)
            if type_num != Blob.type_num:
                raise GitObjectError(f"{sha.decode('ascii')} is not a file")
            return data[:limit]
        return self._stream_prefix(sha, limit)

    def _stream_prefix(self, sha: bytes, limit: int) -> bytes:
        """Inflate only the start of a large blob stored whole (not as a delta)."""
        found = self._locate(sha)
        if found is not None:
            pack, offset = found
            type_num, _, base, data_offset = self._pack_entry(pack, offset)
            if base is not None or type_num != Blob.type_num:
                raise GitObjectError("large file stored as a delta; not read")
            handle = self._pack_handle(pack)
            handle.seek(data_offset)
            return _inflate_prefix(handle, limit)
        hexsha = sha.decode("ascii")
        with open_regular(self._loose_path(hexsha)) as handle:
            data = _inflate_prefix(handle, limit + 64)
        _, nul, body = data.partition(b"\0")
        if not nul:
            raise GitObjectError("damaged loose object header")
        return body[:limit]


def _inflate_prefix(handle: BinaryIO, limit: int) -> bytes:
    inflater = zlib.decompressobj()
    out: list[bytes] = []
    length = 0
    while length < limit:
        chunk = inflater.unconsumed_tail or handle.read(64 * 1024)
        if not chunk:
            break
        try:
            piece = inflater.decompress(chunk, limit - length)
        except zlib.error:
            raise GitObjectError("damaged object data") from None
        out.append(piece)
        length += len(piece)
        if inflater.eof:
            break
    return b"".join(out)
