"""Check type ``magic``: binary formats recognized by their signature.

Most formats are recognized from the first bytes. Office macros are found by stream
names (``_VBA_PROJECT`` in OLE files, ``vbaProject.bin`` in OOXML zip files), which
needs the whole file up to the size limit. Nothing is unpacked, parsed further or run.
"""

from collections.abc import Callable, Iterator
from dataclasses import dataclass

from repovet.engine.checks.base import BuildEnv, Check, CheckError, FileView, Match, Params

HEAD_SIZE = 4096
_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_ZIP = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_VBA_OLE = "_VBA_PROJECT".encode("utf-16-le")


def _pe(data: bytes) -> bool:
    if data[:2] != b"MZ" or len(data) < 0x40:
        return False
    offset = int.from_bytes(data[0x3C:0x40], "little")
    return data[offset : offset + 4] == b"PE\x00\x00"


def _macho(data: bytes) -> bool:
    if data[:4] in (
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
    ):
        return True
    # Universal binaries share 0xCAFEBABE with Java class files; a Mach-O header has a
    # small architecture count where a class file has its version number.
    return (
        data[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")
        and 0 < int.from_bytes(data[4:8], "big") < 30
    )


def _java_class(data: bytes) -> bool:
    return data[:4] == b"\xca\xfe\xba\xbe" and int.from_bytes(data[6:8], "big") >= 45


def _zip_encrypted(data: bytes) -> bool:
    return data[:4] == b"PK\x03\x04" and len(data) >= 8 and data[6] & 0x01 == 1


@dataclass(frozen=True)
class Signature:
    label: str
    test: Callable[[bytes], bool]
    whole_file: bool = False


SIGNATURES: dict[str, Signature] = {
    "pe": Signature("Windows executable (PE)", _pe),
    "elf": Signature("Linux/Unix executable (ELF)", lambda d: d[:4] == b"\x7fELF"),
    "macho": Signature("macOS executable (Mach-O)", _macho),
    "java_class": Signature("Java class file", _java_class),
    "wasm": Signature("WebAssembly module", lambda d: d[:4] == b"\x00asm"),
    "zip": Signature("ZIP archive", lambda d: d[:4] in _ZIP),
    "zip_encrypted": Signature("password-protected ZIP archive", _zip_encrypted),
    "gzip": Signature("gzip archive", lambda d: d[:3] == b"\x1f\x8b\x08"),
    "bzip2": Signature("bzip2 archive", lambda d: d[:3] == b"BZh" and d[3:4] in b"123456789"),
    "xz": Signature("xz archive", lambda d: d[:6] == b"\xfd7zXZ\x00"),
    "7z": Signature("7-Zip archive", lambda d: d[:6] == b"7z\xbc\xaf\x27\x1c"),
    "rar": Signature(
        "RAR archive", lambda d: d[:7] == b"Rar!\x1a\x07\x00" or d[:8] == b"Rar!\x1a\x07\x01\x00"
    ),
    "zstd": Signature("Zstandard archive", lambda d: d[:4] == b"\x28\xb5\x2f\xfd"),
    "tar": Signature("tar archive", lambda d: d[257:262] == b"ustar"),
    "cab": Signature("Windows cabinet archive", lambda d: d[:8] == b"MSCF\x00\x00\x00\x00"),
    "ar": Signature("ar archive (static library, .deb)", lambda d: d[:8] == b"!<arch>\n"),
    "ole_macro": Signature(
        "Office document with VBA macros (OLE)",
        lambda d: d[:8] == _OLE and _VBA_OLE in d,
        whole_file=True,
    ),
    "ooxml_macro": Signature(
        "Office document with VBA macros (OOXML)",
        lambda d: d[:4] in _ZIP and b"vbaProject.bin" in d,
        whole_file=True,
    ),
}


class MagicCheck(Check):
    needs_text = False

    def __init__(self, names: list[str]) -> None:
        self.signatures = [(name, SIGNATURES[name]) for name in names]
        self.whole_file = any(sig.whole_file for _, sig in self.signatures)

    def matches(self, view: FileView) -> Iterator[Match]:
        if view.file.size == 0:
            return
        size = view.limits.max_file_size if self.whole_file else HEAD_SIZE
        data = view.head(size)
        if data is None:
            return
        for name, signature in self.signatures:
            if signature.test(data):
                yield Match(values={"match": signature.label, "value": name})
                return


def build(params: Params, env: BuildEnv) -> Check:
    names = params.get_str_list("signatures", required=True)
    params.done()
    unknown = [name for name in names if name not in SIGNATURES]
    if unknown:
        raise CheckError(f"unknown signature(s) {', '.join(unknown)} ({', '.join(SIGNATURES)})")
    return MagicCheck(names)
