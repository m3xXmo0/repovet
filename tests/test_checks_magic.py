import gzip

import pytest

from helpers import run_check
from repovet.engine.checks.base import CheckError
from repovet.engine.checks.magic import SIGNATURES
from repovet.limits import Limits

PE = b"MZ" + b"\x00" * 58 + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + b"\x00" * 8


def names(data: bytes) -> list[str]:
    return [n for n, sig in SIGNATURES.items() if sig.test(data)]


def test_signatures() -> None:
    assert names(PE) == ["pe"]
    assert names(b"MZ" + b"\x00" * 100) == []
    assert names(b"\x7fELF\x02") == ["elf"]
    assert names(b"\xca\xfe\xba\xbe\x00\x00\x00\x02") == ["macho"]
    assert names(b"\xca\xfe\xba\xbe\x00\x00\x00\x34") == ["java_class"]
    assert names(gzip.compress(b"x")) == ["gzip"]
    assert names(b"x" * 257 + b"ustar\x0000") == ["tar"]
    assert names(b"PK\x03\x04\x14\x00\x01\x00") == ["zip", "zip_encrypted"]
    assert names(b"PK\x03\x04\x14\x00\x00\x00" + b"xl/vbaProject.bin") == ["zip", "ooxml_macro"]


def test_check_reports_first_matching_signature() -> None:
    spec = {"type": "magic", "signatures": ["pe", "elf"]}
    (match,) = run_check(spec, "x.png", PE)
    assert match.values == {"match": "Windows executable (PE)", "value": "pe"}
    assert run_check(spec, "x.txt", b"") == []
    assert run_check(spec, "x.txt", "plain text") == []


def test_macro_search_reads_the_whole_file_up_to_the_limit() -> None:
    data = b"PK\x03\x04" + b"\x00" * 10_000 + b"word/vbaProject.bin"
    spec = {"type": "magic", "signatures": ["ooxml_macro"]}
    assert len(run_check(spec, "a.docm", data)) == 1
    assert run_check(spec, "a.docm", data, limits=Limits(max_file_size=5_000)) == []


def test_unknown_signature() -> None:
    with pytest.raises(CheckError, match="unknown signature"):
        run_check({"type": "magic", "signatures": ["exe"]}, "a", b"")
