"""Check type ``blob``: long encoded runs (Base64, hex) and very long lines.

Encoded runs are decoded in memory only (``base64``, ``bytes.fromhex``, bounded
``zlib``); nothing decoded is ever run. Data URIs and runs that decode to images, fonts
or documents are skipped by default, because embedding media is normal.
"""

import base64
import binascii
import math
import re
import zlib
from collections import Counter
from collections.abc import Iterator

from repocheck.engine.checks.base import BuildEnv, Check, CheckError, FileView, Match, Params

ENCODINGS = ("base64", "hex", "none")
DECOMPRESS_LIMIT = 64 * 1024
PREVIEW_LENGTH = 200
_PRINTABLE_RATIO = 0.9
_DATA_URI = re.compile(r"base64,[ \t]*\Z|data:[\w/+.-]*,\Z", re.IGNORECASE)
HEADER_LENGTH = 2048
MIN_RUN = 32
_MEMO_KEY = "blob:runs"
# One pass finds every candidate; hex digits are part of the Base64 alphabet, so a hex
# run is a Base64-alphabet run made only of hex digits.
_RUNS = re.compile(rf"[A-Za-z0-9+/]{{{MIN_RUN},}}={{0,2}}")
_HEX_RUN = re.compile(r"[0-9A-Fa-f]+")
_HEX_ESCAPES = re.compile(r"(?:\\[xX][0-9A-Fa-f]{2}){2,}")

# Decoded content that is media, fonts or documents, not code.
MEDIA_MAGIC = (
    b"\x89PNG",
    b"\xff\xd8\xff",
    b"GIF8",
    b"BM",
    b"\x00\x00\x01\x00",
    b"%PDF",
    b"wOFF",
    b"wOF2",
    b"\x00\x01\x00\x00",
    b"OTTO",
    b"ID3",
    b"OggS",
    b"fLaC",
    b"\x1aE\xdf\xa3",
    b"<svg",
    b"<?xml",
)


def entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in Counter(text).values())


def is_media(data: bytes) -> bool:
    if data.startswith(MEDIA_MAGIC):
        return True
    # RIFF containers (WebP, WAV, AVI) and ISO media (MP4, MOV, HEIC, AVIF).
    return (data[:4] == b"RIFF" and len(data) >= 12) or data[4:8] == b"ftyp"


def decompress(data: bytes) -> bytes | None:
    """Inflate gzip or zlib data, at most DECOMPRESS_LIMIT bytes (no zip bombs)."""
    if data.startswith(b"\x1f\x8b"):
        wbits = 16 + zlib.MAX_WBITS
    elif len(data) > 2 and data[0] == 0x78 and (data[0] << 8 | data[1]) % 31 == 0:
        wbits = zlib.MAX_WBITS
    else:
        return None
    try:
        return zlib.decompressobj(wbits).decompress(data, DECOMPRESS_LIMIT)
    except zlib.error:
        return None


def as_text(data: bytes) -> str | None:
    """Decoded bytes as text if they are mostly printable, else ``None``."""
    text = data.decode("utf-8", errors="replace")
    sample = text[:4096]
    if not sample:
        return None
    printable = sum(1 for c in sample if c.isprintable() or c in "\n\r\t")
    return text if printable / len(sample) >= _PRINTABLE_RATIO else None


def decode_run(run: str, encoding: str) -> bytes | None:
    try:
        if encoding == "base64":
            core = run.rstrip("=")
            if len(core) % 4 == 1:
                return None
            return base64.b64decode(core + "=" * (-len(core) % 4))
        if run.startswith(("\\x", "\\X")):
            return bytes.fromhex(run.replace("\\x", "").replace("\\X", ""))
        return bytes.fromhex(run if len(run) % 2 == 0 else run[:-1])
    except (binascii.Error, ValueError):
        return None


class BlobCheck(Check):
    def __init__(
        self,
        encodings: list[str],
        min_length: int,
        min_entropy: float,
        decoded_regex: re.Pattern[str] | None,
        not_decoded_regex: re.Pattern[str] | None,
        skip_media: bool,
        skip_header: re.Pattern[str] | None = None,
    ) -> None:
        self.encodings = encodings
        self.min_length = min_length
        self.min_entropy = min_entropy
        self.decoded_regex = decoded_regex
        self.not_decoded_regex = not_decoded_regex
        self.skip_media = skip_media
        self.skip_header = skip_header

    def matches(self, view: FileView) -> Iterator[Match]:
        text = view.text()
        if text is None:
            return
        if self.skip_header is not None and self.skip_header.search(text[:HEADER_LENGTH]):
            return
        if "none" in self.encodings:
            yield from self._long_lines(view)
            return
        for start, run in candidate_runs(view, text):
            if len(run) < self.min_length:
                continue
            for encoding in ("base64", "hex"):
                if encoding not in self.encodings:
                    continue
                if encoding == "hex" and _HEX_RUN.fullmatch(run) is None:
                    continue
                match = self._inspect(view, text, start, run, encoding)
                if match is not None:
                    yield match
                    break
        if "hex" in self.encodings and ("\\x" in text or "\\X" in text):
            escapes = max(1, self.min_length // 4)
            for found in _HEX_ESCAPES.finditer(text):
                if len(found.group(0)) // 4 >= escapes:
                    match = self._inspect(view, text, found.start(), found.group(0), "hex")
                    if match is not None:
                        yield match

    def _long_lines(self, view: FileView) -> Iterator[Match]:
        for number, line in enumerate(view.lines(), start=1):
            if len(line) < self.min_length:
                continue
            if self.min_entropy and entropy(line) < self.min_entropy:
                continue
            yield Match(number, 1, line, {"match": line[:60], "count": f"{len(line):,}"})

    def _inspect(
        self, view: FileView, text: str, start: int, run: str, encoding: str
    ) -> Match | None:
        if _DATA_URI.search(text, max(0, start - 80), start):
            return None
        if self.min_entropy and entropy(run) < self.min_entropy:
            return None
        data = decode_run(run, encoding)
        if data is None:
            return None
        if self.skip_media and is_media(data):
            return None
        inflated = decompress(data)
        decoded = as_text(inflated if inflated is not None else data)
        if self.decoded_regex is not None and (
            decoded is None or not self.decoded_regex.search(decoded)
        ):
            return None
        if (
            self.not_decoded_regex is not None
            and decoded is not None
            and self.not_decoded_regex.search(decoded)
        ):
            return None
        line, column = view.position(start)
        preview = " ".join(decoded[:PREVIEW_LENGTH].split()) if decoded else "binary data"
        if inflated is not None:
            preview = f"(compressed) {preview}"
        values = {"match": run[:60], "decoded": preview, "count": f"{len(run):,}"}
        return Match(line, column, view.line_text(line), values)

    def regexes(self) -> list[re.Pattern[str]]:
        extra = [
            r
            for r in (self.decoded_regex, self.not_decoded_regex, self.skip_header)
            if r is not None
        ]
        return [_RUNS, _HEX_RUN, _HEX_ESCAPES, *extra]


def candidate_runs(view: FileView, text: str) -> list[tuple[int, str]]:
    """Runs of Base64 alphabet characters (hex digits included) of at least
    MIN_RUN characters, found once per file and shared by all blob rules."""
    cached = view.memo.get(_MEMO_KEY)
    if not isinstance(cached, list):
        cached = [(m.start(), m.group(0)) for m in _RUNS.finditer(text)]
        view.memo[_MEMO_KEY] = cached
    return cached


def build(params: Params, env: BuildEnv) -> Check:
    encodings = params.get_str_list("encoding", required=True)
    for name in encodings:
        if name not in ENCODINGS:
            raise CheckError(f"unknown encoding {name!r} ({', '.join(ENCODINGS)})")
    if "none" in encodings and len(encodings) > 1:
        raise CheckError("encoding 'none' (long lines) cannot be combined with others")
    min_length = params.get_int("min_length", default=0, minimum=MIN_RUN)
    if not min_length:
        raise CheckError("'min_length' is required")
    min_entropy = params.get_float("min_entropy", default=0.0, maximum=8.0)
    decoded = params.get_str("decoded_regex")
    not_decoded = params.get_str("not_decoded_regex")
    skip_media = params.get_bool("skip_media", default=True)
    skip_header = params.get_str("skip_header_regex")
    params.done()
    if "none" in encodings and (decoded or not_decoded):
        raise CheckError("'decoded_regex' needs an encoding")
    return BlobCheck(
        encodings,
        min_length,
        min_entropy,
        env.compile(decoded) if decoded else None,
        env.compile(not_decoded) if not_decoded else None,
        skip_media,
        env.compile(skip_header) if skip_header else None,
    )
