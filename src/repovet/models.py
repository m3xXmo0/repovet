"""Data model shared by sources, engine, analyzers and report."""

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Self


class _Level(enum.IntEnum):
    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Self:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            choices = ", ".join(level.label for level in cls)
            raise ValueError(f"unknown {cls.__name__.lower()} {value!r} ({choices})") from None


class Severity(_Level):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Confidence(_Level):
    LOW = 0
    MEDIUM = 1
    HIGH = 2


class CoverageStatus(enum.StrEnum):
    NOT_IMPLEMENTED = "not_implemented"
    SKIPPED = "skipped"
    FAILED = "failed"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"


CATEGORIES = ("danger", "trust", "provenance")


@dataclass(frozen=True)
class AreaInfo:
    name: str
    prefix: str
    category: str
    milestone: int
    label: str


AREAS: dict[str, AreaInfo] = {
    info.name: info
    for info in (
        AreaInfo("autorun", "AUTO", "danger", 1, "auto-run code"),
        AreaInfo("agents", "AGENT", "danger", 1, "AI agent instructions and configuration"),
        AreaInfo("obfuscation", "OBF", "danger", 2, "obfuscated code"),
        AreaInfo("download_exec", "DLX", "danger", 2, "download-and-execute"),
        AreaInfo("binaries", "BIN", "danger", 2, "binaries, archives, file-system tricks"),
        AreaInfo("dependencies", "DEP", "danger", 2, "suspicious dependencies"),
        AreaInfo("provenance", "PROV", "provenance", 3, "languages, structure, history"),
        AreaInfo("trust", "TRUST", "trust", 4, "trust signals from the GitHub API"),
    )
}


@dataclass(frozen=True)
class Location:
    path: str
    line: int | None = None
    column: int | None = None


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    category: str
    area: str
    severity: Severity
    confidence: Confidence
    location: Location | None
    message: str
    evidence: str | None
    rationale: str
    recommendation: str
    references: tuple[str, ...] = ()
    # Where the file sits when that usually means it does not run: vendored, test,
    # example or docs. A label only; the finding is reported all the same.
    context: str | None = None


@dataclass(frozen=True)
class CoverageItem:
    scope: str
    status: CoverageStatus
    reason: str
    count: int
    sample: tuple[str, ...] = ()


@dataclass
class AreaResult:
    area: str
    findings: list[Finding] = field(default_factory=list)
    coverage: list[CoverageItem] = field(default_factory=list)
    facts: dict[str, object] = field(default_factory=dict)
    # (label, text) lines for the terminal profile; the data itself is in ``facts``.
    summary: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    mode: str
    online: bool
    tool_version: str
    rules_loaded: int
    files_scanned: int
    started: datetime
    duration_s: float
    findings: list[Finding]
    coverage: list[CoverageItem]
    facts: dict[str, object] = field(default_factory=dict)
    # Base URI for relative paths in SARIF (a URL target's GitHub blob URL).
    root_uri: str | None = None
    # Terminal profile per category (e.g. provenance): (label, text) lines.
    summaries: dict[str, list[tuple[str, str]]] = field(default_factory=dict)


_STATUS_ORDER = {status: index for index, status in enumerate(CoverageStatus)}
_SAMPLE_SIZE = 5


class CoverageCollector:
    """Collects what could not be checked. Entries with the same scope, status and
    reason are merged; paths are counted once even if several areas report them."""

    def __init__(self) -> None:
        self._paths: dict[tuple[str, CoverageStatus, str], set[str]] = {}
        self._counts: dict[tuple[str, CoverageStatus, str], int] = {}

    def add(
        self,
        scope: str,
        status: CoverageStatus,
        reason: str,
        path: str | None = None,
        count: int = 1,
    ) -> None:
        key = (scope, status, reason)
        if path is None:
            self._counts[key] = self._counts.get(key, 0) + count
        else:
            self._paths.setdefault(key, set()).add(path)

    def items(self) -> list[CoverageItem]:
        keys = set(self._paths) | set(self._counts)
        result = []
        for key in sorted(keys, key=lambda k: (_STATUS_ORDER[k[1]], k[0], k[2])):
            paths = sorted(self._paths.get(key, ()))
            count = len(paths) + self._counts.get(key, 0)
            result.append(CoverageItem(key[0], key[1], key[2], count, tuple(paths[:_SAMPLE_SIZE])))
        return result
