"""Validate saved report data without executing or trusting repository content."""

import math
import re
from datetime import datetime
from typing import Any
from urllib.parse import unquote_to_bytes

from repovet.models import (
    AREAS,
    CATEGORIES,
    Chain,
    Confidence,
    CoverageItem,
    CoverageStatus,
    Finding,
    Location,
    ScanResult,
    Severity,
)
from repovet.report.sanitize import sanitize_path, sanitize_uri

_FINGERPRINT = re.compile(r"repovet:v1:[a-f0-9]{64}")
_DIGEST = re.compile(r"[a-f0-9]{64}")
_RULE = re.compile(r"RC-[A-Z]+-[0-9]{3}")
_ENTRY = re.compile(r"[0-7]{1,11}:[a-f0-9]{40}")


def _object(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError("expected a JSON object")
    return value


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("expected a string")
    return value


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 200_000:
        raise ValueError("expected a bounded list of strings")
    return tuple(_string(item) for item in value)


def _number(value: object, *, positive: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < int(positive):
        raise ValueError("expected a nonnegative integer")
    return value


def _path_from_uri(value: object) -> str:
    uri = _string(value)
    path = unquote_to_bytes(uri).decode("utf-8", "surrogateescape")
    if sanitize_uri(path) != uri:
        raise ValueError("expected a lossless canonical repository URI")
    return path


def _path(data: dict[str, Any]) -> str:
    if "uri" in data:
        return _path_from_uri(data["uri"])
    # Compact records from internal callers may use an already lossless plain path.
    path = _string(data.get("path"))
    if sanitize_path(path) != path or "<U+" in path or "\u2026" in path:
        raise ValueError("a lossless repository URI is required for this path")
    return path


def _location(value: object) -> Location:
    data = _object(value)
    line, column = data.get("line"), data.get("column")
    return Location(
        _path(data),
        None if line is None else _number(line, positive=True),
        None if column is None else _number(column, positive=True),
    )


def finding_from_data(value: object) -> Finding:
    """A stored fingerprint is required; identities are never inferred from counts."""
    data = _object(value)
    fingerprint = _string(data.get("fingerprint"))
    rule = _string(data.get("rule_id"))
    area, category = _string(data.get("area")), _string(data.get("category"))
    if not _FINGERPRINT.fullmatch(fingerprint) or not _RULE.fullmatch(rule):
        raise ValueError("invalid or missing finding fingerprint/rule id; regenerate the report")
    if area not in AREAS or category not in CATEGORIES:
        raise ValueError("unknown finding area or category")
    context = data.get("context")
    if context not in (None, "test", "docs", "example", "vendored"):
        raise ValueError("unknown finding context")
    chain = None
    raw_chain = data.get("chain")
    if raw_chain is not None:
        raw_chain = _object(raw_chain)
        steps = raw_chain.get("steps")
        if not isinstance(steps, list) or not 2 <= len(steps) <= 100:
            raise ValueError("invalid chain steps")
        chain = Chain(_string(raw_chain.get("id")), tuple(_location(step) for step in steps))
    evidence, in_chain = data.get("evidence"), data.get("in_chain")
    location = data.get("location")
    return Finding(
        rule_id=rule,
        title=_string(data.get("title")),
        category=category,
        area=area,
        severity=Severity.parse(_string(data.get("severity"))),
        confidence=Confidence.parse(_string(data.get("confidence"))),
        location=None if location is None else _location(location),
        message=_string(data.get("message")),
        evidence=None if evidence is None else _string(evidence),
        rationale=_string(data.get("rationale")),
        recommendation=_string(data.get("recommendation")),
        references=_strings(data.get("references")),
        context=context,
        chain=chain,
        in_chain=None if in_chain is None else _string(in_chain),
        fingerprint=fingerprint,
    )


def coverage_from_data(value: object) -> CoverageItem:
    item = _object(value)
    return CoverageItem(
        _string(item.get("scope")),
        CoverageStatus(_string(item.get("status"))),
        _string(item.get("reason")),
        _number(item.get("count")),
        _strings(item.get("sample")),
        tuple(_path_from_uri(uri) for uri in _strings(item.get("uris"))),
    )


def snapshot_from_data(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    snapshot = {_path_from_uri(key): _string(val) for key, val in _object(value).items()}
    if len(snapshot) > 200_000:
        raise ValueError("snapshot is too large")
    if not snapshot or any(not _ENTRY.fullmatch(entry) for entry in snapshot.values()):
        raise ValueError("invalid Git snapshot entry")
    if not snapshot.get(".", "").startswith("40000:"):
        raise ValueError("Git snapshot has no root tree")
    return snapshot


def scan_from_data(value: object) -> ScanResult:
    """Read an unfiltered schema 1.5 report suitable for machine comparison."""
    data = _object(value)
    if data.get("schema_version") != "1.5":
        raise ValueError("a schema 1.5 report with fingerprints is required; regenerate it")
    tool, scan = _object(data.get("tool")), _object(data.get("scan"))
    if tool.get("name") != "repovet":
        raise ValueError("saved report is not a repovet report")
    if scan.get("min_severity") != "info":
        raise ValueError("a filtered report cannot be used as a baseline")
    digest = _string(data.get("ruleset_digest"))
    if not _DIGEST.fullmatch(digest):
        raise ValueError("invalid or missing ruleset digest")
    raw_findings, raw_coverage = data.get("findings"), data.get("coverage")
    if not isinstance(raw_findings, list) or len(raw_findings) > 1_000_000:
        raise ValueError("invalid findings list")
    if not isinstance(raw_coverage, list) or len(raw_coverage) > 200_000:
        raise ValueError("invalid coverage list")
    coverage = [coverage_from_data(item) for item in raw_coverage]
    snapshot = snapshot_from_data(scan.get("snapshot"))
    duration = scan.get("duration_s")
    if (
        isinstance(duration, bool)
        or not isinstance(duration, (int, float))
        or not math.isfinite(duration)
        or duration < 0
    ):
        raise ValueError("invalid scan duration")
    online = scan.get("online")
    if not isinstance(online, bool) or online:
        raise ValueError("invalid online flag")
    return ScanResult(
        target=_string(data.get("target")),
        mode=_string(scan.get("mode")),
        online=online,
        tool_version=_string(tool.get("version")),
        rules_loaded=_number(scan.get("rules_loaded")),
        files_scanned=_number(scan.get("files_scanned")),
        started=datetime.fromisoformat(_string(scan.get("started")).replace("Z", "+00:00")),
        duration_s=float(duration),
        findings=[finding_from_data(item) for item in raw_findings],
        coverage=coverage,
        facts=_object(data.get("facts")),
        ruleset_digest=digest,
        snapshot=snapshot,
    )
