"""SARIF 2.1.0 report for code-scanning tools (GitHub code scanning, VS Code SARIF viewer).

Mapping: rules from the YAML rules, ``level`` from the severity,
``properties.security-severity`` for GitHub, coverage gaps as tool execution
notifications. Paths are relative to ``SRCROOT``.
"""

import json
import re
from collections.abc import Sequence
from datetime import timedelta
from pathlib import PurePosixPath, PureWindowsPath

from repovet.engine.loader import Rule
from repovet.models import Confidence, CoverageItem, CoverageStatus, Finding, ScanResult, Severity
from repovet.report.common import disclaimer, no_findings, visible_findings
from repovet.report.sanitize import sanitize, sanitize_data, sanitize_path, sanitize_uri

SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
ROOT_ID = "SRCROOT"

LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub code scanning: >= 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, < 4.0 low.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}
PRECISION = {Confidence.HIGH: "high", Confidence.MEDIUM: "medium", Confidence.LOW: "low"}
_GAPS = {CoverageStatus.FAILED, CoverageStatus.PARTIAL}
_WINDOWS_PATH = re.compile(r"[A-Za-z]:[\\/]|\\\\")


def _rule(rule: Rule) -> dict[str, object]:
    entry: dict[str, object] = {
        "id": rule.id,
        "shortDescription": {"text": sanitize(rule.title, None)},
        "fullDescription": {"text": sanitize(rule.rationale, None)},
        "help": {"text": sanitize(rule.recommendation, None)},
        "defaultConfiguration": {"level": LEVELS[rule.severity]},
        "properties": {
            "tags": list(
                dict.fromkeys(["security", rule.area, *(sanitize(t, None) for t in rule.tags)])
            ),
            "precision": PRECISION[rule.confidence],
            "security-severity": SECURITY_SEVERITY[rule.severity],
            "severity": rule.severity.label,
            "confidence": rule.confidence.label,
            "category": rule.category,
        },
    }
    if rule.references:
        entry["helpUri"] = sanitize(rule.references[0], None)
    return entry


def _result(finding: Finding, index: dict[str, int]) -> dict[str, object]:
    properties: dict[str, object] = {
        "severity": finding.severity.label,
        "confidence": finding.confidence.label,
        "category": finding.category,
        "area": finding.area,
    }
    if finding.context is not None:
        properties["context"] = finding.context
    result: dict[str, object] = {
        "ruleId": finding.rule_id,
        "level": LEVELS[finding.severity],
        "message": {"text": sanitize(finding.message, None)},
        "properties": properties,
    }
    if finding.rule_id in index:
        result["ruleIndex"] = index[finding.rule_id]
    loc = finding.location
    if loc is not None:
        # GitHub code scanning needs a start line; file-level findings point to line 1.
        region: dict[str, object] = {"startLine": loc.line or 1}
        if loc.line and loc.column:
            region["startColumn"] = loc.column
        if loc.line and finding.evidence:
            region["snippet"] = {"text": sanitize(finding.evidence)}
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": sanitize_uri(loc.path), "uriBaseId": ROOT_ID},
                    "region": region,
                }
            }
        ]
        if not loc.line:
            properties["fileLevel"] = True
    return result


def _notification(item: CoverageItem) -> dict[str, object]:
    count = f" ({item.count})" if item.count > 1 else ""
    return {
        "level": "warning" if item.status in _GAPS else "note",
        "message": {"text": f"{sanitize(item.reason, None)}{count}"},
        "descriptor": {"id": sanitize(item.scope, None)},
        "properties": {
            "status": item.status.value,
            "count": item.count,
            "sample": [sanitize_path(p) for p in item.sample],
        },
    }


def root_uri(target: str) -> str | None:
    """``file:`` URI of an absolute local folder, ending with '/'; ``None`` otherwise."""
    if _WINDOWS_PATH.match(target):
        path: PurePosixPath | PureWindowsPath = PureWindowsPath(target)
    elif target.startswith("/"):
        path = PurePosixPath(target)
    else:
        return None
    uri = path.as_uri()
    return uri if uri.endswith("/") else uri + "/"


def build(
    result: ScanResult, rules: Sequence[Rule], min_severity: Severity = Severity.INFO
) -> dict[str, object]:
    visible = visible_findings(result, min_severity)
    ordered = sorted(rules, key=lambda r: r.id)
    index = {rule.id: i for i, rule in enumerate(ordered)}
    started = result.started
    ended = started + timedelta(seconds=result.duration_s)
    text = (
        " ".join(disclaimer(result.rules_loaded)) if visible else no_findings(result.rules_loaded)
    )
    run: dict[str, object] = {
        "tool": {
            "driver": {
                "name": "repovet",
                "version": result.tool_version,
                "semanticVersion": result.tool_version,
                "rules": [_rule(r) for r in ordered],
            }
        },
        "invocations": [
            {
                "executionSuccessful": True,
                "startTimeUtc": started.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "endTimeUtc": ended.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "toolExecutionNotifications": [_notification(c) for c in result.coverage],
            }
        ],
        "columnKind": "unicodeCodePoints",
        "results": [_result(f, index) for f in visible],
        "properties": {
            "target": sanitize_path(result.target),
            "mode": result.mode,
            "online": result.online,
            "filesScanned": result.files_scanned,
            "rulesLoaded": result.rules_loaded,
            "minSeverity": min_severity.label,
            "hiddenBelowMinSeverity": len(result.findings) - len(visible),
            "facts": sanitize_data(result.facts),
            "disclaimer": text,
        },
    }
    uri = result.root_uri or root_uri(result.target)
    if uri is not None:
        run["originalUriBaseIds"] = {ROOT_ID: {"uri": uri}}
    return {"$schema": SCHEMA_URI, "version": "2.1.0", "runs": [run]}


def render(
    result: ScanResult, rules: Sequence[Rule], *, min_severity: Severity = Severity.INFO
) -> str:
    """SARIF text; ASCII only (``ensure_ascii``)."""
    return json.dumps(build(result, rules, min_severity), ensure_ascii=True, indent=2) + "\n"
