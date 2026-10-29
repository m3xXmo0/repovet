"""JSON report. Structure: docs/report.schema.json (bump SCHEMA_VERSION on changes)."""

import json

from repovet.models import CATEGORIES, CoverageItem, Finding, ScanResult, Severity
from repovet.report.common import disclaimer, no_findings, visible_findings
from repovet.report.sanitize import sanitize, sanitize_data, sanitize_path

SCHEMA_VERSION = "1.2"


def _finding(finding: Finding) -> dict[str, object]:
    loc = finding.location
    return {
        "rule_id": finding.rule_id,
        "title": sanitize(finding.title, None),
        "category": finding.category,
        "area": finding.area,
        "severity": finding.severity.label,
        "confidence": finding.confidence.label,
        "location": None
        if loc is None
        else {"path": sanitize_path(loc.path), "line": loc.line, "column": loc.column},
        "message": sanitize(finding.message, None),
        "evidence": sanitize(finding.evidence) if finding.evidence else None,
        "rationale": sanitize(finding.rationale, None),
        "recommendation": sanitize(finding.recommendation, None),
        "references": [sanitize(r, None) for r in finding.references],
    }


def _coverage(item: CoverageItem) -> dict[str, object]:
    return {
        "scope": sanitize(item.scope, None),
        "status": item.status.value,
        "reason": sanitize(item.reason, None),
        "count": item.count,
        "sample": [sanitize_path(p) for p in item.sample],
    }


def build(result: ScanResult, min_severity: Severity = Severity.INFO) -> dict[str, object]:
    visible = visible_findings(result, min_severity)
    by_severity = {s.label: sum(1 for f in visible if f.severity == s) for s in reversed(Severity)}
    by_category = {c: sum(1 for f in visible if f.category == c) for c in CATEGORIES}
    text = (
        " ".join(disclaimer(result.rules_loaded)) if visible else no_findings(result.rules_loaded)
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "repovet", "version": result.tool_version},
        "target": sanitize_path(result.target),
        "scan": {
            "mode": result.mode,
            "online": result.online,
            "started": result.started.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "duration_s": round(result.duration_s, 3),
            "files_scanned": result.files_scanned,
            "rules_loaded": result.rules_loaded,
            "min_severity": min_severity.label,
        },
        "summary": {
            "findings": len(visible),
            "hidden_below_min_severity": len(result.findings) - len(visible),
            "by_severity": by_severity,
            "by_category": by_category,
        },
        "findings": [_finding(f) for f in visible],
        "coverage": [_coverage(c) for c in result.coverage],
        "facts": sanitize_data(result.facts),
        "disclaimer": text,
    }


def render(result: ScanResult, *, min_severity: Severity = Severity.INFO) -> str:
    """JSON text; ASCII only (``ensure_ascii``), so no raw character survives."""
    return json.dumps(build(result, min_severity), ensure_ascii=True, indent=2) + "\n"
