"""Text, JSON and SARIF views of the same coverage-aware finding comparison."""

import json
from collections import defaultdict
from typing import Any

from repovet.comparison import DiffStatus, FindingChange, diff_exit_code
from repovet.differencing import ComparedScan
from repovet.models import Severity
from repovet.report import json_out, sarif
from repovet.report.sanitize import sanitize, sanitize_path

DISCLAIMER = (
    "A green diff means no new or worsened finding met the selected threshold "
    "within what the rules could check. Existing findings remain; diff does not "
    "replace a full scan. Fingerprints identify results and are not tamper evidence."
)


def _visible(change: FindingChange, minimum: Severity) -> bool:
    finding = change.after or change.before
    return finding is not None and finding.severity >= minimum


def build(compared: ComparedScan, minimum: Severity, fail_on: Severity) -> dict[str, object]:
    changes = compared.comparison.changes
    summary = {status.value: 0 for status in DiffStatus}
    for change in changes:
        finding = change.after or change.before
        if finding is not None and finding.in_chain is None:
            summary[change.status.value] += 1
    return {
        "schema_version": "1.0",
        "tool": {"name": "repovet", "version": compared.head.result.tool_version},
        "ruleset_digest": compared.head.result.ruleset_digest,
        "base": {"commit": compared.base.commit, "report": json_out.build(compared.base.result)},
        "head": {"commit": compared.head.commit, "report": json_out.build(compared.head.result)},
        "min_severity": minimum.label,
        "hidden_below_min_severity": sum(not _visible(change, minimum) for change in changes),
        "fail_on": fail_on.label,
        "exit_code": diff_exit_code(compared.comparison, fail_on),
        "summary": summary,
        "changes": [
            {
                "status": change.status.value,
                "worsened": change.worsened,
                "before": None if change.before is None else json_out._finding(change.before),
                "after": None if change.after is None else json_out._finding(change.after),
            }
            for change in changes
            if _visible(change, minimum)
        ],
        "issues": [
            {
                "paths": [sanitize_path(path) for path in issue.paths],
                "reason": sanitize(issue.reason, None),
                "blocking": issue.blocking,
            }
            for issue in compared.comparison.issues
        ],
        "warnings": [sanitize(warning, None) for warning in compared.warnings],
        "disclaimer": DISCLAIMER,
    }


def _text(compared: ComparedScan, minimum: Severity, fail_on: Severity) -> str:
    data: Any = build(compared, minimum, fail_on)
    code = data["exit_code"]
    action = (
        "Complete the missing checks before using this comparison as a gate."
        if code == 3
        else "Review the new or worsened findings before accepting this change."
        if code == 1
        else f"Review existing findings; no new or worsened finding met --fail-on {fail_on.label}."
    )
    lines = [
        f"Action: {action}",
        "",
        f"repovet diff {compared.head.result.tool_version}",
        f"Base {compared.base.commit} -> Head {compared.head.commit}",
        "Findings: " + ", ".join(f"{value} {key}" for key, value in data["summary"].items()),
    ]
    groups: dict[tuple[str, str, bool], list[FindingChange]] = defaultdict(list)
    for change in compared.comparison.changes:
        finding = change.after or change.before
        if _visible(change, minimum) and finding is not None and finding.in_chain is None:
            groups[(change.status.value, finding.rule_id, change.worsened)].append(change)
    for (status, rule, worsened), members in sorted(groups.items()):
        first = members[0].after or members[0].before
        if first is None:
            continue
        label = "worsened" if worsened else status
        title = sanitize(first.title, None)
        lines.extend(
            [
                "",
                f"{label.upper()}  {first.severity.label.upper()}  {rule}  {title}",
            ]
        )
        if first.severity is Severity.INFO:
            lines.append(f"  {len(members)} place(s)")
            continue
        for change in members[:5]:
            finding = change.after or change.before
            if finding is None:
                continue
            location = finding.location
            where = "repository" if location is None else sanitize_path(location.path)
            if location is not None and location.line is not None:
                where += f":{location.line}"
            lines.append(f"  {where}: {sanitize(finding.message, None)}")
        if len(members) > 5:
            lines.append(f"  +{len(members) - 5} more")
    for issue in compared.comparison.issues:
        paths = ", ".join(sanitize_path(path) for path in issue.paths)
        label = "Not comparable" if issue.blocking else "Not checked"
        lines.append(f"{label}: {sanitize(issue.reason, None)}" + (f" ({paths})" if paths else ""))
    lines.extend(f"Warning: {sanitize(warning, None)}" for warning in compared.warnings)
    lines.extend(["", DISCLAIMER])
    return "\n".join(lines) + "\n"


def _sarif(compared: ComparedScan, minimum: Severity, fail_on: Severity) -> str:
    rules = sorted(compared.rules.active(), key=lambda rule: rule.id)
    data: Any = sarif.build(compared.head.result, rules, minimum)
    run = data["runs"][0]
    index = {rule.id: position for position, rule in enumerate(rules)}
    results = []
    for change in compared.comparison.changes:
        finding = change.after or change.before
        if finding is None or not _visible(change, minimum):
            continue
        result: dict[str, Any] = sarif._result(finding, index)
        if change.status in {
            DiffStatus.NEW,
            DiffStatus.UNCHANGED,
            DiffStatus.UPDATED,
            DiffStatus.ABSENT,
        }:
            result["baselineState"] = change.status.value
        result["properties"]["comparisonStatus"] = change.status.value
        result["properties"]["worsened"] = change.worsened
        results.append(result)
    run["results"] = results
    run["invocations"][0]["executionSuccessful"] = not compared.comparison.incomplete
    notices = run["invocations"][0]["toolExecutionNotifications"]
    notices.extend(
        {
            "level": "error" if issue.blocking else "warning",
            "message": {"text": sanitize(issue.reason, None)},
        }
        for issue in compared.comparison.issues
    )
    notices.extend(
        {"level": "warning", "message": {"text": sanitize(warning, None)}}
        for warning in compared.warnings
    )
    run["properties"]["comparison"] = {
        "base": compared.base.commit,
        "head": compared.head.commit,
        "failOn": fail_on.label,
        "exitCode": diff_exit_code(compared.comparison, fail_on),
        "disclaimer": DISCLAIMER,
    }
    return json.dumps(data, ensure_ascii=True, indent=2) + "\n"


def render(fmt: str, compared: ComparedScan, minimum: Severity, fail_on: Severity) -> str:
    if fmt == "text":
        return _text(compared, minimum, fail_on)
    if fmt == "sarif":
        return _sarif(compared, minimum, fail_on)
    if fmt == "json":
        return json.dumps(build(compared, minimum, fail_on), ensure_ascii=True, indent=2) + "\n"
    raise ValueError("unknown diff report format")
