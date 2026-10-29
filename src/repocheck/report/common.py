"""What all report formats share: order of findings, filtering, fixed wording."""

from repocheck.models import Finding, ScanResult, Severity


def disclaimer(rules: int) -> list[str]:
    return [
        f"repocheck reports only what its {rules} rules detect in the checked scope.",
        "A missing finding is not proof that the repository is safe.",
    ]


def no_findings(rules: int) -> str:
    return (
        f"No findings from {rules} rules in the checked scope. This is not a guarantee "
        "that the repository is safe - see 'Not checked'."
    )


def sort_key(finding: Finding) -> tuple[int, str, int, str]:
    loc = finding.location
    return (
        -finding.severity,
        loc.path if loc else "",
        (loc.line or 0) if loc else 0,
        finding.rule_id,
    )


def visible_findings(result: ScanResult, min_severity: Severity) -> list[Finding]:
    """Findings at or above ``min_severity`` in report order."""
    return sorted((f for f in result.findings if f.severity >= min_severity), key=sort_key)
