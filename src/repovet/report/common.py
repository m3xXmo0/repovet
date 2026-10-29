"""What all report formats share: order of findings, filtering, grouping, fixed wording."""

from collections.abc import Sequence
from dataclasses import dataclass

from repovet.models import Finding, ScanResult, Severity

# Findings of these levels get their explanation (Why/Do) in the compact reports by
# default; --details shows it for all.
EXPLAINED = Severity.HIGH
TOP_GROUPS = 3


def disclaimer(rules: int) -> list[str]:
    return [
        f"repovet reports only what its {rules} rules detect in the checked scope.",
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


@dataclass
class Group:
    """Findings of one rule with the same message: one explanation, several places."""

    findings: list[Finding]

    @property
    def first(self) -> Finding:
        return self.findings[0]

    @property
    def explained(self) -> bool:
        return self.first.severity >= EXPLAINED


def group_findings(findings: Sequence[Finding]) -> list[Group]:
    """Group findings with the same rule, message, severity and confidence, in the order
    of their first occurrence (``findings`` should be in report order)."""
    groups: dict[tuple[str, str, int, int], Group] = {}
    for finding in findings:
        key = (finding.rule_id, finding.message, finding.severity, finding.confidence)
        if key in groups:
            groups[key].findings.append(finding)
        else:
            groups[key] = Group([finding])
    return list(groups.values())


def top_groups(groups: Sequence[Group], count: int = TOP_GROUPS) -> list[Group]:
    """The groups to look at first: the most severe above info; at the same level,
    findings outside tests, docs, examples and vendored code first, then by confidence."""
    ranked = [g for g in groups if g.first.severity > Severity.INFO]
    ranked.sort(
        key=lambda g: (
            -g.first.severity,
            all(f.context is not None for f in g.findings),
            -g.first.confidence,
            sort_key(g.first),
        )
    )
    return ranked[:count]


def severity_counts(findings: Sequence[Finding]) -> list[tuple[Severity, int]]:
    """(level, count) for every level, most severe first."""
    return [(s, sum(1 for f in findings if f.severity == s)) for s in reversed(Severity)]
