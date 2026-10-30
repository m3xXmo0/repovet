"""What all report formats share: order of findings, filtering, grouping, fixed wording."""

from collections.abc import Sequence
from dataclasses import dataclass

from repovet.models import Finding, ScanResult, Severity, counted

# Findings of these levels get their explanation (Why/Do) in the compact reports by
# default; --details shows it for all.
EXPLAINED = Severity.HIGH
TOP_GROUPS = 3
# What to do first, by the kind of the most severe findings. Keys are rule tags or
# "area:<name>"; the first two actions that match are shown, in this order.
ACTIONS: tuple[tuple[frozenset[str], str], ...] = (
    (frozenset({"vscode"}), "do not open this folder in VS Code with trust (use Restricted Mode)"),
    (frozenset({"devcontainer"}), "do not reopen it in a dev container"),
    (frozenset({"git"}), "do not run Git commands in it"),
    (
        frozenset({"install", "npm", "pnpm", "yarn", "python", "composer", "ruby"}),
        "do not install its dependencies or run its install scripts",
    ),
    (frozenset({"build", "msbuild", "gradle", "rust"}), "do not build it"),
    (frozenset({"ci", "github-actions"}), "do not use its workflows or releases"),
    (frozenset({"area:agents"}), "do not let an AI coding agent work in it"),
    (frozenset({"area:download_exec", "area:obfuscation"}), "do not run its scripts or code"),
    (frozenset({"area:binaries"}), "do not open or run the files it ships"),
    (frozenset({"area:dependencies"}), "do not install its dependencies"),
)
# Only when no action above matches.
GENERIC_ACTION = (frozenset({"area:autorun"}), "do not open, install or build it")
_ACTIONS_SHOWN = 2


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


def action_line(findings: Sequence[Finding]) -> str | None:
    """One sentence on what not to do yet, from the most severe danger findings (medium
    or above); ``None`` if there are none. Never says that anything is safe."""
    relevant = [f for f in counted(findings) if f.category == "danger"]
    relevant = [f for f in relevant if f.severity >= Severity.MEDIUM]
    if not relevant:
        return None
    worst = max(f.severity for f in relevant)
    keys: set[str] = set()
    for finding in relevant:
        if finding.severity != worst:
            continue
        keys |= {*finding.tags, f"area:{finding.area}"}
        if finding.chain is not None:
            # A chain stands for its parts: the entry point and the code it reaches.
            for part in findings:
                if part.in_chain == finding.chain.id:
                    keys |= {*part.tags, f"area:{part.area}"}
    actions = [text for tags, text in ACTIONS if tags & keys][:_ACTIONS_SHOWN]
    if not actions and GENERIC_ACTION[0] & keys:
        actions = [GENERIC_ACTION[1]]
    if not actions:
        return None
    text = "; ".join(actions)
    return f"{text[0].upper()}{text[1:]} until you have read the findings below."


def visible_findings(result: ScanResult, min_severity: Severity) -> list[Finding]:
    """Findings at or above ``min_severity`` in report order."""
    return sorted((f for f in result.findings if f.severity >= min_severity), key=sort_key)


@dataclass
class Group:
    """Findings of one rule with the same severity and confidence: one explanation,
    several places."""

    findings: list[Finding]

    @property
    def first(self) -> Finding:
        return self.findings[0]

    @property
    def explained(self) -> bool:
        return self.first.severity >= EXPLAINED

    @property
    def headline(self) -> str:
        """The message if all places share it, else the rule's title."""
        messages = {f.message for f in self.findings}
        return self.first.message if len(messages) == 1 else self.first.title

    @property
    def only_chain_parts(self) -> bool:
        return all(f.in_chain is not None for f in self.findings)


def group_findings(findings: Sequence[Finding]) -> list[Group]:
    """Group findings with the same rule, severity and confidence, in the order of their
    first occurrence (``findings`` should be in report order). Every chain finding is a
    group of its own (each has its own path)."""
    groups: dict[tuple[str, int, int, int], Group] = {}
    for finding in findings:
        own = id(finding) if finding.chain is not None else 0
        key = (finding.rule_id, finding.severity, finding.confidence, own)
        if key in groups:
            groups[key].findings.append(finding)
        else:
            groups[key] = Group([finding])
    return list(groups.values())


def top_groups(groups: Sequence[Group], count: int = TOP_GROUPS) -> list[Group]:
    """The groups to look at first: the most severe above info; at the same level,
    findings outside tests, docs, examples and vendored code first, then by confidence."""
    ranked = [g for g in groups if g.first.severity > Severity.INFO and not g.only_chain_parts]
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
    """(level, count) for every level, most severe first. Parts of a chain are not
    counted again; their chain finding counts for them."""
    tally = counted(findings)
    return [(s, sum(1 for f in tally if f.severity == s)) for s in reversed(Severity)]
