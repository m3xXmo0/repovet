"""Apply rules to files and turn matches into findings."""

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace

from repovet.engine.checks.base import FactCheck, FileView, Match, TreeCheck
from repovet.engine.context import ScanContext
from repovet.engine.loader import Rule
from repovet.models import CoverageStatus, Finding, Location
from repovet.report.sanitize import sanitize

_PLACEHOLDER = re.compile(r"\{([a-z]+)\}")
_EVIDENCE_KEEP = 1000


def render_message(template: str, values: dict[str, str], max_length: int) -> str:
    """Fill ``{placeholder}`` names with sanitized, shortened values."""
    return _PLACEHOLDER.sub(lambda m: sanitize(values.get(m.group(1), ""), max_length), template)


def make_finding(rule: Rule, path: str | None, match: Match, ctx: ScanContext) -> Finding:
    """A finding at ``path`` (``None``: repository-wide, e.g. from facts)."""
    values = {"path": path or "", "line": "" if match.line is None else str(match.line)}
    values.update(match.values)
    evidence = match.evidence.strip()[:_EVIDENCE_KEEP] if match.evidence else None
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        category=rule.category,
        area=rule.area,
        severity=rule.severity,
        confidence=rule.confidence,
        location=None if path is None else Location(path, match.line, match.column),
        message=render_message(rule.message, values, ctx.limits.value_length),
        evidence=evidence or None,
        rationale=rule.rationale,
        recommendation=rule.recommendation,
        references=rule.references,
    )


def _rule_findings(rule: Rule, view: FileView, ctx: ScanContext) -> list[Finding]:
    by_line: dict[int | None, Finding] = {}
    try:
        for match in rule.check.matches(view):
            if match.line not in by_line:
                by_line[match.line] = make_finding(rule, view.path, match, ctx)
    except RecursionError:
        view.note(CoverageStatus.FAILED, "Files nested too deeply to check")
    findings = sorted(by_line.values(), key=lambda f: (f.location.line or 0) if f.location else 0)
    cap = ctx.limits.max_matches_per_file
    if len(findings) > cap:
        more = len(findings) - cap
        findings = findings[:cap]
        last = findings[-1]
        findings[-1] = replace(last, message=f"{last.message} (and {more} more in this file)")
    return findings


def _tree_findings(rule: Rule, check: TreeCheck, ctx: ScanContext) -> list[Finding]:
    findings = []
    for path, match in check.tree_matches(ctx.tree):
        if rule.applies_to(path):
            findings.append(make_finding(rule, path, match, ctx))
    return findings


type FileObserver = Callable[[FileView], None]


def _file_pass(
    rules: Sequence[Rule], ctx: ScanContext, observers: Sequence[FileObserver] = ()
) -> dict[str, list[Finding]]:
    """Run file rules in one pass: each file is read once for all rules that apply and
    for the ``observers`` (which see every file, e.g. the provenance profile)."""
    per_rule: dict[str, list[Finding]] = {rule.id: [] for rule in rules}
    if not rules and not observers:
        return per_rule
    for file in ctx.tree.files():
        if ctx.out_of_time():
            break
        applicable = [r for r in rules if r.applies_to(file.path)]
        if not applicable and not observers:
            continue
        view = FileView(file, ctx.limits, ctx.coverage)
        for observe in observers:
            observe(view)
        for rule in applicable:
            if rule.check.needs_text and view.text() is None:
                continue
            per_rule[rule.id].extend(_rule_findings(rule, view, ctx))
    return per_rule


def _is_file_rule(rule: Rule) -> bool:
    return not rule.deprecated and not isinstance(rule.check, FactCheck | TreeCheck)


def prepare_file_rules(
    rules: Sequence[Rule], ctx: ScanContext, observers: Sequence[FileObserver] = ()
) -> None:
    """Run the file rules of all areas in one shared pass before the analyzers run;
    ``run_rules`` then takes their findings from ``ctx.prepared``."""
    ctx.prepared = _file_pass([r for r in rules if _is_file_rule(r)], ctx, observers)


def run_rules(
    rules: Sequence[Rule], ctx: ScanContext, facts: Mapping[str, object] | None = None
) -> list[Finding]:
    """Run ``rules``. Fact rules (``metric``) run only when ``facts`` are given."""
    findings: list[Finding] = []
    file_rules: list[Rule] = []
    for rule in rules:
        if rule.deprecated:
            continue
        if isinstance(rule.check, FactCheck):
            if facts is not None:
                findings.extend(
                    make_finding(rule, None, match, ctx) for match in rule.check.fact_matches(facts)
                )
        elif isinstance(rule.check, TreeCheck):
            findings.extend(_tree_findings(rule, rule.check, ctx))
        else:
            file_rules.append(rule)
    prepared = ctx.prepared or {}
    computed = _file_pass([r for r in file_rules if r.id not in prepared], ctx)
    for rule in file_rules:
        findings.extend(prepared[rule.id] if rule.id in prepared else computed[rule.id])
    return findings


def record_unsupported(ctx: ScanContext) -> None:
    """Coverage entries for auto-run surfaces that are detected but not analyzed."""
    surfaces = ctx.rules.unsupported
    if not surfaces:
        return
    for file in ctx.tree.files():
        if ctx.out_of_time():
            break
        view: FileView | None = None
        for surface in surfaces:
            if not surface.applies_to(file.path):
                continue
            if surface.max_size is not None and file.size > surface.max_size:
                continue
            if surface.contains is not None:
                view = view or FileView(file, ctx.limits, ctx.coverage)
                text = view.text()
                if text is None or view.has_long_lines() or not surface.contains.search(text):
                    continue
            ctx.coverage.add(surface.scope, CoverageStatus.UNSUPPORTED, surface.reason, file.path)
