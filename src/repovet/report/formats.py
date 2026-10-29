"""One entry point for every report format (command line and interactive mode)."""

from collections.abc import Sequence

from repovet.engine.loader import Rule
from repovet.models import ScanResult, Severity
from repovet.report import html, json_out, sarif, terminal

FORMATS = ("text", "json", "sarif", "html")
EXTENSIONS = {"text": "txt", "json": "json", "sarif": "sarif", "html": "html"}


def render(
    fmt: str,
    result: ScanResult,
    rules: Sequence[Rule],
    *,
    min_severity: Severity = Severity.INFO,
    color: bool = False,
    verbose: bool = False,
    details: bool = False,
    unicode: bool = True,
) -> str:
    """The report in ``fmt``. ``color``, ``verbose``, ``details`` and ``unicode`` only
    apply to the text report."""
    if fmt == "json":
        return json_out.render(result, min_severity=min_severity)
    if fmt == "sarif":
        return sarif.render(result, rules, min_severity=min_severity)
    if fmt == "html":
        return html.render(result, min_severity=min_severity)
    if fmt == "text":
        return terminal.render(
            result,
            color=color,
            min_severity=min_severity,
            verbose=verbose,
            details=details,
            unicode=unicode,
        )
    raise ValueError(f"unknown report format {fmt!r}")
