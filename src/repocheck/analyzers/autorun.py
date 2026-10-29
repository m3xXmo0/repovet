"""Area ``autorun``: code that tools run automatically (install, build, IDE, Git, shell)."""

from repocheck.engine.context import ScanContext
from repocheck.engine.runner import record_unsupported, run_rules
from repocheck.models import AreaResult

AREA = "autorun"


def analyze(ctx: ScanContext) -> AreaResult:
    findings = run_rules(ctx.rules.active(AREA), ctx)
    # Auto-run surfaces that repocheck recognizes but does not analyze (_unsupported.yaml).
    record_unsupported(ctx)
    return AreaResult(AREA, findings)
