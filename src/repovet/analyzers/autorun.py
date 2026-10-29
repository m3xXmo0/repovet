"""Area ``autorun``: code that tools run automatically (install, build, IDE, Git, shell)."""

from repovet.engine.context import ScanContext
from repovet.engine.runner import record_unsupported, run_rules
from repovet.models import AreaResult

AREA = "autorun"


def analyze(ctx: ScanContext) -> AreaResult:
    findings = run_rules(ctx.rules.active(AREA), ctx)
    # Auto-run surfaces that repovet recognizes but does not analyze (_unsupported.yaml).
    record_unsupported(ctx)
    return AreaResult(AREA, findings)
