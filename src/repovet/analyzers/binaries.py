"""Area ``binaries``: executables, archives, macros and file-system tricks."""

from repovet.engine.context import ScanContext
from repovet.engine.runner import run_rules
from repovet.models import AreaResult

AREA = "binaries"


def analyze(ctx: ScanContext) -> AreaResult:
    return AreaResult(AREA, run_rules(ctx.rules.active(AREA), ctx))
