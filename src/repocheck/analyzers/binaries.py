"""Area ``binaries``: executables, archives, macros and file-system tricks."""

from repocheck.engine.context import ScanContext
from repocheck.engine.runner import run_rules
from repocheck.models import AreaResult

AREA = "binaries"


def analyze(ctx: ScanContext) -> AreaResult:
    return AreaResult(AREA, run_rules(ctx.rules.active(AREA), ctx))
