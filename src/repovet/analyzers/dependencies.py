"""Area ``dependencies``: lookalike names, foreign sources and package indexes."""

from repovet.engine.context import ScanContext
from repovet.engine.runner import run_rules
from repovet.models import AreaResult

AREA = "dependencies"


def analyze(ctx: ScanContext) -> AreaResult:
    return AreaResult(AREA, run_rules(ctx.rules.active(AREA), ctx))
