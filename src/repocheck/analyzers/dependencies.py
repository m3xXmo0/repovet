"""Area ``dependencies``: lookalike names, foreign sources and package indexes."""

from repocheck.engine.context import ScanContext
from repocheck.engine.runner import run_rules
from repocheck.models import AreaResult

AREA = "dependencies"


def analyze(ctx: ScanContext) -> AreaResult:
    return AreaResult(AREA, run_rules(ctx.rules.active(AREA), ctx))
