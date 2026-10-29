"""Area ``agents``: instructions and configuration for AI coding agents."""

from repocheck.engine.context import ScanContext
from repocheck.engine.runner import run_rules
from repocheck.models import AreaResult

AREA = "agents"


def analyze(ctx: ScanContext) -> AreaResult:
    return AreaResult(AREA, run_rules(ctx.rules.active(AREA), ctx))
