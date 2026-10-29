"""Area ``agents``: instructions and configuration for AI coding agents."""

from repovet.engine.context import ScanContext
from repovet.engine.runner import run_rules
from repovet.models import AreaResult

AREA = "agents"


def analyze(ctx: ScanContext) -> AreaResult:
    return AreaResult(AREA, run_rules(ctx.rules.active(AREA), ctx))
