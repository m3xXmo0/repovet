"""Area ``download_exec``: code that downloads something and runs it."""

from repovet.engine.context import ScanContext
from repovet.engine.runner import run_rules
from repovet.models import AreaResult

AREA = "download_exec"


def analyze(ctx: ScanContext) -> AreaResult:
    return AreaResult(AREA, run_rules(ctx.rules.active(AREA), ctx))
