"""Area ``obfuscation``: code that hides what it does (encoded blobs, packers, invisible text)."""

from repovet.engine.context import ScanContext
from repovet.engine.runner import run_rules
from repovet.models import AreaResult

AREA = "obfuscation"


def analyze(ctx: ScanContext) -> AreaResult:
    return AreaResult(AREA, run_rules(ctx.rules.active(AREA), ctx))
