"""Area ``obfuscation``: code that hides what it does (encoded blobs, packers, invisible text)."""

from repocheck.engine.context import ScanContext
from repocheck.engine.runner import run_rules
from repocheck.models import AreaResult

AREA = "obfuscation"


def analyze(ctx: ScanContext) -> AreaResult:
    return AreaResult(AREA, run_rules(ctx.rules.active(AREA), ctx))
