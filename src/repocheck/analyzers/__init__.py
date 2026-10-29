"""Analyzers, one module per area. Contract: ``analyze(ctx) -> AreaResult``."""

from collections.abc import Callable

from repocheck.analyzers import (
    agents,
    autorun,
    binaries,
    dependencies,
    download_exec,
    obfuscation,
    provenance,
    trust,
)
from repocheck.engine.context import ScanContext
from repocheck.engine.runner import prepare_file_rules, run_rules
from repocheck.models import AREAS, AreaResult, CoverageStatus

type Analyzer = Callable[[ScanContext], AreaResult]

ANALYZERS: dict[str, Analyzer] = {
    autorun.AREA: autorun.analyze,
    agents.AREA: agents.analyze,
    obfuscation.AREA: obfuscation.analyze,
    download_exec.AREA: download_exec.analyze,
    binaries.AREA: binaries.analyze,
    dependencies.AREA: dependencies.analyze,
    provenance.AREA: provenance.analyze,
    trust.AREA: trust.analyze,
}


def run_all(ctx: ScanContext) -> list[AreaResult]:
    """Run every implemented area; record the others as not implemented.

    Rules from ``--rules`` folders for an area without its own module still run
    through the engine.
    """
    results: list[AreaResult] = []
    # One pass over the files for the file rules of every area and the profile.
    prepare_file_rules(ctx.rules.active(), ctx, [provenance.start_observing(ctx)])
    for name, info in AREAS.items():
        analyzer = ANALYZERS.get(name)
        if analyzer is not None:
            result = analyzer(ctx)
            ctx.facts.update(result.facts)
            results.append(result)
            continue
        ctx.coverage.add(
            f"area:{name}",
            CoverageStatus.NOT_IMPLEMENTED,
            f"{name} ({info.label}): not implemented yet (milestone {info.milestone})",
        )
        if ctx.rules.active(name):
            results.append(AreaResult(name, run_rules(ctx.rules.active(name), ctx)))
    return results
