"""ReDoS test: every rule regex runs on pathological 50,000-character inputs in time.

Each single input must finish within PER_INPUT_SECONDS (catastrophic backtracking shows
up as one exploding input, not as a slightly higher sum). Python's ``re`` cannot be
interrupted, so the regexes run in a child process that is killed if one of them hangs.
Messages go through a pipe, which sends synchronously: a multiprocessing queue sends from
a feeder thread that cannot run while a regex holds the GIL, so a hang would be blamed on
the previous regex.
"""

import multiprocessing
import re
import time
from multiprocessing.connection import Connection
from typing import Any

from helpers import builtin_rules
from repovet.analyzers import provenance

LENGTH = 50_000
PER_INPUT_SECONDS = 1.0
HANG_SECONDS = 60.0
STARTUP_SECONDS = 60.0
_BASE_CHARS = " \t\n\r\"'`/\\.-_=:;,|&<>(){}[]*+?!#$%@~^0aAzZ9\x00é\U000e0041"


def pathological_inputs(pattern: str) -> list[str]:
    chars = set(_BASE_CHARS) | {c for c in pattern if c.isprintable()}
    inputs = [c * LENGTH for c in sorted(chars)]
    inputs += [c * LENGTH + "\x00" for c in "a 0/-."]
    words = sorted(set(re.findall(r"[A-Za-z][A-Za-z0-9_-]{1,20}", pattern)))[:40]
    for word in words:
        inputs.append((word + " ") * (LENGTH // (len(word) + 1)))
        inputs.append((word + "|") * (LENGTH // (len(word) + 1)))
    inputs += ["ab" * (LENGTH // 2), "a " * (LENGTH // 2), "\\\\" * (LENGTH // 2)]
    return inputs


def collect_patterns() -> list[tuple[str, str, int]]:
    """All regexes with a label; identical (pattern, flags) pairs are tested once."""
    rules = builtin_rules()
    found: list[tuple[str, str, int]] = []
    for name, pattern in rules.patterns.items():
        found.append((f"pattern {name}", pattern, 0))
    for rule in rules.rules:
        for index, compiled in enumerate(rule.check.regexes()):
            found.append((f"{rule.id}#{index}", compiled.pattern, compiled.flags))
    for surface in rules.unsupported:
        if surface.contains is not None:
            found.append(
                (f"unsupported {surface.scope}", surface.contains.pattern, surface.contains.flags)
            )
    data = provenance.load_profile_data(rules.filesets)
    data_regexes = [("provenance generated_header", data.generated_header)]
    for marker in data.ai_markers:
        data_regexes += [
            (f"ai_marker {marker.tool}", r) for r in (marker.message, marker.author) if r
        ]
    for label, compiled in data_regexes:
        found.append((label, compiled.pattern, compiled.flags))
    unique: dict[tuple[str, int], tuple[str, str, int]] = {}
    for label, pattern, flags in found:
        unique.setdefault((pattern, flags), (label, pattern, flags))
    return list(unique.values())


def _worker(patterns: list[tuple[str, str, int]], out: Connection) -> None:
    for label, pattern, flags in patterns:
        compiled = re.compile(pattern, flags)
        out.send(("start", label))
        worst, worst_input = 0.0, ""
        for text in pathological_inputs(pattern):
            start = time.perf_counter()
            compiled.search(text)
            for _ in compiled.finditer(text):
                pass
            elapsed = time.perf_counter() - start
            if elapsed > worst:
                worst, worst_input = elapsed, text[:20]
        out.send(("done", label, worst, worst_input))
    out.send(("end",))


def test_patterns_are_collected() -> None:
    labels = [label for label, _, _ in collect_patterns()]
    assert any(label.startswith("pattern ") for label in labels)
    assert any(label.startswith("RC-") for label in labels)
    assert any(label.startswith("ai_marker ") for label in labels)


def test_rule_regexes_resist_redos() -> None:
    patterns = collect_patterns()
    ctx = multiprocessing.get_context("spawn")
    reader, writer = ctx.Pipe(duplex=False)
    process = ctx.Process(target=_worker, args=(patterns, writer), daemon=True)
    process.start()
    slow: list[tuple[str, float, str]] = []
    current = "(process start)"
    timeout = STARTUP_SECONDS
    try:
        while True:
            if not reader.poll(timeout):
                raise AssertionError(f"regex did not finish in time: {current}")
            message: Any = reader.recv()
            timeout = HANG_SECONDS
            if message[0] == "start":
                current = message[1]
            elif message[0] == "done":
                if message[2] > PER_INPUT_SECONDS:
                    slow.append((message[1], round(message[2], 3), message[3]))
            else:
                break
    finally:
        if process.is_alive():
            process.terminate()
        process.join(timeout=10)
    assert not slow, f"regexes too slow on pathological input: {slow}"
