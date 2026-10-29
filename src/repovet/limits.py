"""Default limits that keep a scan bounded in size and time."""

import re
from dataclasses import dataclass

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB


@dataclass(frozen=True)
class Limits:
    max_file_size: int = 2 * MIB
    max_files: int = 50_000
    max_depth: int = 64
    max_line_length: int = 20_000
    max_matches_per_file: int = 5
    max_scan_seconds: float = 600.0
    max_commits: int = 100_000
    yaml_max_nodes: int = 200_000
    yaml_max_aliases: int = 1_000
    evidence_length: int = 160
    value_length: int = 120
    skip_env_dirs: bool = True


# Folders with installed third-party code, tool environments or tool caches. They are
# usually not part of the repository and can be very large; skipped unless
# --include-env-dirs is given. (__pycache__ stays in: committed .pyc files matter.)
ENV_DIR_NAMES = frozenset(
    {".venv", "venv", "node_modules", ".tox", ".nox", ".mypy_cache", ".ruff_cache", ".pytest_cache"}
)


DEFAULT_LIMITS = Limits()

_SIZE = re.compile(r"(\d+(?:\.\d+)?)\s*(b|k|kb|kib|m|mb|mib|g|gb|gib)?", re.IGNORECASE)
_UNITS = {"": 1, "b": 1, "k": KIB, "m": MIB, "g": GIB}


def parse_size(text: str) -> int:
    """Parse sizes like ``2MB``, ``512k`` or ``1048576`` (binary units)."""
    match = _SIZE.fullmatch(text.strip())
    if not match:
        raise ValueError(f"invalid size {text!r} (examples: 2MB, 512KB, 1048576)")
    unit = (match.group(2) or "").lower()[:1]
    value = int(float(match.group(1)) * _UNITS[unit])
    if value <= 0:
        raise ValueError(f"size must be greater than zero: {text!r}")
    return value


def format_size(size: int) -> str:
    for unit, factor in (("GB", GIB), ("MB", MIB), ("KB", KIB)):
        if size >= factor:
            value = size / factor
            return f"{value:.0f} {unit}" if value == int(value) else f"{value:.1f} {unit}"
    return f"{size} bytes"
