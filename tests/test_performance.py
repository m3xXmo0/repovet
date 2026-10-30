"""Performance: a generated repository with 10,000 files is checked in under 15 seconds.
Only the scan is timed, not the generation of the files.

The first scan of freshly written files is not timed: on Windows, Defender scans every
new file when it is first opened, which costs more than the scan itself (measured up to
16 s). That run still has to finish with correct results; the second run measures
repovet's own work, which is what the limit is about (measured 1.4 s)."""

import time
from pathlib import Path

import pytest

from repovet.cli import EXIT_FINDINGS, main

FILES = 10_000
LIMIT_SECONDS = 15.0

_PY = "import os\n\n\ndef handler(event):\n    return os.path.join('a', str(event))\n" * 20
_JS = "export function add(a, b) {\n  return a + b; // simple\n}\n" * 30
_MD = "# Title\n\nSome documentation with a [link](https://example.invalid).\n" * 15
_JSON = '{"name": "pkg", "version": "1.0.0", "scripts": {"build": "tsc", "test": "vitest"}}\n'


def generate(root: Path) -> None:
    kinds = [
        ("py", _PY.encode()),
        ("js", _JS.encode()),
        ("md", _MD.encode()),
        ("json", _JSON.encode()),
        ("bin", bytes(range(256)) * 8),
    ]
    for index in range(FILES - 6):
        folder = root / f"pkg{index % 50:02d}" / f"mod{index % 7}"
        folder.mkdir(parents=True, exist_ok=True)
        ext, data = kinds[index % len(kinds)]
        (folder / f"file{index}.{ext}").write_bytes(data)
    specials = {
        "package.json": '{"scripts": {"postinstall": "node setup.js"}}',
        "CLAUDE.md": "# Notes\nRun the tests.\n<!-- maintainers: keep this short -->\n",
        ".vscode/tasks.json": '{"tasks": [{"label": "w", "command": "node setup.js",'
        ' "runOptions": {"runOn": "folderOpen"}}]}',
        "setup.py": "from setuptools import setup\nsetup(name='demo')\n",
        ".mcp.json": '{"mcpServers": {"x": {"command": "node", "args": ["server.js"]}}}',
        "big.txt": "x" * 100_000,
    }
    for rel, text in specials.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode())


@pytest.mark.slow
def test_ten_thousand_files_in_time(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = tmp_path / "repo"
    generate(repo)
    assert main(["scan", str(repo), "--no-color"]) == EXIT_FINDINGS  # warm-up, not timed
    first = capsys.readouterr().out
    start = time.perf_counter()
    code = main(["scan", str(repo), "--no-color"])
    elapsed = time.perf_counter() - start
    out = capsys.readouterr().out
    assert code == EXIT_FINDINGS
    assert f"{FILES:,} files" in out
    assert out.splitlines()[1:] == first.splitlines()[1:]  # same report apart from the header
    assert elapsed < LIMIT_SECONDS, f"scan took {elapsed:.1f} s"
