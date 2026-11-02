"""scripts/check_dist.py on small hand-made distributions: size limits and the
measurement data that must stay out of the sdist."""

import io
import tarfile
import zipfile
from pathlib import Path

import check_dist
import pytest

PACKAGE = {"repovet/__init__.py"}


def _wheel(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as wheel:
        wheel.writestr("repovet/__init__.py", "")
        wheel.writestr("repovet-1.dist-info/entry_points.txt", check_dist.SCRIPT_ENTRY)
        wheel.writestr("repovet-1.dist-info/licenses/LICENSE", "MIT")
        wheel.writestr("repovet-1.dist-info/METADATA", f"License-Expression: {check_dist.LICENSE}")


def _sdist(path: Path, names: list[str]) -> None:
    with tarfile.open(path, "w:gz") as sdist:
        for name in names:
            info = tarfile.TarInfo(f"repovet-1/{name}")
            info.size = 1
            sdist.addfile(info, io.BytesIO(b"x"))


@pytest.fixture
def dist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(check_dist, "package_files", lambda: PACKAGE)
    monkeypatch.setattr(check_dist, "SDIST_REQUIRED", {"README.md"})
    _wheel(tmp_path / "repovet-1-py3-none-any.whl")
    _sdist(tmp_path / "repovet-1.tar.gz", ["src/repovet/__init__.py", "README.md"])
    return tmp_path


def test_limits() -> None:
    assert check_dist.MAX_WHEEL_BYTES == 1024 * 1024
    assert check_dist.MAX_SDIST_BYTES == 2560 * 1024


def test_size_up_to_the_limit_passes(tmp_path: Path) -> None:
    path = tmp_path / "repovet-1.tar.gz"
    path.write_bytes(b"x" * 10)
    assert check_dist.check_size(path, 10, "sdist") == []
    assert check_dist.check_size(path, 9, "sdist") == [
        "sdist: repovet-1.tar.gz is 10 bytes, more than the limit of 9"
    ]


def test_small_distributions_pass(dist: Path) -> None:
    assert check_dist.main(["check_dist.py", str(dist)]) == 0


@pytest.mark.parametrize(
    ("limit", "kind"), [("MAX_WHEEL_BYTES", "wheel"), ("MAX_SDIST_BYTES", "sdist")]
)
def test_too_large_distribution_fails(
    dist: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    limit: str,
    kind: str,
) -> None:
    monkeypatch.setattr(check_dist, limit, 1)
    assert check_dist.main(["check_dist.py", str(dist)]) == 1
    assert f"{kind}: repovet-1" in capsys.readouterr().err


def test_measurement_data_in_the_sdist_fails(
    dist: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    names = ["src/repovet/__init__.py", "README.md", *sorted(check_dist.SDIST_EXCLUDED)]
    _sdist(dist / "repovet-1.tar.gz", names)
    assert check_dist.main(["check_dist.py", str(dist)]) == 1
    err = capsys.readouterr().err
    for name in check_dist.SDIST_EXCLUDED:
        assert f"sdist: must not contain {name}" in err
