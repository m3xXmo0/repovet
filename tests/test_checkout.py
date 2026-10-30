"""repovet clone: path validation, the written working tree and the clone command.

Test repositories are built in Git objects only (tests/gitrepo.py) and served through
the local dulwich transport; hostile names never reach the disk unless the clone
writes them, which these tests check it does not.
"""

import hashlib
import io
import os
import struct
import sys
from pathlib import Path

import pytest

from gitrepo import CommitSpec, build_repo, local_transport
from repovet import cli, interactive
from repovet.cli import EXIT_ABORTED, EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main
from repovet.sources import checkout, remote
from repovet.sources.checkout import CheckoutError, unsafe_component, unsafe_paths
from repovet.sources.remote import GitHubRepo, clone

REPO = GitHubRepo("octo", "demo")
URL = "https://github.com/octo/demo"
TASKS = (
    '{"tasks": [{"label": "x", "command": "node setup.js", "runOptions": {"runOn": "folderOpen"}}]}'
)
FILES: dict[str, object] = {
    "README.md": "# Demo\n",
    "src/app.py": "print('hello')\n",
    "bin/run.sh": {"executable": "#!/bin/sh\necho hi\n"},
    "docs/link": {"symlink": "../README.md"},
    "vendor/lib": {"submodule": "a" * 40},
}

type Capture = pytest.CaptureFixture[str]


@pytest.mark.parametrize(
    "name",
    [
        ".git",
        ".GIT",
        ".git.",
        ".git ",
        ".g\u200cit",
        "\ufeff.git",
        "GIT~1",
        "aux",
        "CON.txt",
        "nul .c",
        "com1",
        "LPT\u00b9",
        "a:b",
        "file.txt:hidden",
        "x<y",
        'q"',
        "a\\b",
        "pipe|",
        "what?",
        "star*",
        "dot.",
        "space ",
        "tab\tname",
        "",
        ".",
        "..",
    ],
)
def test_unsafe_names(name: str) -> None:
    assert unsafe_component(name) is not None


@pytest.mark.parametrize(
    "name", [".github", ".gitignore", ".gitattributes", "git", "auxiliary", "con2", "a.b.c", "~1"]
)
def test_ordinary_names(name: str) -> None:
    assert unsafe_component(name) is None


def test_unsafe_paths_and_collisions() -> None:
    assert unsafe_paths(["src/a.py", "src/b.py", "README.md"]) == []
    problems = unsafe_paths(["/etc/passwd", "C:/x", "a/../b", "a/.git/hooks/post-checkout"])
    assert len(problems) == 4
    collisions = unsafe_paths(["Readme.md", "README.md"])
    assert collisions and "collides with Readme.md" in collisions[0]
    # A file and a folder that differ only in case, and NFC/NFD forms of one name.
    assert unsafe_paths(["src", "SRC/x.py"])
    assert unsafe_paths(["caf\u00e9.txt", "cafe\u0301.txt"])


def _origin(tmp_path: Path, files: dict[str, object], **kwargs: object) -> Path:
    origin = tmp_path / "origin.git"
    build_repo(origin, [CommitSpec(files)], **kwargs)  # type: ignore[arg-type]
    return origin


def _write(
    tmp_path: Path, files: dict[str, object], dest: Path, **kwargs: object
) -> checkout.Written:
    origin = _origin(tmp_path, files, **kwargs)
    with clone(REPO, transport=local_transport({"octo/demo": origin})) as cloned:
        return checkout.write(
            cloned.objects,
            cloned.commit,
            cloned.workspace / "objects" / "pack",
            dest,
            url=REPO.url,
            ref=cloned.full_ref,
        )


def test_writes_files_and_a_minimal_git_folder(tmp_path: Path) -> None:
    dest = tmp_path / "demo"
    written = _write(tmp_path, FILES, dest)
    assert written.files == 3
    assert written.links == ["docs/link"]
    assert written.submodules == ["vendor/lib"]
    assert written.branch == "main"
    assert (dest / "README.md").read_bytes() == b"# Demo\n"
    assert (dest / "src" / "app.py").is_file()
    assert not (dest / "docs" / "link").exists()
    assert not (dest / "vendor").exists()
    if sys.platform != "win32":
        assert (dest / "bin" / "run.sh").stat().st_mode & 0o100
        assert not (dest / "README.md").stat().st_mode & 0o100
        # Not the owner-only mode of the staging folder.
        mask = os.umask(0)
        os.umask(mask)
        assert dest.stat().st_mode & 0o777 == 0o777 & ~mask
    git = dest / ".git"
    assert (git / "HEAD").read_text(encoding="ascii") == "ref: refs/heads/main\n"
    assert not (git / "hooks").exists()
    config = (git / "config").read_text(encoding="ascii")
    assert f"url = {URL}" in config and '[branch "main"]' in config
    for key in ("fsmonitor", "hookspath", "filter", "sshcommand", "pager", "editor", "alias"):
        assert key not in config.lower()
    sha = (git / "refs" / "heads" / "main").read_text(encoding="ascii").strip()
    assert (git / "refs" / "remotes" / "origin" / "main").read_text(encoding="ascii").strip() == sha
    assert list((git / "objects" / "pack").glob("pack-*.pack"))
    assert list((git / "objects" / "pack").glob("pack-*.idx"))


def test_index_lists_every_tree_entry(tmp_path: Path) -> None:
    dest = tmp_path / "demo"
    _write(tmp_path, FILES, dest)
    data = (dest / ".git" / "index").read_bytes()
    assert data[:4] == b"DIRC"
    version, count = struct.unpack(">II", data[4:12])
    assert (version, count) == (2, 5)
    assert hashlib.sha1(data[:-20], usedforsecurity=False).digest() == data[-20:]
    names, pos = [], 12
    for _ in range(count):
        flags = struct.unpack(">H", data[pos + 60 : pos + 62])[0]
        name = data[pos + 62 : pos + 62 + flags]
        names.append(name.decode())
        mode = struct.unpack(">I", data[pos + 24 : pos + 28])[0]
        if name == b"docs/link":
            assert mode == 0o120000
        if name == b"bin/run.sh":
            assert mode == 0o100755
        if mode in (0o100644, 0o100755):
            # The stat data still matches after the move into place, so Git sees the
            # files as unchanged without reading them again.
            st = dest.joinpath(*name.decode().split("/")).stat()
            _, _, mtime, mtime_ns, dev, ino, _, _, _, size = struct.unpack(
                ">10I", data[pos : pos + 40]
            )
            assert (mtime, mtime_ns) == (int(st.st_mtime), st.st_mtime_ns % 1_000_000_000)
            assert (dev, ino, size) == (
                st.st_dev & 0xFFFFFFFF,
                st.st_ino & 0xFFFFFFFF,
                st.st_size,
            )
        pos += 62 + flags + (8 - (62 + flags) % 8)
    assert (
        names
        == sorted(names)
        == ["README.md", "bin/run.sh", "docs/link", "src/app.py", "vendor/lib"]
    )


@pytest.mark.parametrize(
    "files",
    [
        {".GIT/hooks/post-checkout": "#!/bin/sh\necho x\n", "README.md": "x\n"},
        {"sub/.git./config": "[core]\n", "README.md": "x\n"},
        {"Readme.md": "a\n", "README.md": "b\n"},
        {"aux/notes.txt": "x\n"},
        {"report.txt:payload": "x\n"},
        {"git~1/HEAD": "x\n"},
    ],
    ids=[
        "dot-git-upper",
        "dot-git-trailing-dot",
        "case-collision",
        "reserved",
        "ads",
        "short-name",
    ],
)
def test_unsafe_tree_aborts_before_writing(tmp_path: Path, files: dict[str, object]) -> None:
    dest = tmp_path / "demo"
    with pytest.raises(CheckoutError, match="unsafe paths"):
        _write(tmp_path, files, dest)
    assert not dest.exists()


def test_destination_must_be_missing_or_empty(tmp_path: Path) -> None:
    full = tmp_path / "full"
    full.mkdir()
    (full / "x.txt").write_text("x", encoding="utf-8")
    with pytest.raises(CheckoutError, match="not empty"):
        checkout.check_destination(full)
    afile = tmp_path / "file"
    afile.write_text("x", encoding="utf-8")
    with pytest.raises(CheckoutError, match="not a folder"):
        checkout.check_destination(afile)
    with pytest.raises(CheckoutError, match="parent folder not found"):
        checkout.check_destination(tmp_path / "missing" / "demo")
    with pytest.raises(CheckoutError, match="not allowed"):
        checkout.check_destination(tmp_path / "aux")
    empty = tmp_path / "empty"
    empty.mkdir()
    checkout.check_destination(empty)
    _write(tmp_path, {"README.md": "x\n"}, empty)
    assert (empty / "README.md").is_file()


def test_partial_clone_is_removed_on_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    original = checkout._create_file

    def failing(path: Path, data: bytes, executable: bool) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError(28, "No space left on device")
        original(path, data, executable)

    monkeypatch.setattr(checkout, "_create_file", failing)
    dest = tmp_path / "demo"
    with pytest.raises(CheckoutError, match="No space left"):
        _write(tmp_path, {"a.txt": "a\n", "b.txt": "b\n"}, dest)
    assert not dest.exists()
    assert _staging_folders(tmp_path) == []
    # An empty folder given by the user stays, but empty again.
    empty = tmp_path / "empty"
    empty.mkdir()
    calls = 0
    with pytest.raises(CheckoutError):
        _write(tmp_path / "second", {"a.txt": "a\n", "b.txt": "b\n"}, empty)
    assert empty.is_dir() and not any(empty.iterdir())
    assert _staging_folders(tmp_path) == []


def _staging_folders(parent: Path) -> list[Path]:
    return sorted(parent.glob(f"{checkout.STAGING_PREFIX}*"))


@pytest.mark.parametrize("given", ["missing", "empty"])
def test_interrupted_write_leaves_no_partial_clone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, given: str
) -> None:
    calls = 0
    original = checkout._create_file

    def interrupted(path: Path, data: bytes, executable: bool) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt
        original(path, data, executable)

    monkeypatch.setattr(checkout, "_create_file", interrupted)
    dest = tmp_path / "demo"
    if given == "empty":
        dest.mkdir()
    with pytest.raises(KeyboardInterrupt):
        _write(tmp_path / "origin", {"a.txt": "a\n", "b.txt": "b\n", "c.txt": "c\n"}, dest)
    if given == "empty":
        assert dest.is_dir() and not any(dest.iterdir())
    else:
        assert not dest.exists()
    assert _staging_folders(tmp_path) == []


def _link(link: Path, target: Path) -> None:
    if sys.platform == "win32":
        # A junction needs no special rights (symlinks may).
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


@pytest.mark.parametrize("given", ["missing", "empty"])
def test_target_replaced_by_a_link_before_the_rename_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, given: str
) -> None:
    dest = tmp_path / "demo"
    if given == "empty":
        dest.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    original = checkout._write_git

    def then_swap(*args: object, **kwargs: object) -> None:
        original(*args, **kwargs)  # type: ignore[arg-type]
        if dest.exists():
            dest.rmdir()
        _link(dest, outside)

    monkeypatch.setattr(checkout, "_write_git", then_swap)
    with pytest.raises(CheckoutError, match="target changed while writing: target is a link"):
        _write(tmp_path / "origin", {"a.txt": "a\n"}, dest)
    assert not any(outside.iterdir())
    assert dest.is_symlink() or dest.is_junction()
    assert _staging_folders(tmp_path) == []


def test_clone_appears_in_one_rename(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dest = tmp_path / "demo"
    seen: list[bool] = []
    original = checkout._write_git

    def watch(*args: object, **kwargs: object) -> None:
        original(*args, **kwargs)  # type: ignore[arg-type]
        seen.append(dest.exists())

    monkeypatch.setattr(checkout, "_write_git", watch)
    _write(tmp_path / "origin", FILES, dest)
    assert seen == [False]
    assert (dest / "README.md").is_file() and (dest / ".git" / "index").is_file()
    assert _staging_folders(tmp_path) == []


def test_tag_and_commit_give_a_detached_head(tmp_path: Path) -> None:
    origin = tmp_path / "origin.git"
    ids = build_repo(
        origin, [CommitSpec({"a.txt": "1\n"}), CommitSpec({"a.txt": "2\n"})], tags={"v1": 0}
    )
    for ref in ("v1", ids[0]):
        dest = tmp_path / f"d-{ref[:6]}"
        with clone(REPO, ref=ref, transport=local_transport({"octo/demo": origin})) as cloned:
            written = checkout.write(
                cloned.objects,
                cloned.commit,
                cloned.workspace / "objects" / "pack",
                dest,
                url=REPO.url,
                ref=cloned.full_ref,
            )
        assert written.branch is None
        assert (dest / ".git" / "HEAD").read_text(encoding="ascii") == f"{ids[0]}\n"
        assert (dest / "a.txt").read_bytes() == b"1\n"


def test_unusual_branch_names_are_not_written_as_refs(tmp_path: Path) -> None:
    assert checkout._branch("refs/heads/feature/x") == "feature/x"
    for bad in (
        "refs/heads/a..b",
        "refs/heads/.hidden",
        "refs/heads/x.lock",
        "refs/heads/a b",
        "refs/heads/-x",
        'refs/heads/a"]',
        "refs/tags/v1",
        None,
    ):
        assert checkout._branch(bad) is None


# --- command ---------------------------------------------------------------------


@pytest.fixture
def served(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    clean = tmp_path / "clean.git"
    build_repo(clean, [CommitSpec({"README.md": "# Demo\n"})])
    risky = tmp_path / "risky.git"
    build_repo(risky, [CommitSpec({".vscode/tasks.json": TASKS, "README.md": "x\n"})])
    transport = local_transport({"octo/demo": clean, "octo/risky": risky})
    monkeypatch.setattr(remote, "github_transport", transport)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def answer(monkeypatch: pytest.MonkeyPatch, text: str | None) -> None:
    """Simulate a terminal (``text`` is typed) or no terminal (None)."""
    monkeypatch.setattr(interactive, "can_ask", lambda stdin, environ: text is not None)
    monkeypatch.setattr(sys, "stdin", io.StringIO(text or ""))


def test_clone_with_yes_and_no_findings(
    served: Path, capsys: Capture, monkeypatch: pytest.MonkeyPatch
) -> None:
    answer(monkeypatch, None)
    assert main(["clone", URL, "--yes", "--offline", "--no-color"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "SUMMARY" in out and "Cloned into demo" in out
    assert (served / "demo" / "README.md").is_file()


def test_clone_without_terminal_never_clones_with_findings(
    served: Path, capsys: Capture, monkeypatch: pytest.MonkeyPatch
) -> None:
    answer(monkeypatch, None)
    assert main(["clone", "https://github.com/octo/risky", "--yes", "--offline"]) == EXIT_FINDINGS
    assert "not cloned" in capsys.readouterr().err
    assert not (served / "risky").exists()
    # Without --yes and without a terminal nothing is cloned either.
    assert main(["clone", URL, "--offline"]) == EXIT_OK
    assert "use --yes" in capsys.readouterr().err
    assert not (served / "demo").exists()


def test_clone_asks_and_defaults_to_no(
    served: Path, capsys: Capture, monkeypatch: pytest.MonkeyPatch
) -> None:
    answer(monkeypatch, "\n")
    assert (
        main(["clone", "https://github.com/octo/risky", "--offline", "--no-color"]) == EXIT_FINDINGS
    )
    captured = capsys.readouterr()
    assert "Clone anyway? [y/N]" in captured.out
    assert "declined" in captured.err
    assert not (served / "risky").exists()
    # --yes does not skip the question when there are findings at the threshold.
    answer(monkeypatch, "y\n")
    assert (
        main(["clone", "https://github.com/octo/risky", "target", "--yes", "--offline"])
        == EXIT_FINDINGS
    )
    assert "Clone anyway?" in capsys.readouterr().out
    assert (served / "target" / ".vscode" / "tasks.json").is_file()


def test_clone_fail_on_changes_the_threshold(
    served: Path, capsys: Capture, monkeypatch: pytest.MonkeyPatch
) -> None:
    answer(monkeypatch, None)
    code = main(
        ["clone", "https://github.com/octo/risky", "--yes", "--fail-on", "critical", "--offline"]
    )
    assert code == EXIT_OK
    assert (served / "risky" / "README.md").is_file()


def test_clone_usage_errors(served: Path, capsys: Capture, monkeypatch: pytest.MonkeyPatch) -> None:
    answer(monkeypatch, None)
    (served / "busy").mkdir()
    (served / "busy" / "x").write_text("x", encoding="utf-8")
    assert main(["clone", URL, "busy", "--yes"]) == EXIT_USAGE
    assert "not empty" in capsys.readouterr().err
    assert main(["clone", "ssh://git@github.com/octo/demo.git"]) == EXIT_USAGE
    assert main(["clone", str(served)]) == EXIT_USAGE
    assert main(["clone", "https://github.com/octo/missing", "--yes", "--offline"]) == EXIT_ABORTED


def test_clone_error_while_writing_exits_3(
    served: Path, capsys: Capture, monkeypatch: pytest.MonkeyPatch
) -> None:
    answer(monkeypatch, None)

    def broken(*args: object, **kwargs: object) -> None:
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(checkout, "_create_file", broken)
    assert main(["clone", URL, "--yes", "--offline"]) == EXIT_ABORTED
    assert "clone aborted" in capsys.readouterr().err
    assert not (served / "demo").exists()


def test_cli_module_has_no_clone_logic() -> None:
    assert not hasattr(cli, "unsafe_paths")
