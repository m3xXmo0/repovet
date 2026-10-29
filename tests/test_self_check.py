"""Static self-check of repovet's own source, beyond what ruff can ban.

ruff (banned-api, bandit) covers imports like subprocess, pickle and yaml.load. This
test covers bare builtins that ruff cannot ban and writing calls: repovet only
reads the scanned folder and writes nothing but its report (stdout/stderr, or the
file named with -o in the one function listed in REPORT_WRITERS), for URL
targets the temporary clone folder (only in the functions in CLONE_WORKSPACE), and
for ``repovet clone`` the new working tree (only in the functions in CHECKOUT).
"""

import ast
import unicodedata
from pathlib import Path

SRC = Path(__file__).parent.parent / "src" / "repovet"
FORBIDDEN_CALLS = {"compile", "exec", "eval", "__import__", "breakpoint", "input"}
FORBIDDEN_METHODS = {
    "write_text",
    "write_bytes",
    "mkdir",
    "makedirs",
    "unlink",
    "rmdir",
    "rmtree",
    "remove",
    "rename",
    "replace",
    "touch",
    "chmod",
    "symlink_to",
    "hardlink_to",
    "symlink",
    "truncate",
    "mkdtemp",
    "mkstemp",
    "add_pack",
    "add_object",
    "add_objects",
}
WRITE_MODES = ("w", "a", "x", "+")
# (module, function) allowed to open a file for writing: the -o report file.
REPORT_WRITERS = {("scanning.py", "write_report")}
# (module, function) allowed to create, fill and delete the temporary clone folder of a
# URL target. It is never inside the scanned folder and holds only a pack file.
CLONE_WORKSPACE = {
    ("sources/remote.py", "_new_workspace"),
    ("sources/remote.py", "_fetch"),
    ("sources/remote.py", "_remove_workspace"),
    ("sources/remote.py", "make_writable"),
}
# (module, function) allowed to write the working tree of ``repovet clone``: into a new
# or empty folder the user named, from Git objects that were checked, after every path
# was validated.
CHECKOUT = {
    ("sources/checkout.py", "_create_file"),
    ("sources/checkout.py", "_write_tree"),
    ("sources/checkout.py", "_write_git"),
    ("sources/checkout.py", "_create_stage"),
    ("sources/checkout.py", "_move_into_place"),
    ("sources/checkout.py", "_remove_stage"),
    ("sources/checkout.py", "make_writable"),
}
# Flags of os.open that write, and shutil functions that copy or move files.
WRITE_FLAGS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC"}
SHUTIL_WRITERS = {"copy", "copy2", "copyfile", "copytree", "copyfileobj", "move"}


def python_files() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def _calls_with_function(tree: ast.Module) -> list[tuple[ast.Call, str]]:
    """Every call with the name of the innermost enclosing function ('' at module level)."""
    found: list[tuple[ast.Call, str]] = []
    stack: list[tuple[ast.AST, str]] = [(tree, "")]
    while stack:
        node, function = stack.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            function = node.name
        if isinstance(node, ast.Call):
            found.append((node, function))
        stack.extend((child, function) for child in ast.iter_child_nodes(node))
    return found


def offenders() -> list[str]:
    found: list[str] = []
    for path in python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        module = path.relative_to(SRC).as_posix()
        for node, function in _calls_with_function(tree):
            where = f"{module}:{node.lineno}"
            func = node.func
            if isinstance(func, ast.Name) and func.id in FORBIDDEN_CALLS:
                found.append(f"{where} calls {func.id}()")
            opens = (isinstance(func, ast.Name) and func.id == "open" and _writes(node, 1)) or (
                isinstance(func, ast.Attribute) and func.attr == "open" and _writes(node, 0)
            )
            opens = opens or _os_open_writes(node)
            allowed = REPORT_WRITERS | CHECKOUT
            if opens and (module, function) not in allowed:
                found.append(f"{where} opens a file for writing")
            if (
                isinstance(func, ast.Attribute)
                and func.attr in SHUTIL_WRITERS
                and isinstance(func.value, ast.Name)
                and func.value.id == "shutil"
                and (module, function) not in CHECKOUT
            ):
                found.append(f"{where} calls shutil.{func.attr}()")
            if isinstance(func, ast.Attribute) and func.attr in FORBIDDEN_METHODS:
                if func.attr == "replace" and _is_str_replace(node):
                    continue
                if (module, function) in CLONE_WORKSPACE | CHECKOUT:
                    continue
                found.append(f"{where} calls .{func.attr}()")
    return found


def _writes(node: ast.Call, mode_index: int) -> bool:
    modes = [
        *node.args[mode_index : mode_index + 1],
        *(k.value for k in node.keywords if k.arg == "mode"),
    ]
    return any(
        isinstance(m, ast.Constant)
        and isinstance(m.value, str)
        and any(c in m.value for c in WRITE_MODES)
        for m in modes
    )


def _os_open_writes(node: ast.Call) -> bool:
    """os.open(path, flags) with a writing flag such as os.O_WRONLY or os.O_CREAT."""
    func = node.func
    if not (
        isinstance(func, ast.Attribute)
        and func.attr == "open"
        and isinstance(func.value, ast.Name)
        and func.value.id == "os"
        and len(node.args) > 1
    ):
        return False
    names = {n.attr for n in ast.walk(node.args[1]) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(node.args[1]) if isinstance(n, ast.Name)}
    return bool(names & WRITE_FLAGS)


def _is_str_replace(node: ast.Call) -> bool:
    # Path.replace(target) takes one argument and os/shutil.replace(src, dst) is called on
    # the module; any other x.replace(old, new) is str.replace, not a file rename.
    func = node.func
    assert isinstance(func, ast.Attribute)
    on_module = isinstance(func.value, ast.Name) and func.value.id in {"os", "shutil"}
    return len(node.args) == 2 and not node.keywords and not on_module


def test_source_files_found() -> None:
    assert len(python_files()) > 10


def test_no_dynamic_code_and_no_writes_in_source() -> None:
    assert offenders() == []


def test_write_detection_covers_path_open() -> None:
    tree = ast.parse("def f(p):\n    p.open('w')\n    open(p, mode='a')\n    p.open()\n")
    calls = _calls_with_function(tree)
    flagged = sorted(
        n.lineno
        for n, _ in calls
        if (isinstance(n.func, ast.Attribute) and n.func.attr == "open" and _writes(n, 0))
        or (isinstance(n.func, ast.Name) and n.func.id == "open" and _writes(n, 1))
    )
    assert flagged == [2, 3]
    assert {fn for _, fn in calls} == {"f"}


def test_write_detection_covers_os_open_flags() -> None:
    tree = ast.parse(
        "import os\nos.open(p, os.O_RDONLY)\nos.open(p, os.O_WRONLY | os.O_CREAT, 0o666)\n"
    )
    calls = [n for n, _ in _calls_with_function(tree)]
    assert [n.lineno for n in calls if _os_open_writes(n)] == [3]


def _raw_invisible(text: str) -> list[str]:
    hits = []
    for char in text:
        cp = ord(char)
        if char in "\n\r\t":
            continue
        if (
            cp < 0x20
            or 0x7F <= cp <= 0x9F
            or 0xFE00 <= cp <= 0xFE0F
            or 0xE0000 <= cp <= 0xE01EF
            or unicodedata.category(char) in {"Cf", "Zl", "Zp", "Co"}
        ):
            hits.append(f"U+{cp:04X}")
    return hits


def test_no_raw_invisible_characters_in_code_tests_and_rules() -> None:
    # Invisible or control characters only as escapes, never raw.
    project = SRC.parent.parent
    files = [
        p
        for folder in (project / "src", project / "tests")
        for p in folder.rglob("*")
        if p.suffix in {".py", ".yaml", ".txt", ".md", ".toml"} and "__pycache__" not in p.parts
    ]
    bad = {
        str(p.relative_to(project)): hits
        for p in files
        if (hits := _raw_invisible(p.read_text(encoding="utf-8")))
    }
    assert bad == {}
