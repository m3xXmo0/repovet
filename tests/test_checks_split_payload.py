from helpers import run_check
from repovet.engine.checks.split_payload import looks_encoded, preview

SPEC = {"type": "split_payload"}
# Base64 of 'print("dummy payload, nothing runs")', split in two.
A, B = "cHJpbnQoImR1bW15IHBheWxv", "YWQsIG5vdGhpbmcgcnVucyIp"


def test_python_join_through_names_assigned_once() -> None:
    text = f'import base64\nX = "{A}"\nY = "{B}"\ncode = base64.b64decode(X + Y)\nexec(code)\n'
    (match,) = run_check(SPEC, "a.py", text)
    assert match.line == 5
    assert match.values == {"count": "2", "decoded": 'print("dummy payload, nothing runs")'}


def test_python_codecs_and_bytes_fromhex() -> None:
    hex_a, hex_b = "6563686f2064756d", "6d79202d6e6f7468696e67"
    text = f'import os\nos.system(bytes.fromhex("{hex_a}" + "{hex_b}").decode())\n'
    (match,) = run_check(SPEC, "b.py", text)
    assert match.values["decoded"] == "echo dummy -nothing"
    text = f'import codecs\nexec(codecs.decode("{A}" + "{B}", "base64"))\n'
    assert run_check(SPEC, "c.py", text)


def test_python_without_execution_or_with_reassigned_names() -> None:
    assert not run_check(SPEC, "a.py", f'import base64\nd = base64.b64decode("{A}" + "{B}")\n')
    text = f'import base64\nX = "{A}"\nX = X + "{B}"\nexec(base64.b64decode(X))\n'
    assert not run_check(SPEC, "a.py", text)


def test_javascript_comments_and_template_literals_do_not_count() -> None:
    text = f'// const a = "{A}";\nconst b = `{B}${{x}}`;\neval(atob(a + b));\n'
    assert not run_check(SPEC, "a.js", text)


def test_javascript_decoded_variable_in_vm() -> None:
    text = (
        f'const vm = require("vm");\nconst p1 = "{A}", unused = 1;\nconst p2 = "{B}";\n'
        'let code = Buffer.from(["' + A + '", "' + B + '"].join(""), "base64url").toString();\n'
        "vm.runInThisContext(code);\n"
    )
    (match,) = run_check(SPEC, "a.mjs", text)
    assert match.line == 5


def test_other_files_and_long_lines_are_skipped() -> None:
    text = f'eval(atob("{A}" + "{B}"));\n'
    assert run_check(SPEC, "a.ts", text)
    assert not run_check(SPEC, "a.rb", text)
    assert not run_check(SPEC, "a.js", text.rstrip("\n") + " " * 30_000 + "\n")


def test_helpers() -> None:
    assert looks_encoded("6563686f2064756d6d79", "hex")
    assert not looks_encoded("6563686f2", "hex")
    assert not looks_encoded("short", "base64")
    assert not looks_encoded("not base64 at all!!", "base64")
    assert preview("zz", "hex") == "(could not be decoded)"
    assert preview(("QUFB" * 40), "base64").endswith("...")
