import base64
import zlib

import pytest

from helpers import run_check, view_of
from repovet.engine.checks import BUILDERS
from repovet.engine.checks.base import BuildEnv, CheckError, Params
from repovet.engine.checks.blob import (
    code_density,
    decode_run,
    decompress,
    entropy,
    is_media,
    string_share,
)

CODE = base64.b64encode(b"import os\nos.system('echo harmless')\n").decode()
RANDOM = base64.b64encode(bytes(range(256)) * 2).decode()


def test_entropy() -> None:
    assert entropy("") == 0.0
    assert entropy("aaaa") == 0.0
    assert entropy("abcd") == pytest.approx(2.0)


def test_decode_run() -> None:
    assert decode_run("aGk", "base64") == b"hi"
    assert decode_run("a", "base64") is None
    assert decode_run("6869", "hex") == b"hi"
    assert decode_run("\\x68\\x69", "hex") == b"hi"
    assert decode_run("zz", "hex") is None


def test_media_and_decompress() -> None:
    assert is_media(b"\x89PNG\r\n")
    assert is_media(b"RIFF\x00\x00\x00\x00WEBPVP8 ")
    assert not is_media(b"import os")
    assert decompress(zlib.compress(b"hello")) == b"hello"
    assert decompress(b"plain") is None
    bomb = zlib.compress(b"\x00" * 10_000_000)
    inflated = decompress(bomb)
    assert inflated is not None and len(inflated) == 64 * 1024


def test_decoded_regex_reports_decoded_preview() -> None:
    spec = {"type": "blob", "encoding": "base64", "min_length": 32, "decoded_regex": "import"}
    matches = run_check(spec, "a.py", f'X = "{CODE}"\n')
    assert len(matches) == 1
    assert matches[0].line == 1
    assert matches[0].column == 6
    assert matches[0].values["decoded"].startswith("import os os.system")


def test_not_decoded_regex_and_entropy() -> None:
    spec = {
        "type": "blob",
        "encoding": "base64",
        "min_length": 100,
        "min_entropy": 5.0,
        "not_decoded_regex": "import",
    }
    assert run_check(spec, "a.py", f'X = "{RANDOM}"\n')[0].values["decoded"] == "binary data"
    long_code = base64.b64encode(b"import os\n" * 20).decode()
    assert run_check({**spec, "min_entropy": 0}, "a.py", long_code) == []
    assert run_check(spec, "a.py", "A" * 400) == []


def test_data_uri_and_media_skipped() -> None:
    spec = {"type": "blob", "encoding": "base64", "min_length": 100}
    assert run_check(spec, "a.js", f'u = "data:application/octet-stream;base64,{RANDOM}"') == []
    png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(range(200))).decode()
    assert run_check(spec, "a.js", f'u = "{png}"') == []
    assert len(run_check({**spec, "skip_media": False}, "a.js", f'u = "{png}"')) == 1


def test_hex_runs_need_word_boundaries() -> None:
    spec = {"type": "blob", "encoding": "hex", "min_length": 32, "decoded_regex": "require"}
    text = b"require('child_process')".hex()
    assert len(run_check(spec, "a.js", f'h = "{text}"')) == 1
    assert run_check(spec, "a.js", f'h = "g{text}"') == []


def test_hex_escapes_and_generated_header() -> None:
    escaped = "".join(f"\\x{b:02x}" for b in b"require('child_process')")
    spec = {"type": "blob", "encoding": "hex", "min_length": 40, "decoded_regex": "require"}
    assert len(run_check(spec, "a.js", f'h = "{escaped}"')) == 1
    header = {**spec, "skip_header_regex": "@generated"}
    assert run_check(header, "a.js", f'// @generated\nh = "{escaped}"') == []


def test_runs_are_shared_between_rules() -> None:
    view = view_of("a.py", f'X = "{CODE}"')
    spec = {"type": "blob", "encoding": "base64", "min_length": 32, "decoded_regex": "import"}
    check = BUILDERS["blob"](Params(spec), BuildEnv({}))
    assert len(list(check.matches(view))) == 1
    assert "blob:runs" in view.memo
    view.memo["blob:runs"] = []
    assert list(check.matches(view)) == []


def test_long_lines() -> None:
    spec = {"type": "blob", "encoding": "none", "min_length": 50}
    matches = run_check(spec, "a.py", "short\n" + "x" * 60 + "\n")
    assert [(m.line, m.values["count"]) for m in matches] == [(2, "60")]


def test_code_density_and_string_share() -> None:
    assert code_density("") == string_share("") == 0.0
    assert code_density("f(a);") == pytest.approx(0.6)
    assert string_share("x = 'abcd'") == pytest.approx(0.6)
    assert string_share('a "b\\"c" d') == pytest.approx(6 / 10)
    assert string_share("x = 'unclosed") == pytest.approx(9 / 13)
    assert string_share("a 'x\\") == pytest.approx(3 / 5)


def test_long_lines_shaped_like_code() -> None:
    spec = {
        "type": "blob",
        "encoding": "none",
        "min_length": 50,
        "min_code_density": 0.06,
        "max_string_share": 0.8,
    }
    code = "a=f(b);" * 10
    prose = "word " * 20
    text_in_string = "x = '" + "a;b(c)=d " * 10 + "'"
    matches = run_check(spec, "a.js", f"{code}\n{prose}\n{text_in_string}\n")
    assert [m.line for m in matches] == [1]


def test_long_lines_are_checked_beyond_the_regex_limit() -> None:
    spec = {"type": "blob", "encoding": "base64", "min_length": 32, "decoded_regex": "import"}
    line = "x" * 30_000 + f' "{CODE}"'
    assert len(run_check(spec, "a.js", line)) == 1


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ({"encoding": "rot13", "min_length": 32}, "unknown encoding"),
        ({"encoding": ["none", "hex"], "min_length": 32}, "cannot be combined"),
        ({"encoding": "base64"}, "'min_length' is required"),
        ({"encoding": "base64", "min_length": 4}, ">= 32"),
        ({"encoding": "base64", "min_length": 32, "min_entropy": 9}, "<= 8.0"),
        ({"encoding": "none", "min_length": 32, "decoded_regex": "x"}, "needs an encoding"),
        ({"encoding": "base64", "min_length": 32, "extra": 1}, "unknown check parameter"),
        ({"encoding": "base64", "min_length": 32, "min_code_density": 0.1}, "need encoding"),
        ({"encoding": "none", "min_length": 32, "max_string_share": 2}, "<= 1.0"),
    ],
)
def test_invalid_parameters(spec: dict[str, object], message: str) -> None:
    with pytest.raises(CheckError, match=message):
        run_check({"type": "blob", **spec}, "a.py", "")
