"""Check type ``split_payload``: an encoded string split into constants, joined, decoded
and run.

Only constants of the same file count: string literals joined with ``+`` (or
``"".join([...])``), directly or through names assigned exactly once in the file from
such an expression. The joined text must look like Base64 or hex. It is reported when it
goes into a decoder (``b64decode``, ``bytes.fromhex``, ``Buffer.from(..., "base64")``,
``atob`` ...) whose result is executed: inside the call of an execution function, or
through a name assigned once from the decoder call. There is no data-flow analysis
beyond that.

Python files are read with ``ast.parse``; JavaScript and TypeScript files with the
string spans of ``parsers.codelex`` and regexes on the remaining code. Nothing is run;
the joined constant is decoded (as data) only to show it in the message.
"""

import ast
import base64
import binascii
import re
from collections.abc import Iterator
from dataclasses import dataclass

from repovet.engine.checks.base import BuildEnv, Check, FileView, Match, Params
from repovet.engine.checks.python_ast import dotted_name, import_aliases, resolve
from repovet.parsers.codelex import family_of, literal_spans

_MIN_LENGTH = 16
_MAX_DEPTH = 8
_BASE64 = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2})+")
_PREVIEW = 80
# Lowercase literals for the prefilter: decoder and execution function names.
_DECODER_NAMES = (
    "b64decode",
    "decodebytes",
    "a2b_",
    "fromhex",
    "unhexlify",
    "codecs",
    "buffer.from",
    "atob",
)
_SINK_NAMES = (
    "eval",
    "exec",
    "compile",
    "function",
    "vm.",
    "spawn",
    "system",
    "popen",
    "subprocess",
)
_JS_EXTENSIONS = {"js", "mjs", "cjs", "jsx", "ts", "tsx", "mts", "cts"}

_PY_DECODERS = {
    "base64.b64decode": "base64",
    "base64.standard_b64decode": "base64",
    "base64.urlsafe_b64decode": "base64",
    "base64.decodebytes": "base64",
    "binascii.a2b_base64": "base64",
    "bytes.fromhex": "hex",
    "binascii.unhexlify": "hex",
    "binascii.a2b_hex": "hex",
}
_PY_SINKS = {
    "exec",
    "eval",
    "compile",
    "builtins.exec",
    "builtins.eval",
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
}


@dataclass(frozen=True)
class Joined:
    """A string built from ``parts`` constants."""

    value: str
    parts: int


def looks_encoded(value: str, encoding: str) -> bool:
    if len(value) < _MIN_LENGTH:
        return False
    pattern = _HEX if encoding == "hex" else _BASE64
    return pattern.fullmatch(value) is not None


def preview(value: str, encoding: str) -> str:
    """The decoded text for the message (data only), shortened."""
    try:
        if encoding == "hex":
            data = bytes.fromhex(value)
        else:
            padded = value + "=" * (-len(value) % 4)
            data = base64.b64decode(padded.replace("-", "+").replace("_", "/"))
    except (ValueError, binascii.Error):
        return "(could not be decoded)"
    text = data.decode("utf-8", errors="replace")
    return text if len(text) <= _PREVIEW else text[:_PREVIEW] + "..."


# --- Python ----------------------------------------------------------------------


class _PythonFile:
    def __init__(self, module: ast.Module) -> None:
        self.aliases = import_aliases(module)
        self.module = module
        # Every binding of a name (assignment, augmented assignment, for, with, :=,
        # comprehension) counts; only names bound exactly once keep their value.
        counts: dict[str, int] = {}
        values: dict[str, ast.expr] = {}
        for node in ast.walk(module):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                counts[node.id] = counts.get(node.id, 0) + 1
            elif isinstance(node, ast.Assign) and len(node.targets) == 1:
                if isinstance(node.targets[0], ast.Name):
                    values[node.targets[0].id] = node.value
            elif (
                isinstance(node, ast.AnnAssign)
                and node.value is not None
                and isinstance(node.target, ast.Name)
            ):
                values[node.target.id] = node.value
        self.values = {name: value for name, value in values.items() if counts.get(name) == 1}

    def name(self, node: ast.expr) -> str | None:
        raw = dotted_name(node)
        return None if raw is None else resolve(raw, self.aliases)

    def joined(self, node: ast.expr, depth: int = 0) -> Joined | None:
        if depth > _MAX_DEPTH:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str | bytes):
            value = node.value
            return Joined(value if isinstance(value, str) else value.decode("latin-1"), 1)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.joined(node.left, depth + 1), self.joined(node.right, depth + 1)
            if left is None or right is None:
                return None
            return Joined(left.value + right.value, left.parts + right.parts)
        if isinstance(node, ast.Name) and node.id in self.values:
            return self.joined(self.values[node.id], depth + 1)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            # "".join([A, B]) and (A + B).encode()
            func = node.func
            if func.attr == "encode" and not node.args:
                return self.joined(func.value, depth + 1)
            separator = self.joined(func.value, depth + 1)
            if func.attr == "join" and separator is not None and separator.value == "":
                items = node.args[0] if len(node.args) == 1 else None
                if isinstance(items, ast.List | ast.Tuple):
                    parts = [self.joined(item, depth + 1) for item in items.elts]
                    if all(p is not None for p in parts):
                        found = [p for p in parts if p is not None]
                        return Joined("".join(p.value for p in found), sum(p.parts for p in found))
        return None

    def split_decode(self, node: ast.expr, depth: int = 0) -> tuple[Joined, str] | None:
        """A decoder call on a split constant anywhere in ``node`` (or behind a name
        assigned once from such an expression)."""
        if depth > _MAX_DEPTH:
            return None
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and sub.args:
                encoding = _PY_DECODERS.get(self.name(sub.func) or "")
                if encoding is None and self.name(sub.func) == "codecs.decode":
                    encoding = _codecs_encoding(sub)
                if encoding is not None:
                    joined = self.joined(sub.args[0])
                    if joined and joined.parts >= 2 and looks_encoded(joined.value, encoding):
                        return joined, encoding
            if isinstance(sub, ast.Name) and sub.id in self.values:
                found = self.split_decode(self.values[sub.id], depth + 1)
                if found is not None:
                    return found
        return None

    def matches(self) -> Iterator[tuple[int, Joined, str]]:
        for node in ast.walk(self.module):
            if not isinstance(node, ast.Call) or self.name(node.func) not in _PY_SINKS:
                continue
            for argument in node.args:
                found = self.split_decode(argument)
                if found is not None:
                    yield node.lineno, found[0], found[1]
                    break


def _codecs_encoding(call: ast.Call) -> str | None:
    if len(call.args) < 2 or not isinstance(call.args[1], ast.Constant):
        return None
    codec = str(call.args[1].value).lower().replace("-", "_")
    return {"base64": "base64", "base_64": "base64", "hex": "hex"}.get(codec)


# --- JavaScript and TypeScript ----------------------------------------------------

_MARK = "\x01"
_STRING = re.compile(r"\x01(\d+)\x01")
_IDENT = r"[A-Za-z_$][\w$]*"
_OPERAND = rf"(?:\x01\d+\x01|{_IDENT})"
# Matched against an expression without spaces and tabs (operands are names and
# placeholders, so spacing does not matter).
_CONCAT = re.compile(rf"\(?{_OPERAND}(?:\+{_OPERAND})*\)?")
_ARRAY_JOIN = re.compile(rf"\[({_OPERAND}(?:,{_OPERAND})*),?\]\.join\((\x01\d+\x01)\)")
_SPACE = re.compile(r"[ \t]+")
# An optional TypeScript type annotation between the name and '='.
_TYPE = r"(?::[ \t]*[\w$.<>\[\]| ]{1,60}?[ \t]*)?"
_DECLARATION = re.compile(
    rf"\b(?:const|let|var)[ \t]+({_IDENT})[ \t]*{_TYPE}=(?!=)[ \t]*([^;\n]{{1,2000}})"
)
# Every assignment to a name (declaration or later assignment).
_ASSIGNMENT = re.compile(rf"(?<![\w$.]){_IDENT}(?=[ \t]*{_TYPE}(?:=(?![=>])|\+=|-=))")
# A call argument with at most one level of parentheses (a .join("") inside).
_ARGUMENT = r"(?:[^()\n]|\([^()\n]{0,200}\)){1,500}?"
_DECODER = re.compile(
    rf"\bBuffer\.from[ \t]*\([ \t]*({_ARGUMENT})[ \t]*,[ \t]*\x01(\d+)\x01[ \t]*\)"
    rf"|\batob[ \t]*\([ \t]*({_ARGUMENT})[ \t]*\)"
)
_SINK = re.compile(
    r"(?:\beval|\bnew[ \t]+Function|(?<![\w$.])Function|\bvm\.(?:runInThisContext|runInNewContext"
    r"|runInContext|compileFunction)|\bnew[ \t]+vm\.Script|\b(?:execSync|execFileSync|spawnSync"
    r"|execFile|spawn|exec))[ \t]*\(([^;\n]{0,500})"
)


class _ScriptFile:
    def __init__(self, text: str, path: str) -> None:
        spans = literal_spans(text, path)
        self.strings: list[str] = []
        pieces: list[str] = []
        position = 0
        if spans is not None:
            for start, end, kind in zip(spans.starts, spans.ends, spans.kinds, strict=True):
                pieces.append(text[position:start])
                literal = text[start:end]
                # Comments and template literals with placeholders are blanked out.
                if kind == "c" or (literal[0] == "`" and "${" in literal):
                    pieces.append(re.sub(r"[^\n]", " ", literal))
                else:
                    pieces.append(f"{_MARK}{len(self.strings)}{_MARK}")
                    self.strings.append(literal[1:-1] if len(literal) >= 2 else "")
                position = end
        pieces.append(text[position:])
        self.code = "".join(pieces)
        assigned: dict[str, int] = {}
        for found in _ASSIGNMENT.finditer(self.code):
            assigned[found.group(0)] = assigned.get(found.group(0), 0) + 1
        self.values: dict[str, str] = {}
        for found in _DECLARATION.finditer(self.code):
            name = found.group(1)
            if assigned.get(name) == 1:
                self.values[name] = found.group(2).strip()
        self.decoded = {
            name for name, value in self.values.items() if self.split_decode(value) is not None
        }

    def joined(self, expression: str, depth: int = 0) -> Joined | None:
        expression = _SPACE.sub("", expression).rstrip(";")
        if depth > _MAX_DEPTH or not expression:
            return None
        array = _ARRAY_JOIN.fullmatch(expression)
        if array is not None:
            if self.strings[int(array.group(2).strip(_MARK))] != "":
                return None
            operands = array.group(1).split(",")
        elif _CONCAT.fullmatch(expression):
            operands = [o.strip("()") for o in expression.split("+")]
        else:
            return None
        value, parts = "", 0
        for operand in operands:
            literal = _STRING.fullmatch(operand)
            if literal is not None:
                value += self.strings[int(literal.group(1))]
                parts += 1
                continue
            inner = self.values.get(operand)
            resolved = None if inner is None else self.joined(inner, depth + 1)
            if resolved is None:
                return None
            value += resolved.value
            parts += resolved.parts
        return Joined(value, parts)

    def split_decode(self, expression: str) -> tuple[Joined, str] | None:
        for found in _DECODER.finditer(expression):
            if found.group(1) is not None:
                encoding = self.strings[int(found.group(2))].lower()
                if encoding not in ("base64", "base64url", "hex"):
                    continue
                argument = found.group(1)
            else:
                encoding, argument = "base64", found.group(3)
            encoding = "hex" if encoding == "hex" else "base64"
            joined = self.joined(argument)
            if joined and joined.parts >= 2 and looks_encoded(joined.value, encoding):
                return joined, encoding
        return None

    def matches(self) -> Iterator[tuple[int, Joined, str]]:
        for sink in _SINK.finditer(self.code):
            argument = sink.group(1)
            found = self.split_decode(argument)
            if found is None:
                for name in self.decoded:
                    if re.search(rf"(?<![\w$.]){re.escape(name)}(?![\w$])", argument):
                        found = self.split_decode(self.values[name])
                        break
            if found is not None:
                yield self.code.count("\n", 0, sink.start()) + 1, found[0], found[1]


class SplitPayloadCheck(Check):
    def matches(self, view: FileView) -> Iterator[Match]:
        text = view.text()
        # Cheap prefilter: a decoder and an execution function must both be named.
        if text is None or not view.contains_any(_DECODER_NAMES):
            return
        if not view.contains_any(_SINK_NAMES):
            return
        extension = view.name.rpartition(".")[2].lower()
        found: Iterator[tuple[int, Joined, str]]
        if family_of(view.path) == "python":
            module = view.python_module()
            if module is None:
                return
            found = _PythonFile(module).matches()
        elif extension in _JS_EXTENSIONS:
            if view.has_long_lines():
                view.note_long_lines()
                return
            found = _ScriptFile(text, view.path).matches()
        else:
            return
        for line, joined, encoding in found:
            yield Match(
                line,
                None,
                view.line_text(line),
                {"count": str(joined.parts), "decoded": preview(joined.value, encoding)},
            )

    def regexes(self) -> list[re.Pattern[str]]:
        return [_CONCAT, _ARRAY_JOIN, _SPACE, _DECLARATION, _ASSIGNMENT, _DECODER, _SINK]


def build(params: Params, env: BuildEnv) -> Check:
    params.done()
    return SplitPayloadCheck()
