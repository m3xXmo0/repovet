"""Check types. One module per type; a new type needs a module here plus tests."""

from collections.abc import Callable

from repovet.engine.checks import (
    blob,
    chain,
    dependency,
    filename,
    import_ref,
    keypath,
    magic,
    metric,
    python_ast,
    regex,
    sentence,
    split_payload,
    tree,
    unicode,
)
from repovet.engine.checks.base import BuildEnv, Check, Params

type Builder = Callable[[Params, BuildEnv], Check]

BUILDERS: dict[str, Builder] = {
    "filename": filename.build,
    "regex": regex.build,
    "sentence": sentence.build,
    "split_payload": split_payload.build,
    "keypath": keypath.build,
    "unicode": unicode.build,
    "python_ast": python_ast.build,
    "import_ref": import_ref.build,
    "blob": blob.build,
    "magic": magic.build,
    "tree": tree.build,
    "dependency": dependency.build,
    "metric": metric.build,
    "chain": chain.build,
}

# Check types that arrive in later milestones.
PLANNED: dict[str, int] = {}
