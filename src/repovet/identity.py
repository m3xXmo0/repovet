"""Versioned, content-based finding identities shared by reports and comparisons."""

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import replace

from repovet.limits import Limits
from repovet.models import Finding
from repovet.sources.tree import FileTree

FINGERPRINT_VERSION = "repovet:v1"


def normalize_content(text: str) -> str:
    """Normalize line endings and outer whitespace; preserve code and string contents."""
    return text.replace("\r\n", "\n").replace("\r", "\n").strip()


def _material(finding: Finding) -> str:
    if finding.identity_material is not None:
        return normalize_content(finding.identity_material)
    if finding.evidence:
        return normalize_content(finding.evidence)
    message = finding.message
    if finding.location and finding.location.path:
        message = message.replace(finding.location.path, "<file>")
    return normalize_content(message)


def fingerprint(finding: Finding, *, chain_contents: Mapping[str, str] | None = None) -> str:
    """A semantic bucket, not a unique occurrence or a proof of file integrity.

    Identical findings deliberately share this value. The matcher preserves their
    multiplicity and uses locations to disambiguate. Chain step paths and content
    digests are ordered; scan-local chain numbers and line positions are excluded.
    """
    payload: dict[str, object] = {"rule": finding.rule_id, "content": _material(finding)}
    if finding.chain is not None:
        contents = chain_contents or {}
        payload["chain"] = [
            {"path": step.path, "content": contents.get(step.path, "unavailable")}
            for step in finding.chain.steps
        ]
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(encoded.encode("ascii")).hexdigest()
    return f"{FINGERPRINT_VERSION}:{digest}"


def enrich_findings(findings: Sequence[Finding], tree: FileTree, limits: Limits) -> list[Finding]:
    """Assign identities once, after chains have been assembled; bound every read."""
    files = {file.path: file for file in tree.files()}
    contents: dict[str, str] = {}
    paths = {
        step.path
        for finding in findings
        if finding.chain is not None
        for step in finding.chain.steps
    }
    for path in sorted(paths):
        file = files.get(path)
        if file is None or file.size > limits.max_file_size:
            contents[path] = "unavailable"
            continue
        try:
            data = file.read_bytes(limits.max_file_size + 1)
        except OSError:
            contents[path] = "unavailable"
            continue
        contents[path] = (
            hashlib.sha256(data).hexdigest() if len(data) <= limits.max_file_size else "unavailable"
        )
    return [replace(f, fingerprint=fingerprint(f, chain_contents=contents)) for f in findings]
