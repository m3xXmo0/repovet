# Reconstructions of documented attack techniques

Each file describes one publicly documented supply-chain incident or repository-based
attack technique and rebuilds only its *shape* as inline fixture files. The files are
created in a temporary folder during the test and scanned offline; nothing is run.

- Hosts are placeholders (`example.invalid`); commands are harmless; there are no
  working payloads and no real indicators (hashes, command-and-control hosts, wallets).
- `sources` link to public, verifiable reports (advisories, CVEs, post-mortems).
- `must_fire` / `must_not_fire` are checked by `tests/test_reconstructions.py`.
- `known_gaps` are rules that should fire but do not. They are kept as written instead
  of weakening the expectation; the test fails as soon as a gap closes, so it can be
  moved to `must_fire`.
- `not_covered` names parts of a technique that are outside what repovet checks.

Run `uv run python scripts/reconstructions.py` for an overview.
