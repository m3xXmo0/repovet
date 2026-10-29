# Schemas for tests

- `sarif-schema-2.1.0.json`: SARIF 2.1.0 JSON schema (OASIS, errata 01), downloaded once on
  2026-10-29 from
  https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
  and stored unchanged, so tests never use the network. Copyright OASIS Open; used only
  to validate repocheck's SARIF output in `tests/test_report_formats.py`.

The schema of repocheck's own JSON report is `docs/report.schema.json`.
