# Recorded GitHub API answers

Tests never use the network. The trust area is tested with answers that were recorded
once from the real GitHub REST API (unauthenticated) and then anonymized:

- owner, repository and user names, e-mail addresses and numeric ids are replaced
  (`example-org/example-repo`, `user-1`, `...@example.invalid`);
- commit ids and digests are replaced by fake values;
- descriptions, commit messages and release notes are replaced or dropped;
- template URLs (`*_url`), avatars, node ids and other fields the trust area does not
  read are dropped.

Each file maps an API path with its query (parameters sorted, as the client sends them)
to `{status, headers, body}`; `status` defaults to 200. `tests/github_fake.py` serves
them and adds the rate-limit headers.

| File               | Recorded from                                    |
|--------------------|--------------------------------------------------|
| `established.json` | an established open-source project (2026-10-29): repository, owner, contributors and commits (one item each, counted through the `Link` header), latest release, default branch |

Tests derive other situations (young repositories, forks, archived repositories,
missing data) by changing single fields of these answers.
