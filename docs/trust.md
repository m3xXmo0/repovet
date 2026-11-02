# Trust (GitHub API)

For a GitHub URL, and for a local folder whose `.git/config` names a GitHub repository as
remote `origin` (or as its only remote), repovet asks the GitHub REST API about the
repository and its owner. The trust profile comes before the provenance profile (excerpt,
anonymized):

```
TRUST PROFILE                            facts, not findings
  Repository example-org/example-repo, created 2010-04-06 (16 years ago); last
             push 2026-10-07 (22 days ago)
  Owner      example-org (organization), account created 2016-01-17 (10 years
             ago); 16 public repositories, 2,654 followers
  Popularity 74,935 stars, 17,200 forks, 2,130 watchers
  Activity   5,562 commits on main, last 2026-10-07 (22 days ago); 864
             contributors; 38 releases, latest 3.1.3 on 2026-02-19 (2 assets);
             4 open issues and pull requests
  Status     not archived; not a fork; main is protected; license BSD-3-Clause
             (GitHub); no security policy in the files
  API        6 requests, 52 of 60 left (resets 17:46 UTC), no token
             Stars, forks, followers and accounts can be bought or faked; these
             are indicators, not proof.
```

- **A local folder's remote is only a claim.** Whoever prepared the folder chose it.
  repovet therefore looks up the folder's HEAD commit in that repository (`Local` line).
  GitHub also finds commits that exist only in forks of the repository, so "found" is no
  proof either.
- **Requests:** usually 6 to 8 per scan: repository, owner, commits, contributors, latest
  release, default branch, a name search (only for descriptions of 20 or more
  characters), the local HEAD of a folder, the star times (one or two requests, only for
  50 to 200 stars) and the repository a manifest names (only if it belongs to another
  owner). Counts come from one-item pages, so large repositories cost the same. Each scan
  stops after 25 requests without a token (100 with one) and after 60 seconds.
- **Rate limit:** without a token GitHub allows 60 requests per hour and IP address.
  repovet checks the remaining requests first (that check is free), waits at most 20
  seconds when GitHub asks for a short pause, and otherwise stops and lists what was not
  checked under "Not checked", with the time the limit resets. The scan itself continues;
  the exit code does not change.
- **Token (optional):** set `GITHUB_TOKEN` or `GH_TOKEN` to raise the limit to 5,000
  requests per hour. A fine-grained token without any permissions is enough, because only
  public data is read. The token is sent only to `https://api.github.com`, never on the
  command line, and never appears in reports, error messages or `-v` output. The report
  says only whether a token was used and from which variable.

  ```
  # Bash
  GITHUB_TOKEN=github_pat_... uv run repovet scan https://github.com/pallets/flask

  # PowerShell
  $env:GITHUB_TOKEN = "github_pat_..."; uv run repovet scan https://github.com/pallets/flask
  ```
- **What is not used:** private repositories, GraphQL, the stargazer accounts themselves,
  and any cache (every scan asks again).
- **Limits of the indicators:** the name search looks at the five most starred
  repositories whose name contains the checked name; star times are only fetched for 50 to
  200 stars; only the latest release is looked at; manifests only in the root folder.
  Stars, accounts, dates and descriptions can all be faked.

The trust indicators (rules `RC-TRUST-*`) are listed in
[What is checked](checks.md#what-works-today).
