# Security model

- **Nothing from the checked repository is executed:** no scripts, hooks, builds, package
  managers or imports. Python files are only parsed with `ast.parse`; YAML is only read
  with a safe loader with size and alias limits. Ruff rules (`banned-api`, flake8-bandit)
  and a self-check test forbid `subprocess`, `os.system`, `eval`, `exec`, `pickle` and
  similar in repovet's own code.
- **Offline analysis:** the analysis of files and history makes no network connections.
  There are only two: for a URL target the HTTPS download from github.com (TLS verified, no
  Git configuration, credential helpers or stored passwords are used), and for the trust
  area HTTPS requests to `api.github.com` only (no other host, no redirect elsewhere, at
  most 1 MiB per answer, a fixed request budget per scan). `--offline` switches the API
  off; a local folder with `--offline` makes no connection at all. The test suite blocks
  sockets to make sure of that; API tests use recorded answers, and the clone tests use a
  local Git server on 127.0.0.1 only.
- **Read-only:** files are only opened for reading; nothing in the checked folder is
  changed. Symlinks, junctions and reparse points are not followed. Inside `.git/`, only
  `config`, `hooks/*` and `info/attributes` are read, as plain files.
- **No `git` binary:** repovet never calls `git`, so Git configuration in the checked
  repository (for example `core.fsmonitor`, filters or pagers) can never run. GitHub URLs
  are fetched with [dulwich](https://www.dulwich.io/), a pure-Python Git implementation:
  only the pack file is downloaded into a fresh temporary folder (no working tree, refs,
  hooks, submodules, LFS or filters), and files are read from the Git objects in memory.
  Object sizes are checked before anything is unpacked, so a small download cannot inflate
  into gigabytes. The folder is deleted after the scan.

- **`repovet clone` writes only what was checked:** the working tree comes from the Git
  objects of the scan (no second download), every path is validated before the first
  file is written (no `.git` in any spelling, no `..`, no absolute paths, Windows device
  names, alternate data streams or case collisions; one bad path stops the whole clone),
  files are created new and never through a link, symbolic links and submodules are not
  created, and no hooks, filters or LFS run. The `.git` folder gets a fixed, minimal
  configuration and no hooks. A partly written clone is removed on any error.

Found a way to break one of these guarantees? Please report it privately, as described in
[SECURITY.md](../SECURITY.md).
