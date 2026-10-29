# Data sources

Data files that repocheck ships as package data. They are read offline; repocheck never
downloads or updates them at run time.

## pypi-top.txt

- Content: the 15,000 most downloaded PyPI projects of the last 30 days, most popular
  first, names normalized per PEP 503. Names only, no download counts.
- Source: <https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json>
  (project <https://github.com/hugovk/top-pypi-packages>), "last_update" 2026-10-01,
  built from the public PyPI download statistics. Downloaded 2026-10-29.
- License: the repository states no license. Only package names and their order are
  used here: facts from the public PyPI index, not creative content. To be confirmed
  before a public release.

## npm-top.txt

- Content: the most downloaded npm packages (15,913 names), most popular first.
  Names only.
- Source: npm-high-impact 1.13.0, file `lib/top-download.js`
  (<https://github.com/wooorm/npm-high-impact>), downloaded from unpkg on 2026-10-29.
  The JavaScript file was only read as text to extract the names.
- License: MIT, Copyright (c) Titus Wormer.

## Use

`engine/checks/dependency.py` (check type `dependency`, mode `typosquat`) loads both
lists. A dependency is reported when its name is not on the list itself but is one or
two edits away from a name in the top ranks (rules RC-DEP-001 to 003).

## Updating

Download both files into an empty folder, extract the names as above (the npm file is a
JavaScript module: parse it as text, never run it), keep the header comments, and note
the new date and version here. Then run the dependency rule cases and the corpus test.
