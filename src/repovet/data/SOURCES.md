# Data sources

Data files that repovet ships as package data. They are read offline; repovet never
downloads or updates them at run time.

## pypi-top.txt

- Content: the 15,000 most downloaded PyPI projects of the last 30 days, most popular
  first, names normalized per PEP 503. Names only, no download counts.
- Source: "top-pypi-packages" by Hugo van Kemenade,
  <https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json>
  (project <https://github.com/hugovk/top-pypi-packages>, DOI via
  <https://zenodo.org/badge/latestdoi/116806538>), "last_update" 2026-10-01, built from
  the public PyPI download statistics. Downloaded 2026-10-29.
- License: Creative Commons Attribution 4.0 International (CC BY 4.0),
  <https://creativecommons.org/licenses/by/4.0/>, as stated by the author in
  <https://github.com/hugovk/top-pypi-packages/issues/78>.
- Changes: only the project names are kept (no download counts), cut to the first
  15,000 and normalized per PEP 503.

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

## License texts

npm-top.txt is derived from npm-high-impact, which is distributed under this license:

```
(The MIT License)

Copyright (c) Titus Wormer <tituswormer@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

pypi-top.txt is used under CC BY 4.0; the license text is at
<https://creativecommons.org/licenses/by/4.0/legalcode>.
