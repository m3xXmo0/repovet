"""HTML report: one self-contained file that works offline.

No JavaScript and no external resources: the Content-Security-Policy allows nothing but
the inline style sheet. Findings are grouped like in the text report and collapse with
``<details>``. Every string from the repository is sanitized first and then
HTML-escaped, so neither markup nor invisible characters get through.
"""

import html
from collections.abc import Sequence

from repovet.models import CATEGORIES, CoverageItem, Finding, ScanResult, Severity
from repovet.report.common import (
    Group,
    disclaimer,
    group_findings,
    no_findings,
    severity_counts,
    top_groups,
    visible_findings,
)
from repovet.report.sanitize import sanitize, sanitize_path

CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; "
    "form-action 'none'"
)

STYLE = """
:root {
  color-scheme: light dark;
  --bg: #ffffff; --fg: #1f2328; --muted: #59636e; --line: #d1d9e0; --panel: #f6f8fa;
  --code: #eff2f5; --critical: #a40e26; --high: #cf222e; --medium: #9a6700;
  --low: #0969da; --info: #59636e; --badge-fg: #ffffff;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117; --fg: #e6edf3; --muted: #9198a1; --line: #3d444d; --panel: #151b23;
    --code: #1f2630; --critical: #ff7b72; --high: #f85149; --medium: #d29922;
    --low: #58a6ff; --info: #9198a1; --badge-fg: #0d1117;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
main { max-width: 980px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 24px; margin: 0 0 4px; }
h2 { font-size: 18px; margin: 32px 0 12px; border-bottom: 1px solid var(--line);
  padding-bottom: 6px; }
.meta, .note, .muted { color: var(--muted); }
.meta { margin: 0 0 4px; overflow-wrap: anywhere; }
code, pre { font: 13px/1.45 ui-monospace, SFMono-Regular, Consolas, Menlo, monospace; }
code { background: var(--code); padding: 1px 4px; border-radius: 4px; }
pre { background: var(--code); padding: 8px 10px; border-radius: 6px; margin: 4px 0 8px;
  white-space: pre-wrap; overflow-wrap: anywhere; }
.summary { background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
  padding: 12px 16px; margin-top: 16px; }
.counts { display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 8px; padding: 0;
  list-style: none; }
.badge { display: inline-block; min-width: 72px; text-align: center; font-size: 12px;
  font-weight: 700; letter-spacing: .03em; border-radius: 12px; padding: 1px 8px;
  color: var(--badge-fg); background: var(--info); }
.zero { opacity: .45; }
.critical .badge, .badge.critical { background: var(--critical); }
.high .badge, .badge.high { background: var(--high); }
.medium .badge, .badge.medium { background: var(--medium); }
.low .badge, .badge.low { background: var(--low); }
.info .badge, .badge.info { background: var(--info); }
.first { margin: 4px 0 0; padding-left: 22px; }
.first li { margin: 2px 0; }
details { border: 1px solid var(--line); border-left-width: 4px; border-radius: 6px;
  margin: 8px 0; background: var(--bg); }
details.critical { border-left-color: var(--critical); }
details.high { border-left-color: var(--high); }
details.medium { border-left-color: var(--medium); }
details.low { border-left-color: var(--low); }
details.info { border-left-color: var(--info); }
summary { cursor: pointer; padding: 8px 12px; overflow-wrap: anywhere; }
summary .place { color: var(--muted); }
.body { padding: 0 12px 10px 16px; }
.label { display: inline-block; font-size: 12px; border: 1px solid var(--line);
  border-radius: 10px; padding: 0 6px; color: var(--muted); margin-left: 4px; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; margin: 8px 0; }
dt { font-weight: 600; }
dd { margin: 0; overflow-wrap: anywhere; }
ul.places { margin: 4px 0; padding-left: 20px; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; vertical-align: top; padding: 4px 8px;
  border-bottom: 1px solid var(--line); overflow-wrap: anywhere; }
th { width: 130px; color: var(--muted); font-weight: 600; }
.notice { margin-top: 32px; padding: 12px 16px; border-radius: 8px;
  border: 1px solid var(--line); background: var(--panel); }
"""


def _text(value: str, max_length: int | None = None) -> str:
    """Repository or report text, made visible (sanitize) and then HTML-escaped."""
    return html.escape(sanitize(value, max_length), quote=True)


def _place(finding: Finding) -> str:
    loc = finding.location
    if loc is None:
        place = "(repository)"
    else:
        path = html.escape(sanitize_path(loc.path), quote=True)
        place = f"{path}:{loc.line}" if loc.line else path
    label = f' <span class="label">{_text(finding.context)}</span>' if finding.context else ""
    return f"<code>{place}</code>{label}"


def _badge(severity: Severity) -> str:
    return f'<span class="badge {severity.label}">{severity.label.upper()}</span>'


def _reference(url: str) -> str:
    shown = _text(url)
    if url.startswith("https://"):
        return f'<a href="{shown}" rel="noreferrer noopener">{shown}</a>'
    return shown


def _group(group: Group, anchor: str) -> list[str]:
    first = group.first
    sev = first.severity.label
    where = _place(first) if len(group.findings) == 1 else f"{len(group.findings)} places"
    opened = " open" if group.explained else ""
    out = [
        f'<details id="{anchor}" class="{sev}"{opened}>',
        f"<summary>{_badge(first.severity)} <code>{first.rule_id}</code> "
        f'<span class="place">{where}</span> &mdash; {_text(first.message)}</summary>',
        '<div class="body"><dl>',
        f"<dt>Rule</dt><dd>{_text(first.title)}</dd>",
        f"<dt>Confidence</dt><dd>{first.confidence.label}</dd>",
        "</dl>",
        '<ul class="places">',
    ]
    for finding in group.findings:
        evidence = f"<pre>&gt; {_text(finding.evidence, 160)}</pre>" if finding.evidence else ""
        out.append(f"<li>{_place(finding)}{evidence}</li>")
    out += [
        "</ul>",
        f"<dl><dt>Why</dt><dd>{_text(first.rationale)}</dd>",
        f"<dt>Do</dt><dd>{_text(first.recommendation)}</dd>",
    ]
    if first.references:
        links = "<br>".join(_reference(r) for r in first.references)
        out.append(f"<dt>See</dt><dd>{links}</dd>")
    out.append("</dl></div></details>")
    return out


def _summary(
    visible: Sequence[Finding], groups: Sequence[Group], anchors: dict[int, str]
) -> list[str]:
    out = ['<section class="summary" aria-label="Summary">', '<ul class="counts">']
    for severity, count in severity_counts(visible):
        zero = " zero" if not count else ""
        out.append(f'<li class="{severity.label}{zero}">{_badge(severity)} {count}</li>')
    out.append("</ul>")
    first = top_groups(groups)
    if first:
        out.append('<strong>Look at these first</strong><ol class="first">')
        for group in first:
            f = group.first
            where = _place(f) if len(group.findings) == 1 else f"{len(group.findings)} places"
            out.append(
                f'<li>{_badge(f.severity)} <a href="#{anchors[id(group)]}">'
                f"<code>{f.rule_id}</code></a> {where} &mdash; {_text(f.title)}</li>"
            )
        out.append("</ol>")
    elif visible:
        out.append('<p class="muted">Only info findings: facts worth knowing, no warnings.</p>')
    out.append("</section>")
    return out


def _coverage(item: CoverageItem) -> str:
    text = _text(item.reason)
    if item.sample:
        sample = ", ".join(
            f"<code>{html.escape(sanitize_path(p), quote=True)}</code>" for p in item.sample
        )
        more = ", &hellip;" if item.count > len(item.sample) else ""
        return f"<li>{text} ({item.count}): {sample}{more}</li>"
    return f"<li>{text} ({item.count})</li>" if item.count > 1 else f"<li>{text}</li>"


def render(result: ScanResult, *, min_severity: Severity = Severity.INFO) -> str:
    visible = visible_findings(result, min_severity)
    hidden = len(result.findings) - len(visible)
    groups = group_findings(visible)
    anchors = {id(g): f"g{n}" for n, g in enumerate(groups, 1)}
    online = "online" if result.online else "offline"
    started = result.started.isoformat(timespec="seconds").replace("+00:00", "Z")
    out = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">',
        '<meta name="referrer" content="no-referrer">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>repovet report: {html.escape(sanitize_path(result.target), quote=True)}</title>",
        f"<style>{STYLE}</style>",
        "</head>",
        "<body><main>",
        "<h1>repovet report</h1>",
        f'<p class="meta">{_text(result.mode)} <code>'
        f"{html.escape(sanitize_path(result.target), quote=True)}</code></p>",
        f'<p class="meta">repovet {_text(result.tool_version)} &middot; {online} &middot; '
        f"{result.files_scanned:,} files &middot; {result.rules_loaded} rules &middot; "
        f"{started}</p>",
        '<p class="note">Text in <code>code</code> and quoted blocks comes from the checked '
        "repository: it is untrusted and shown escaped.</p>",
    ]
    out += _summary(visible, groups, anchors)
    if not visible:
        out.append(f"<p>{_text(no_findings(result.rules_loaded))}</p>")
    for category in CATEGORIES:
        in_category = [g for g in groups if g.first.category == category]
        if not in_category:
            continue
        found = [f for g in in_category for f in g.findings]
        counts = " &middot; ".join(f"{n} {s.label}" for s, n in severity_counts(found) if n)
        out.append(f'<h2>{category.capitalize()} <span class="muted">{counts}</span></h2>')
        for group in in_category:
            out += _group(group, anchors[id(group)])
    if hidden:
        out.append(
            f"<p class=\"muted\">{hidden} finding(s) below '{min_severity.label}' not shown "
            "(--min-severity).</p>"
        )
    for category in CATEGORIES:
        lines = result.summaries.get(category)
        if not lines:
            continue
        note = '<span class="muted">facts, not findings</span>'
        out.append(f"<h2>{category.capitalize()} profile {note}</h2>")
        out.append("<table>")
        for label, text in lines:
            out.append(f"<tr><th>{_text(label)}</th><td>{_text(text)}</td></tr>")
        out.append("</table>")
    out.append("<h2>Not checked</h2>")
    out.append("<ul>")
    out += [_coverage(item) for item in result.coverage] or ["<li>nothing recorded</li>"]
    out.append("</ul>")
    notice = (
        " ".join(disclaimer(result.rules_loaded)) if visible else no_findings(result.rules_loaded)
    )
    out.append(f'<p class="notice">{_text(notice)}</p>')
    out.append("</main></body></html>")
    return "\n".join(out) + "\n"
