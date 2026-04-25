import html as _html
from contextlib import suppress
from collections import defaultdict
from datetime import datetime, timezone

from saudit.modules.output.base import BaseOutputModule


_SEV_COLOR = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#20c997",
    "info": "#6c757d",
    "unknown": "#6c757d",
}

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.5; }
h1 { font-size: 1.6rem; font-weight: 700; color: #58a6ff; }
h2 { font-size: 1.1rem; font-weight: 600; color: #8b949e; margin-bottom: .5rem; }
a { color: #58a6ff; text-decoration: none; word-break: break-all; }
a:hover { text-decoration: underline; }
.container { max-width: 1100px; margin: 0 auto; padding: 1.5rem; }
.header { background: #161b22; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem;
          border: 1px solid #30363d; display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; }
.header h1 { flex: 1; }
.meta { font-size: .8rem; color: #8b949e; }
.section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 1rem; }
details > summary { list-style: none; }
details > summary::-webkit-details-marker { display: none; }
.section-header { display: flex; align-items: center; gap: .75rem; padding: 1rem 1.25rem;
                  cursor: pointer; user-select: none; border-radius: 8px; }
.section-header:hover { background: #1c2128; }
.arrow { transition: transform .2s; color: #8b949e; font-size: .75rem; }
details[open] .arrow { transform: rotate(90deg); }
.badge { font-size: .75rem; font-weight: 700; padding: .15rem .55rem; border-radius: 12px;
         background: #21262d; color: #8b949e; }
.badge-count { background: #21262d; color: #58a6ff; }
.section-body { padding: 0 1.25rem 1.25rem; }
table { width: 100%; border-collapse: collapse; font-size: .85rem; }
th { text-align: left; padding: .5rem .75rem; color: #8b949e; border-bottom: 1px solid #30363d;
     font-weight: 600; font-size: .75rem; text-transform: uppercase; letter-spacing: .05em; }
td { padding: .5rem .75rem; border-bottom: 1px solid #21262d; vertical-align: top; }
tr:last-child td { border-bottom: none; }
.sev { font-size: .7rem; font-weight: 700; padding: .15rem .5rem; border-radius: 4px;
       text-transform: uppercase; white-space: nowrap; }
.url-list { list-style: none; max-height: 300px; overflow-y: auto; }
.url-list li { padding: .25rem 0; border-bottom: 1px solid #21262d; font-size: .85rem; }
.url-list li:last-child { border-bottom: none; }
.tech-grid { display: flex; flex-wrap: wrap; gap: .5rem; }
.tech-pill { background: #21262d; border: 1px solid #30363d; border-radius: 20px;
             padding: .25rem .75rem; font-size: .8rem; color: #c9d1d9; }
.waf-banner { background: #161b22; border: 1px solid #f0883e; border-radius: 6px;
              padding: .75rem 1rem; color: #f0883e; font-weight: 600; }
.secret-row td { background: rgba(220,53,69,.06); }
.empty { color: #8b949e; font-style: italic; font-size: .9rem; padding: .5rem 0; }
"""


def _sev_badge(severity: str) -> str:
    color = _SEV_COLOR.get(severity.lower(), "#6c757d")
    return f'<span class="sev" style="background:{color}22;color:{color}">{_html.escape(severity.upper())}</span>'


def _section(title: str, icon: str, items_count: int, body: str, open_by_default: bool = False) -> str:
    open_attr = " open" if open_by_default else ""
    return f"""
<div class="section">
  <details{open_attr}>
    <summary class="section-header">
      <span class="arrow">▶</span>
      <span style="font-size:1.2rem">{icon}</span>
      <span style="font-weight:600;color:#c9d1d9">{_html.escape(title)}</span>
      <span class="badge badge-count">{items_count}</span>
    </summary>
    <div class="section-body">{body}</div>
  </details>
</div>"""


class html_report(BaseOutputModule):
    watched_events = ["URL", "TECHNOLOGY", "FINDING", "VULNERABILITY", "WAF"]
    meta = {
        "description": "Self-contained HTML recon report with collapsible sections",
        "created_date": "2025-01-01",
        "author": "@suizer",
    }
    options = {"output_file": ""}
    options_desc = {"output_file": "Output file path (default: html_report.html)"}

    async def setup(self):
        self._prep_output_dir("html_report.html")
        self._urls = []
        self._techs = []
        self._waf = []
        self._findings = []
        return True

    async def handle_event(self, event):
        tags = set(getattr(event, "tags", []) or [])

        if event.type == "URL":
            if "status-404" not in tags:
                self._urls.append(event.data)

        elif event.type == "TECHNOLOGY":
            d = event.data
            name = d if isinstance(d, str) else d.get("technology", str(d))
            self._techs.append(name)

        elif event.type == "WAF":
            self._waf.append(str(event.data))

        elif event.type in ("FINDING", "VULNERABILITY"):
            if "status-404" in tags:
                return
            d = event.data if isinstance(event.data, dict) else {"description": str(event.data)}
            rec = dict(d)
            rec["_type"] = event.type
            rec["_severity"] = rec.get("severity", "info").lower()
            rec["_is_secret"] = "secret" in tags
            self._findings.append(rec)

    async def cleanup(self):
        if getattr(self, "_file", None) is not None:
            with suppress(Exception):
                self.file.close()

    async def report(self):
        if self.file is None:
            return
        self.file.write(self._build())
        self.file.flush()
        self.info(f"HTML report saved to {self.output_file}")

    # ── builders ──────────────────────────────────────────────────────────────

    def _build(self) -> str:
        seeds = list(getattr(self.scan.target, "seeds", {}).inputs or [])
        target_str = str(seeds[0]) if seeds else "Unknown target"
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        sections = []

        # WAF
        if self._waf:
            body = "".join(f'<div class="waf-banner">🛡 {_html.escape(w)}</div>' for w in sorted(set(self._waf)))
        else:
            body = '<p class="empty">No WAF detected</p>'
        sections.append(_section("WAF Detection", "🛡", len(self._waf), body, open_by_default=bool(self._waf)))

        # Technologies
        unique_techs = sorted(set(self._techs))
        if unique_techs:
            pills = "".join(f'<span class="tech-pill">{_html.escape(t)}</span>' for t in unique_techs)
            body = f'<div class="tech-grid">{pills}</div>'
        else:
            body = '<p class="empty">No technologies detected</p>'
        sections.append(_section("Technologies", "🔧", len(unique_techs), body, open_by_default=bool(unique_techs)))

        # Findings / Vulnerabilities
        findings_body = self._build_findings()
        vuln_count = len(self._findings)
        sections.append(_section("Findings & Vulnerabilities", "🔍", vuln_count, findings_body, open_by_default=True))

        # URLs
        url_body = self._build_urls()
        sections.append(_section("Crawled URLs", "🌐", len(self._urls), url_body))

        sections_html = "\n".join(sections)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SuizerAudit — {_html.escape(target_str)}</title>
  <style>{_CSS}</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>SuizerAudit Report</h1>
    <div>
      <div class="meta">Target: <strong style="color:#c9d1d9">{_html.escape(target_str)}</strong></div>
      <div class="meta">Generated: {ts}</div>
    </div>
  </div>
  {sections_html}
</div>
</body>
</html>"""

    def _build_findings(self) -> str:
        if not self._findings:
            return '<p class="empty">No findings</p>'

        secrets = [f for f in self._findings if f.get("_is_secret")]
        rest = [f for f in self._findings if not f.get("_is_secret")]
        sorted_findings = secrets + sorted(rest, key=lambda f: _SEV_ORDER.get(f.get("_severity", "info"), 5))

        rows = []
        for f in sorted_findings:
            sev = f.get("_severity", "info")
            badge = _sev_badge(sev)
            desc = _html.escape(str(f.get("description", f.get("name", ""))))
            url = f.get("url", "")
            url_cell = f'<a href="{_html.escape(url)}">{_html.escape(url)}</a>' if url else "—"
            secret_class = ' class="secret-row"' if f.get("_is_secret") else ""
            rows.append(f"<tr{secret_class}><td>{badge}</td><td>{desc}</td><td>{url_cell}</td></tr>")

        return f"""<table>
  <thead><tr><th>Severity</th><th>Description</th><th>URL</th></tr></thead>
  <tbody>{''.join(rows)}</tbody>
</table>"""

    def _build_urls(self) -> str:
        if not self._urls:
            return '<p class="empty">No URLs discovered</p>'
        items = "".join(
            f'<li><a href="{_html.escape(u)}" target="_blank">{_html.escape(u)}</a></li>'
            for u in sorted(set(self._urls))
        )
        return f'<ul class="url-list">{items}</ul>'
