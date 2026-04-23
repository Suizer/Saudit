"""
WebPeas — terminal output module for SuizerAudit.
Organises findings into colour-coded sections at scan end, LinPEAS style.
"""

from collections import defaultdict
from contextlib import suppress
from datetime import datetime

from bbot.modules.output.base import BaseOutputModule

# ── ANSI palette ──────────────────────────────────────────────────────────────
R   = "\033[0m"          # reset
RED = "\033[1;31m"
YEL = "\033[1;33m"
GRN = "\033[1;32m"
CYN = "\033[1;36m"
BLU = "\033[1;34m"
WHT = "\033[1;37m"
DIM = "\033[2m"

SEV_COLOR = {
    "critical": RED,
    "high":     RED,
    "medium":   YEL,
    "low":      GRN,
    "info":     CYN,
    "unknown":  DIM,
}

SEV_ICON = {
    "critical": f"{RED}[!!!]{R}",
    "high":     f"{RED}[ ! ]{R}",
    "medium":   f"{YEL}[ ~ ]{R}",
    "low":      f"{GRN}[ + ]{R}",
    "info":     f"{CYN}[ > ]{R}",
    "unknown":  f"{DIM}[ ? ]{R}",
}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

BANNER = f"""{RED}
  ███████╗ █████╗ ██╗   ██╗██████╗██╗████████╗
  ██╔════╝██╔══██╗██║   ██║╚══██╔╝██║╚══██╔══╝
  ███████╗███████║██║   ██║   ██║ ██║   ██║
  ╚════██║██╔══██║██║   ██║   ██║ ██║   ██║
  ███████║██║  ██║╚██████╔╝██████╗██║   ██║
  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚═╝   ╚═╝{R}
  {DIM}SuizerAudit — Autonomous Web Recon{R}
"""


def _hdr(title: str) -> str:
    bar = "═" * (54 - len(title) - 2)
    return f"\n{BLU}══[ {WHT}{title}{BLU} ]{bar}{R}"


def _sev(f: dict) -> str:
    return f.get("severity", "unknown").lower()


def _sort(findings: list) -> list:
    return sorted(findings, key=lambda f: SEV_ORDER.get(_sev(f), 5))


class webpeas(BaseOutputModule):
    watched_events = ["FINDING", "VULNERABILITY", "TECHNOLOGY", "URL", "HTTP_RESPONSE"]
    meta = {
        "description": "LinPEAS-style terminal output — concise, colour-coded, section-grouped",
        "created_date": "2024-01-01",
        "author": "@suizer",
    }
    options = {}
    options_desc = {}

    async def setup(self):
        self._findings   = []          # FINDING / VULNERABILITY
        self._techs      = set()
        self._urls       = []          # confirmed live URLs
        self._js_stats   = defaultdict(int)   # type → count (from jsfuzzer tags)
        self._target     = str(self.scan.target)
        return True

    async def handle_event(self, event):
        if event.type == "TECHNOLOGY":
            data = event.data
            name = data.get("technology", "") if isinstance(data, dict) else str(data)
            if name:
                self._techs.add(name)
            return

        if event.type == "URL":
            self._urls.append(event.data)
            return

        if event.type == "HTTP_RESPONSE":
            return  # used only for counting, not stored

        # FINDING or VULNERABILITY
        tags = set(getattr(event, "tags", []) or [])
        data = event.data
        if not isinstance(data, dict):
            return

        if event.type == "VULNERABILITY":
            sev   = data.get("severity", "medium").lower()
            title = data.get("name", data.get("description", "Vulnerability"))
        else:
            sev   = "info"
            title = data.get("description", "Finding")
            for tag in tags:
                if tag.startswith("severity-"):
                    sev = tag.split("severity-", 1)[1]
                    break

        # Track JS findings separately for the summary line
        if "jsfuzzer" in tags:
            ftype = "endpoint" if "endpoint" in tags else \
                    "secret"   if "secret"   in tags else \
                    "entropy"  if "entropy"  in tags else "other"
            self._js_stats[ftype] += 1

        source = "jsfuzzer" if "jsfuzzer" in tags else \
                 "mendix"   if "mendix-recon" in tags else \
                 event.module if hasattr(event, "module") else "saudit"

        self._findings.append({
            "severity": sev,
            "title":    str(title)[:120],
            "url":      data.get("url", ""),
            "source":   source,
            "tags":     tags,
        })

    async def report(self):
        lines = [BANNER]
        lines.append(f"  {WHT}Target :{R} {self._target}")
        lines.append(f"  {WHT}Date   :{R} {datetime.now().strftime('%Y-%m-%d %H:%M')}")

        # ── Infrastructure ────────────────────────────────────────────────
        lines.append(_hdr("INFRASTRUCTURE"))
        if self._urls:
            for url in sorted(set(self._urls))[:20]:
                lines.append(f"  {GRN}[+]{R} {url}")
        else:
            lines.append(f"  {DIM}No live URLs confirmed{R}")

        # ── Technologies ──────────────────────────────────────────────────
        lines.append(_hdr("TECHNOLOGIES DETECTED"))
        if self._techs:
            chunks = [f"{CYN}[+]{R} {t}" for t in sorted(self._techs)]
            lines.append("  " + "   ".join(chunks))
        else:
            lines.append(f"  {DIM}None detected{R}")

        # ── JS Analysis summary ───────────────────────────────────────────
        js_findings = [f for f in self._findings if "jsfuzzer" in f["tags"]]
        lines.append(_hdr("JAVASCRIPT ANALYSIS"))
        if js_findings:
            lines.append(
                f"  {CYN}[>]{R} {len(js_findings)} JS findings — "
                f"secrets: {self._js_stats['secret']+self._js_stats['entropy']}  "
                f"endpoints: {self._js_stats['endpoint']}  "
                f"other: {self._js_stats['other']}"
            )
            for f in _sort(js_findings)[:10]:
                icon = SEV_ICON.get(_sev(f), SEV_ICON["unknown"])
                lines.append(f"  {icon} {f['title'][:100]}")
            if len(js_findings) > 10:
                lines.append(f"  {DIM}  … and {len(js_findings)-10} more — see js_analysis/ folder{R}")
        else:
            lines.append(f"  {DIM}No JS findings (jsfuzzer not active or no .js files found){R}")

        # ── Vulnerabilities & Findings ────────────────────────────────────
        other = [f for f in self._findings if "jsfuzzer" not in f["tags"]]
        lines.append(_hdr("VULNERABILITIES & FINDINGS"))
        if other:
            for f in _sort(other):
                icon  = SEV_ICON.get(_sev(f), SEV_ICON["unknown"])
                src   = f"{DIM}[{f['source']}]{R}"
                url   = f"  {DIM}→ {f['url']}{R}" if f["url"] else ""
                lines.append(f"  {icon} {src} {f['title']}")
                if url:
                    lines.append(url)
        else:
            lines.append(f"  {GRN}[+]{R} No additional findings")

        # ── Summary counter ───────────────────────────────────────────────
        all_f = self._findings
        counts = defaultdict(int)
        for f in all_f:
            counts[_sev(f)] += 1

        lines.append(_hdr("SUMMARY"))
        summary_parts = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            if counts[sev]:
                col = SEV_COLOR.get(sev, "")
                summary_parts.append(f"{col}{sev.upper()}: {counts[sev]}{R}")
        lines.append("  " + "   ".join(summary_parts) if summary_parts else f"  {GRN}Clean — no findings{R}")
        lines.append(f"\n{DIM}{'═'*58}{R}\n")

        output = "\n".join(lines)
        with suppress(Exception):
            self._stdout(output)

    def _stdout(self, text: str):
        print(text, flush=True)
