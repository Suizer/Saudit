from __future__ import annotations

import json
from pathlib import Path

from saudit.modules.base import BaseModule

# Event types to re-inject for follow-up scans.
# - URL         → scanner crawls known endpoints without starting from scratch
# - TECHNOLOGY  → activates technology-conditional modules (wpscan, mendix_recon, etc.)
# - WAF         → provides WAF context to output modules
# - FINDING     → ai_review and html_report can re-analyse without re-scanning
# - VULNERABILITY → same as above
_REINJECT_TYPES = {"URL", "TECHNOLOGY", "WAF", "FINDING", "VULNERABILITY"}


class from_report(BaseModule):
    watched_events = ["SCAN"]
    produced_events = ["URL", "TECHNOLOGY", "WAF", "FINDING", "VULNERABILITY"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Re-seed a scan from a previous scan's NDJSON output (--from-report)",
        "created_date": "2025-01-01",
        "author": "@suizer",
    }
    options = {"report_file": ""}
    options_desc = {
        "report_file": "Path to the output.json (NDJSON) from a previous saudit scan"
    }

    # Accept the root SCAN event regardless of scope distance
    scope_distance_modifier = None

    async def setup(self):
        report_file = self.config.get("report_file", "")
        if not report_file:
            return None, "report_file not set — module inactive"

        self._report_path = Path(report_file).expanduser().resolve()
        if not self._report_path.is_file():
            return False, f"Report file not found: {self._report_path}"

        return True

    async def handle_event(self, event):
        counts = {t: 0 for t in _REINJECT_TYPES}

        try:
            raw = self._report_path.read_text(encoding="utf-8")
        except Exception as e:
            self.warning(f"Could not read report file: {e}")
            return

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            event_type = entry.get("type", "")
            if event_type not in _REINJECT_TYPES:
                continue

            data = entry.get("data")
            if not data:
                continue

            tags = set(entry.get("tags", []))
            tags.add("from-initial-scan")

            await self.emit_event(
                data,
                event_type,
                parent=event,
                tags=tags,
                context=f"{{module}} re-injected {{event.type}} from previous scan",
            )
            counts[event_type] += 1

        parts = [f"{v} {k}" for k, v in counts.items() if v]
        self.info(f"Re-injected from {self._report_path.name}: {', '.join(parts) or 'nothing'}")
