import re
import asyncio
from urllib.parse import urlparse

from saudit.modules.base import BaseModule

# 5 parámetros más comunes — cubre el 90% de casos reales
TEST_PARAMS = ["id", "q", "search", "name", "filter"]

# Payloads SQLi mínimos — solo error-based, sin time-based
SQLI_PAYLOADS = [
    ("single_quote",  "'"),
    ("double_quote",  "\""),
    ("comment_dash",  "' --"),
    ("or_true",       "' OR '1'='1"),
]

# Strings de error SQL conocidos
SQL_ERROR_PATTERNS = re.compile(
    r"(syntax error|sql syntax|mysql_fetch|ORA-\d{4,5}|pg_exec|SQLiteException"
    r"|sqlite3\.|unclosed quotation|sql command not properly ended"
    r"|error in your sql syntax|unknown column|unterminated string"
    r"|Microsoft OLE DB|ADODB\.|Jet Database Engine|division by zero"
    r"|supplied argument is not a valid MySQL|Warning.*mysql_"
    r"|SequelizeDatabaseError|TypeORMError|SQLSTATE)",
    re.IGNORECASE,
)

_MATCH_RE = re.compile(r"Match:\s*(/[^\s|]{2,})")

# Endpoints que claramente no son API REST — skip rápido
_SKIP_EXTENSIONS = re.compile(r"\.(js|css|png|jpg|gif|svg|ico|woff|ttf|map)$", re.IGNORECASE)


def _base_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _extract_endpoint(description: str) -> str | None:
    m = _MATCH_RE.search(description)
    return m.group(1).rstrip("/") if m else None


class api_sqli_probe(BaseModule):
    """
    Probes API endpoints discovered by jsfuzzer with minimal SQLi payloads.
    Error-based only — no time-based delays. Skips auth-protected endpoints.
    Public endpoints only; pass auth_token in config for authenticated probing.
    """

    watched_events = ["FINDING"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "aggressive", "web-thorough"]
    meta = {
        "description": "Probe jsfuzzer-discovered API endpoints for SQL injection (error-based, public endpoints)",
        "author": "@suizer",
        "created_date": "2026-04-23",
    }
    options = {
        "test_post": True,
        "auth_token": "",
    }
    options_desc = {
        "test_post":   "Also probe endpoints with POST JSON body payloads",
        "auth_token":  "Bearer token for authenticated endpoints (e.g. 'Bearer eyJ...')",
    }

    in_scope_only = True

    async def setup(self):
        self._seen_endpoints = set()
        self._test_post = self.config.get("test_post", True)
        token = self.config.get("auth_token", "").strip()
        self._auth_headers = {"Authorization": token} if token else {}
        return True

    async def filter_event(self, event):
        tags = set(getattr(event, "tags", []) or [])
        if "jsfuzzer" not in tags:
            return False, "not a jsfuzzer finding"
        if "endpoint" not in tags:
            return False, "not an endpoint finding"
        return True, ""

    async def handle_event(self, event):
        data = event.data
        if not isinstance(data, dict):
            return

        description = data.get("description", "")
        js_url = data.get("url", "")

        endpoint_path = _extract_endpoint(description)
        if not endpoint_path:
            return

        # Skip static assets — no tiene sentido probar SQLi en un .js
        if _SKIP_EXTENSIONS.search(endpoint_path):
            return

        base = _base_url(js_url) if js_url else ""
        if not base:
            return

        endpoint_url = f"{base}{endpoint_path}"

        if endpoint_url in self._seen_endpoints:
            return
        self._seen_endpoints.add(endpoint_url)

        self.verbose(f"Probing {endpoint_url}")

        # ── Baseline ─────────────────────────────────────────────────────────
        baseline = await self.helpers.request(
            endpoint_url,
            headers=self._auth_headers,
            allow_redirects=True,
        )
        if baseline is None:
            return

        baseline_status = baseline.status_code
        baseline_text   = baseline.text

        # Skip inmediato si el endpoint requiere auth y no tenemos token
        if baseline_status in (401, 403) and not self._auth_headers:
            self.verbose(f"Skipping {endpoint_url} — requires auth ({baseline_status})")
            return

        # ── GET probes en paralelo ────────────────────────────────────────────
        async def _probe_get(param, payload_name, payload):
            url_probe = f"{endpoint_url}?{param}={payload}"
            resp = await self.helpers.request(
                url_probe,
                headers=self._auth_headers,
                allow_redirects=True,
            )
            if resp is None:
                return None
            return self._evaluate(
                resp, baseline_status, baseline_text,
                method="GET", param=param, payload=payload_name,
                url=url_probe, host=event.host,
            )

        combos = [
            (param, payload_name, payload)
            for param in TEST_PARAMS
            for payload_name, payload in SQLI_PAYLOADS
        ]
        results = await asyncio.gather(*[_probe_get(*c) for c in combos])

        for finding in results:
            if finding:
                await self._emit(finding, event)
                return  # un finding por endpoint es suficiente

        # ── POST JSON probes ──────────────────────────────────────────────────
        if self._test_post:
            for payload_name, payload in SQLI_PAYLOADS[:2]:
                body = {p: payload for p in TEST_PARAMS}
                resp = await self.helpers.request(
                    endpoint_url,
                    method="POST",
                    json=body,
                    headers={"Content-Type": "application/json", **self._auth_headers},
                    allow_redirects=True,
                )
                if resp is None:
                    continue

                finding = self._evaluate(
                    resp, baseline_status, baseline_text,
                    method="POST", param="json_body", payload=payload_name,
                    url=endpoint_url, host=event.host,
                )
                if finding:
                    await self._emit(finding, event)
                    return

    def _evaluate(self, resp, baseline_status, baseline_text,
                  method, param, payload, url, host) -> dict | None:
        body   = resp.text or ""
        status = resp.status_code

        error_match = SQL_ERROR_PATTERNS.search(body)
        if error_match:
            return {
                "severity":  "high",
                "method":    method,
                "param":     param,
                "payload":   payload,
                "url":       url,
                "host":      str(host),
                "detection": "sql_error",
                "evidence":  error_match.group(0)[:120],
            }

        if baseline_status in range(200, 300) and status in range(500, 600):
            return {
                "severity":  "medium",
                "method":    method,
                "param":     param,
                "payload":   payload,
                "url":       url,
                "host":      str(host),
                "detection": "status_change",
                "evidence":  f"{baseline_status} → {status}",
            }

        if baseline_text and len(body) > 0:
            ratio = len(body) / max(len(baseline_text), 1)
            if ratio > 3.0 and status == baseline_status:
                return {
                    "severity":  "low",
                    "method":    method,
                    "param":     param,
                    "payload":   payload,
                    "url":       url,
                    "host":      str(host),
                    "detection": "response_size_anomaly",
                    "evidence":  f"body x{ratio:.1f} baseline size",
                }

        return None

    async def _emit(self, finding: dict, parent_event):
        sev      = finding["severity"]
        method   = finding["method"]
        param    = finding["param"]
        payload  = finding["payload"]
        url      = finding["url"]
        detect   = finding["detection"]
        evidence = finding.get("evidence", "")

        desc = (
            f"Possible SQL Injection [{sev.upper()}] — {method} {url} "
            f"param={param} payload={payload} "
            f"detection={detect} evidence={evidence}"
        )

        event_type = "VULNERABILITY" if sev == "high" else "FINDING"

        await self.emit_event(
            {
                "host":        finding["host"],
                "url":         url,
                "description": desc,
                "severity":    sev,
                "name":        "SQL Injection (error-based probe)",
            },
            event_type,
            parent=parent_event,
            tags=[
                "api_sqli_probe",
                f"severity-{sev}",
                f"detection-{detect}",
            ],
            context=f"{{module}} found possible SQLi at {url} ({detect})",
        )
