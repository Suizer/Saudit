from __future__ import annotations

import re
import asyncio
import secrets
from urllib.parse import urlparse

from saudit.modules.base import BaseModule

# Parámetros que suelen existir pero no aparecen en el JS
HIDDEN_PARAMS = [
    "debug", "callback", "redirect", "next", "format",
    "output", "token", "admin", "test", "lang",
]

# Parámetros comunes en APIs REST (fallback cuando no hay spec)
COMMON_PARAMS = ["id", "q", "search", "name", "filter"]

SQL_ERROR_RE = re.compile(
    r"(syntax error|sql syntax|mysql_fetch|ORA-\d{4,5}|pg_exec|SQLiteException"
    r"|sqlite3\.|unclosed quotation|sql command not properly ended"
    r"|error in your sql syntax|unknown column|unterminated string"
    r"|Microsoft OLE DB|ADODB\.|Jet Database Engine"
    r"|supplied argument is not a valid MySQL|Warning.*mysql_"
    r"|SequelizeDatabaseError|TypeORMError|SQLSTATE)",
    re.IGNORECASE,
)

# WAF headers present in response → slow-mode needed
_WAF_RESP_HEADERS = frozenset({"cf-ray", "x-sucuri-id", "x-fw-server", "x-protected-by"})

_MATCH_RE  = re.compile(r"Match:\s*(/[^\s|]{2,})")
_PARAMS_RE = re.compile(r"Params:\s*([^\|]+)")
_METHOD_RE = re.compile(r"Swagger\s+(GET|POST|PUT|PATCH|DELETE)")
_SKIP_EXT  = re.compile(r"\.(js|css|png|jpg|gif|svg|ico|woff|ttf|map)$", re.I)

POST_METHODS = {"POST", "PUT", "PATCH"}

# SSTI canary: server evaluates {_SSTI_A*_SSTI_A} → _SSTI_RESULT appears in body
_SSTI_A      = 337
_SSTI_RESULT = str(_SSTI_A * _SSTI_A)  # "113569"


def _base_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _extract_endpoint(description: str) -> str | None:
    m = _MATCH_RE.search(description)
    return m.group(1).rstrip("/") if m else None


def _extract_swagger_params(event_data: dict, description: str) -> list[str]:
    params = event_data.get("_swagger_params")
    if params:
        return params
    m = _PARAMS_RE.search(description)
    if m:
        return [p.strip() for p in m.group(1).split(",") if p.strip()]
    return []


def _extract_method(event_data: dict, description: str) -> str:
    method = event_data.get("_swagger_method")
    if method:
        return method
    m = _METHOD_RE.search(description)
    return m.group(1) if m else "GET"


def _html_unescaped(text: str, char: str) -> bool:
    """True if char appears literally (not HTML-entity encoded)."""
    escaped = {"<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;"}
    if char not in text:
        return False
    return escaped.get(char, char) not in text


def _waf_in_response(resp) -> bool:
    headers_lower = {k.lower() for k in (resp.headers or {})}
    return bool(_WAF_RESP_HEADERS & headers_lower) or resp.status_code == 429


class api_probe(BaseModule):
    """
    Canary-based probe for jsfuzzer and swagger_probe discovered endpoints.
    Detects reflected XSS, SQL injection, SSTI, and status crashes.
    Concurrency-limited and WAF-aware to avoid triggering rate-limits.
    """

    watched_events = ["FINDING"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "aggressive", "web-thorough"]
    meta = {
        "description": "Canary probe: XSS, SQLi, SSTI, crash detection on discovered API endpoints",
        "author": "@suizer",
        "created_date": "2026-04-23",
    }
    options = {
        "test_post":   True,
        "auth_token":  "",
        "concurrency": 3,
        "timeout":     10,
    }
    options_desc = {
        "test_post":   "Also probe POST/PUT/PATCH on every discovered endpoint",
        "auth_token":  "Bearer token for authenticated endpoints (e.g. 'Bearer eyJ...')",
        "concurrency": "Max parallel parameter probes per endpoint (default 3; reduced to 1 on WAF)",
        "timeout":     "Per-request timeout in seconds (default 10)",
    }

    in_scope_only = True

    async def setup(self):
        self._seen       = set()
        self._test_post  = self.config.get("test_post", True)
        token            = self.config.get("auth_token", "").strip()
        self._auth_hdrs  = {"Authorization": token} if token else {}
        self._concurrency = int(self.config.get("concurrency", 3))
        self._timeout     = int(self.config.get("timeout", 10))
        self._semaphore   = asyncio.Semaphore(self._concurrency)
        return True

    async def filter_event(self, event):
        tags = set(getattr(event, "tags", []) or [])
        if "endpoint" not in tags:
            return False, "not an endpoint finding"
        if "jsfuzzer" not in tags and "swagger-probe" not in tags:
            return False, "not from jsfuzzer or swagger_probe"
        return True, ""

    async def handle_event(self, event):
        data = event.data
        if not isinstance(data, dict):
            return
        description = data.get("description", "")
        js_url      = data.get("url", "")

        endpoint_path = _extract_endpoint(description)
        if not endpoint_path or _SKIP_EXT.search(endpoint_path):
            return

        base = _base_url(js_url) if js_url else ""
        if not base:
            return

        endpoint_url = f"{base}{endpoint_path}"
        if endpoint_url in self._seen:
            return
        self._seen.add(endpoint_url)

        method         = _extract_method(data, description)
        swagger_params = _extract_swagger_params(data, description)

        self.verbose(f"Canary probe {method} {endpoint_url}")

        # ── Baseline ────────────────────────────────────────────────────────
        baseline = await self.helpers.request(
            endpoint_url, headers=self._auth_hdrs, allow_redirects=True,
            timeout=self._timeout,
        )
        if baseline is None:
            return

        baseline_status = baseline.status_code
        baseline_text   = baseline.text

        if baseline_status == 404:
            self.verbose(f"Skip {endpoint_url} — endpoint returned 404")
            return

        if baseline_status in (401, 403) and not self._auth_hdrs:
            self.verbose(f"Skip {endpoint_url} — auth required ({baseline_status}), no token configured")
            return

        # WAF detected in baseline → serialise probes + add delay between requests
        waf = _waf_in_response(baseline)
        if waf:
            self.verbose(f"{endpoint_url} — WAF detected in baseline, switching to serial + delay mode")
        probe_sem   = asyncio.Semaphore(1 if waf else self._concurrency)
        probe_delay = 1.5 if waf else 0.0

        # ── Canary values ────────────────────────────────────────────────────
        canary        = f"sdt{secrets.token_hex(4)}"
        ssti_expr     = f"{{{_SSTI_A}*{_SSTI_A}}}"  # e.g. {337*337}
        # Combined probe: XSS chars + SSTI expression in a single request
        probe_value   = f"{canary}<\"'>{ssti_expr}"

        # ── Build param list ─────────────────────────────────────────────────
        all_params = list(dict.fromkeys(swagger_params + COMMON_PARAMS + HIDDEN_PARAMS))

        # ── GET probes ───────────────────────────────────────────────────────
        async def _probe_get(param: str):
            async with probe_sem:
                if probe_delay:
                    await asyncio.sleep(probe_delay)
                url_probe = f"{endpoint_url}?{param}={probe_value}"
                resp = await self.helpers.request(
                    url_probe, headers=self._auth_hdrs, allow_redirects=True,
                    timeout=self._timeout,
                )
                if resp is None:
                    return None
                return self._evaluate(
                    resp, baseline_status, baseline_text,
                    canary=canary, ssti_expr=ssti_expr,
                    method="GET", param=param, url=url_probe, host=event.host,
                )

        get_results = await asyncio.gather(*[_probe_get(p) for p in all_params])

        emitted_types: set[str] = set()
        for finding in get_results:
            if finding and finding["type"] not in emitted_types:
                await self._emit(finding, event)
                emitted_types.add(finding["type"])

        # ── POST probe ───────────────────────────────────────────────────────
        if self._test_post and (method in POST_METHODS or method == "GET"):
            body_params = swagger_params if swagger_params else COMMON_PARAMS
            body = {p: probe_value for p in body_params}
            if probe_delay:
                await asyncio.sleep(probe_delay)
            resp = await self.helpers.request(
                endpoint_url,
                method="POST",
                json=body,
                headers={"Content-Type": "application/json", **self._auth_hdrs},
                allow_redirects=True,
                timeout=self._timeout,
            )
            if resp is not None:
                finding = self._evaluate(
                    resp, baseline_status, baseline_text,
                    canary=canary, ssti_expr=ssti_expr,
                    method="POST", param="json_body", url=endpoint_url, host=event.host,
                )
                if finding and finding["type"] not in emitted_types:
                    await self._emit(finding, event)

    def _evaluate(self, resp, baseline_status, baseline_text,
                  canary, ssti_expr, method, param, url, host) -> dict | None:
        body   = resp.text or ""
        status = resp.status_code

        # 1. Canary reflected → XSS or SSTI
        if canary in body:
            # SSTI: expression was evaluated ({337*337} → 113569 in body, not literal)
            if _SSTI_RESULT in body and ssti_expr not in body:
                return {
                    "type":      "ssti",
                    "severity":  "high",
                    "method":    method,
                    "param":     param,
                    "url":       url,
                    "host":      str(host),
                    "detection": "ssti",
                    "evidence":  f"expression {ssti_expr} evaluated to {_SSTI_RESULT} — param={param}",
                }

            # XSS: canary reflected with dangerous chars unescaped
            if _html_unescaped(body, "<") or _html_unescaped(body, '"'):
                return {
                    "type":      "xss_reflection",
                    "severity":  "medium",
                    "method":    method,
                    "param":     param,
                    "url":       url,
                    "host":      str(host),
                    "detection": "xss_reflection",
                    "evidence":  f"canary reflected unescaped — param={param}",
                }

            # Reflected but properly escaped — context for further testing
            return {
                "type":      "param_reflection",
                "severity":  "info",
                "method":    method,
                "param":     param,
                "url":       url,
                "host":      str(host),
                "detection": "param_reflection",
                "evidence":  f"canary reflected (escaped) — param={param}",
            }

        # 2. SQL error in response body
        sql_match = SQL_ERROR_RE.search(body)
        if sql_match:
            return {
                "type":      "sqli_error",
                "severity":  "high",
                "method":    method,
                "param":     param,
                "url":       url,
                "host":      str(host),
                "detection": "sql_error",
                "evidence":  sql_match.group(0)[:120],
            }

        # 3. Status crash — 2xx baseline → 5xx with probe input
        if baseline_status in range(200, 300) and status in range(500, 600):
            return {
                "type":      "status_crash",
                "severity":  "medium",
                "method":    method,
                "param":     param,
                "url":       url,
                "host":      str(host),
                "detection": "status_crash",
                "evidence":  f"{baseline_status} → {status}",
            }

        return None

    async def _emit(self, finding: dict, parent_event):
        sev      = finding["severity"]
        ftype    = finding["type"]
        method   = finding["method"]
        param    = finding["param"]
        url      = finding["url"]
        detect   = finding["detection"]
        evidence = finding.get("evidence", "")

        type_labels = {
            "xss_reflection":  "Reflected XSS candidate",
            "param_reflection": "Parameter reflected (context for further testing)",
            "sqli_error":      "SQL Injection (error-based)",
            "ssti":            "Server-Side Template Injection candidate",
            "status_crash":    "Input crash (possible injection point)",
        }
        label = type_labels.get(ftype, ftype)

        desc = (
            f"{label} [{sev.upper()}] — {method} {url} "
            f"param={param} detection={detect} evidence={evidence}"
        )

        event_type = "VULNERABILITY" if sev == "high" else "FINDING"

        if ftype == "param_reflection":
            self.verbose(desc)
            return

        await self.emit_event(
            {
                "host":        finding["host"],
                "url":         url,
                "description": desc,
                "severity":    sev,
                "name":        label,
            },
            event_type,
            parent=parent_event,
            tags=[
                "api-probe",
                f"severity-{sev}",
                f"detection-{detect}",
                ftype,
            ],
            context=f"{{module}} found {label} at {url}",
        )
