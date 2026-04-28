"""
ai_review.py — Local AI post-scan analysis for SuizerAudit.

Backend priority:
  1. Ollama     (local, free — preferred)
  2. Claude     (cloud, Anthropic API — high quality)
  3. Gemini     (cloud, free tier fallback)
  4. Skip       (warn and exit cleanly)

Produces:
  - Prioritized attack plan with ready-to-run commands
  - WAF-aware payloads (evasion techniques per detected WAF)
  - Source-map code review with targeted commands using real endpoints/params
  - Hardcoded secrets and directly exposed sensitive files

Config:
  OLLAMA_HOST=http://localhost:11434     (.env or env var — for Docker users)
  OLLAMA_MODEL=qwen2.5-coder:7b         (.env or env var)
  ANTHROPIC_API_KEY=...                  (.env or env var — Claude backend)
  ANTHROPIC_MODEL=claude-sonnet-4-6     (.env or env var — override model)
  GEMINI_API_KEY=...                     (.env or env var, fallback only)
  -c modules.ai_review.analyze_maps=false   (skip map review)
"""

from __future__ import annotations

import os
import asyncio
from pathlib import Path
from contextlib import suppress
from datetime import datetime
from collections import defaultdict

import httpx

from saudit.modules.output.base import BaseOutputModule

# ── Backend endpoints ─────────────────────────────────────────────────────────
# OLLAMA_HOST env var lets Docker users point to host.docker.internal:11434
_OLLAMA_BASE      = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
_OLLAMA_CHAT_URL  = f"{_OLLAMA_BASE}/api/chat"
_OLLAMA_TAGS_URL  = f"{_OLLAMA_BASE}/api/tags"

_GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-1.5-flash:generateContent?key={key}"
)

_ANTHROPIC_URL     = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2024-10-22"
_ANTHROPIC_DELAY   = 1.0

_CHUNK_CHARS  = 110_000   # safe upper bound for 32k-context models (leaves room for prompt + 4k response)
_OLLAMA_DELAY = 0.5
_GEMINI_DELAY = 4.0
_JS_FILE_CAP  = 10        # max source files sent to the model — beyond this it's almost always vendor noise

# Filename fragments that strongly suggest vendor/library bundles with zero security value
_VENDOR_FRAGMENTS = {
    "polyfill", "runtime", "jquery", "lodash", "bootstrap", "angular",
    "moment", "d3.", "highcharts", "fontawesome", "material", "antd",
    "tailwind", "core-js", "regenerator", "i18n", "locale", "webpackruntime",
    "vendors~", "framework~", "commons~",
}

# Regex patterns that indicate actual security-relevant code in a JS file
# A file must match at least _JS_SIGNAL_THRESHOLD of these to be worth analyzing
import re as _re
_CONTENT_SIGNAL_PATTERNS = [
    _re.compile(r'fetch\s*\('),
    _re.compile(r'axios\.'),
    _re.compile(r'XMLHttpRequest'),
    _re.compile(r'\.ajax\s*\('),
    _re.compile(r'"Authorization"'),
    _re.compile(r"'Authorization'"),
    _re.compile(r'Bearer\s+'),
    _re.compile(r'api[_\-]?[Kk]ey'),
    _re.compile(r'password\s*[:=]'),
    _re.compile(r'secret\s*[:=]'),
    _re.compile(r'/api/'),
    _re.compile(r'/v\d+/'),
    _re.compile(r'/admin'),
    _re.compile(r'/auth/'),
    _re.compile(r'/login'),
    _re.compile(r'/upload'),
    _re.compile(r'localStorage\.'),
    _re.compile(r'sessionStorage\.'),
    _re.compile(r'document\.cookie'),
    _re.compile(r'\beval\s*\('),
    _re.compile(r'\bbtoa\s*\('),
    _re.compile(r'\batob\s*\('),
]
_JS_SIGNAL_THRESHOLD = 3  # minimum pattern matches to consider a file worth analyzing

# Extensions that are directly exploitable when exposed via /ftp/ or similar
_SENSITIVE_EXTENSIONS = {
    ".bak", ".kdbx", ".env", ".pyc", ".sql", ".gz", ".zip",
    ".log", ".config", ".pem", ".key", ".p12", ".pfx", ".cer",
    ".yml", ".yaml", ".xml", ".json",
}

# Severity ordering for sorting findings before passing to the model
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ── WAF evasion reference ─────────────────────────────────────────────────────
_WAF_HINTS = {
    "cloudflare": (
        "Cloudflare WAF detected. Use these evasion techniques:\n"
        "- SQLi: tamper=space2comment,between,randomcase — avoid UNION SELECT in plaintext\n"
        "- XSS: HTML entity encoding, SVG vectors, event handler obfuscation (onerror, onpointerover)\n"
        "- Path bypass: /%2f, /./, unicode normalization, double URL encoding\n"
        "- Add header: X-Forwarded-For: 127.0.0.1"
    ),
    "modsecurity": (
        "ModSecurity WAF detected. Use these evasion techniques:\n"
        "- SQLi: tamper=charunicodeencode,modsecurityversioned,space2comment\n"
        "- XSS: charset confusion, UTF-7, null bytes between tags\n"
        "- Comments: /*!UNION*/ /*!SELECT*/ syntax\n"
        "- HPP (HTTP Parameter Pollution): duplicate params with different values"
    ),
    "akamai": (
        "Akamai WAF detected. Use these evasion techniques:\n"
        "- SQLi: case variation, inline comments, scientific notation for numbers\n"
        "- XSS: protocol-relative URLs, data: URIs, srcdoc attribute\n"
        "- Rate limiting: rotate User-Agent, add X-Forwarded-For variation\n"
        "- Try chunked Transfer-Encoding to bypass body inspection"
    ),
    "aws": (
        "AWS WAF detected. Use these evasion techniques:\n"
        "- SQLi: tamper=equaltolike,greatest,hex2char — avoid exact signature matches\n"
        "- XSS: Unicode escapes \\u003cscript\\u003e, template literals\n"
        "- Fragment payloads across multiple parameters\n"
        "- JSON body injection often less inspected than form params"
    ),
    "f5": (
        "F5 BIG-IP WAF detected. Use these evasion techniques:\n"
        "- SQLi: tamper=between,bluecoat,charencode — F5 is strict on UNION-based\n"
        "- XSS: less-common vectors: onfocus, onblur, CSS expression()\n"
        "- Try HTTP/2 with header injection\n"
        "- Multipart form data often bypasses body rules"
    ),
    "imperva": (
        "Imperva/Incapsula WAF detected. Use these evasion techniques:\n"
        "- SQLi: tamper=space2hash,halfversionedmorekeywords\n"
        "- XSS: javascript: protocol in href/src, iframe srcdoc\n"
        "- Path traversal: mix encoding schemes (%252e%252e)\n"
        "- Add legitimate-looking headers: Referer, Origin matching target"
    ),
}

_NO_WAF_HINT = (
    "No WAF detected. Use direct payloads without evasion:\n"
    "- SQLi: standard UNION-based, error-based, time-based blind\n"
    "- XSS: <script>alert(1)</script>, standard event handlers\n"
    "- No encoding tricks needed — go straight for impact"
)

# ── ANSI ──────────────────────────────────────────────────────────────────────
_R   = "\033[0m"
_CYN = "\033[1;36m"
_YEL = "\033[1;33m"
_GRN = "\033[1;32m"
_DIM = "\033[2m"
_WHT = "\033[1;37m"


def _hdr(title: str) -> str:
    bar = "─" * max(0, 56 - len(title) - 2)
    return f"\n{_CYN}──[ {_WHT}{title}{_CYN} ]{bar}{_R}"


def _waf_hint(wafs: list[str]) -> str:
    if not wafs:
        return _NO_WAF_HINT
    for waf in wafs:
        waf_lower = waf.lower()
        for key, hint in _WAF_HINTS.items():
            if key in waf_lower:
                return hint
    return f"WAF detected ({', '.join(wafs)}). Use encoding and tamper scripts. Identify vendor for specific bypass."


# ── System prompt ─────────────────────────────────────────────────────────────
_SYSTEM_PROMPT = """\
You are a senior penetration tester with 10+ years of experience in web application security.
You are reviewing results from an authorized automated recon scan produced by Saudit.
Your output is consumed directly by a human pentester who will execute your suggestions.

## Saudit pipeline context

Saudit runs in layers. Understanding which preset ran tells you what surface was already covered:

  initial (always runs first — passive fingerprinting, no brute-force)
    httpx, portscan → fingerprintx, sslcert, wafw00f, ntlm, oauth, azure_realm
    robots, securitytxt, security_headers
    badsecrets, jsfuzzer → retirejs
    git → gitdumper, code_repository → gitdumper, gitlab_onprem
    swagger_probe, graphql_introspection, hunt
    nuclei (tags:tech only — technology fingerprinting, NOT full template run)
    cms_advisor (detects WordPress/Mendix and recommends wpscan/mendix_recon)

  web-basic (extends initial — active, unauthenticated)
    bypass403, baddns, ffuf (surface dirbust)
    filedownload → extractous (downloads and extracts text from exposed files)
    api_probe (probes API endpoints found by swagger_probe/graphql_introspection)
    NOTE: nuclei full templates are NOT included — pentester adds nuclei preset manually

  web-authenticated (extends web-basic — requires valid session)
    session_check, paramminer_getparams/headers/cookies
    reflected_parameters, api_sqli_probe, lightfuzz (sqli,xss,ssti,cmdi,path,crypto,serial,esi)

  web-authenticated-thorough (extends web-authenticated — aggressive)
    host_header, generic_ssrf, smuggler, url_manipulation
    lightfuzz with force_common_headers, speculate_params

## Module source interpretation

When reading findings, the module field tells you the attack surface:
- swagger_probe / graphql_introspection → verified API specs — high-value attack entry points
- jsfuzzer (tag:endpoint) → AST-extracted endpoints from JavaScript — often undocumented
- git → exposed .git directory — source code likely recoverable
- gitdumper → source code recovered from exposed .git — treat as full code review opportunity
- code_repository → links to external repos (GitHub/GitLab/Docker) — recon surface
- gitlab_onprem → self-hosted GitLab found — enumerate repos for secrets and source code
- cms_advisor → CMS detected (WordPress/Mendix) — specialized module NOT yet run, pentester must add it
- api_probe → probed API endpoints for injection — treat findings as confirmed or near-confirmed
- filedownload / extractous → sensitive file recovered and parsed — treat content as direct evidence
- badsecrets → hardcoded secret in HTTP headers/cookies — often directly exploitable
- bypass403 → 403 bypass attempt — confirmed bypasses are high priority
- nuclei → template-based finding — check template name for CVE or misconfiguration class
- lightfuzz → parameter fuzzing result — confirmed with active probing

## Rules
- Always produce EXACT, ready-to-run commands using the actual target URL and parameters from the data.
- Never use placeholders like <target>, example.com, or <token> — use the real values provided.
- Adapt every payload to the WAF evasion context provided.
- Skip generic advice. If something is not directly actionable, omit it.
- Items in the CRITICAL EXPOSURE section must always appear in the Attack Plan, regardless of tag severity.
- Prioritize by real exploitability: exposed files > secrets > injection points > misconfigurations.
- cms_advisor findings are recommendations, not vulnerabilities — list them under Next Steps, not Attack Plan.
- gitdumper findings mean source code is available — always suggest grep for secrets and hardcoded creds.
- Be concise but complete. A command block is worth more than a paragraph."""


class ai_review(BaseOutputModule):
    watched_events = ["FINDING", "VULNERABILITY", "TECHNOLOGY", "WAF", "URL_UNVERIFIED"]
    meta = {
        "description": "Local AI (Ollama) post-scan analysis with WAF-aware commands and source-map review",
        "created_date": "2025-01-01",
        "author": "@suizer",
    }
    options = {
        "ollama_model":    "qwen2.5-coder:7b",
        "anthropic_key":   "",
        "anthropic_model": "claude-sonnet-4-6",
        "gemini_key":      "",
        "analyze_maps":    True,
    }
    options_desc = {
        "ollama_model":    "Ollama model to use (default: qwen2.5-coder:7b)",
        "anthropic_key":   "Anthropic API key for Claude backend (or set ANTHROPIC_API_KEY env var / .env)",
        "anthropic_model": "Claude model ID (default: claude-sonnet-4-6)",
        "gemini_key":      "Gemini API key fallback (or set GEMINI_API_KEY env var / .env)",
        "analyze_maps":    "Review unpacked source-map files (default: true)",
    }

    output_filename = "AI_REVIEW.md"

    async def setup(self):
        self._prep_output_dir("AI_REVIEW.md")
        self._analyze_maps = self.config.get("analyze_maps", True)
        self._ollama_model     = self._resolve_env("OLLAMA_MODEL", self.config.get("ollama_model", "qwen2.5-coder:7b"))
        self._anthropic_key   = self._resolve_env("ANTHROPIC_API_KEY", self.config.get("anthropic_key", ""))
        self._anthropic_model = self._resolve_env("ANTHROPIC_MODEL", self.config.get("anthropic_model", "claude-sonnet-4-6"))
        self._gemini_key      = self._resolve_env("GEMINI_API_KEY", self.config.get("gemini_key", ""))
        self._backend         = None

        self._findings        = []
        self._vulns           = []
        self._technologies    = []
        self._wafs            = []
        self._api_specs       = []   # findings from swagger_probe / graphql_introspection / jsfuzzer
        self._recommendations = []   # cms_advisor / gitdumper advisory findings
        self._js_urls         = []   # .js URLs for minified-JS fallback (capped at 15)

        # lightfuzz signal tracking — module → finding count
        self._lightfuzz_signals = {
            "hunt":                  0,
            "reflected_parameters":  0,
            "swagger_probe":         0,
            "graphql_introspection": 0,
            "paramminer_getparams":  0,
            "paramminer_headers":    0,
            "paramminer_cookies":    0,
        }
        return True

    # ── Event collection ──────────────────────────────────────────────────────

    async def filter_event(self, event):
        # Only accept .js URL_UNVERIFIED events; pass all other watched types through
        if event.type == "URL_UNVERIFIED":
            url = str(event.data) if isinstance(event.data, str) else event.data.get("url", "")
            if not url.lower().split("?")[0].endswith(".js"):
                return False, "not a .js URL"
        return True, "accepted"

    async def handle_event(self, event):
        data = event.data
        tags = list(getattr(event, "tags", []) or [])

        # Collect JS URLs for minified-JS fallback (max 15)
        if event.type == "URL_UNVERIFIED":
            if len(self._js_urls) < 15:
                url = str(data) if isinstance(data, str) else data.get("url", str(data))
                self._js_urls.append(url)
            return

        if event.type == "TECHNOLOGY":
            if isinstance(data, dict):
                self._technologies.append(data.get("technology", ""))
            return

        if event.type == "WAF":
            if isinstance(data, dict):
                self._wafs.append(data.get("waf", "Unknown WAF"))
            return

        if not isinstance(data, dict):
            return

        # Skip findings the scanner confirmed as 404
        if "status-404" in tags:
            return

        record = {
            "type":        event.type,
            "description": data.get("description", ""),
            "url":         data.get("url", ""),
            "severity":    "info",
            "tags":        tags,
            "module":      str(getattr(event, "module", "")),
            "risk":        data.get("risk", ""),
        }
        for tag in tags:
            if tag.startswith("severity-"):
                record["severity"] = tag.split("severity-", 1)[1]
                break

        # Promote sensitive file exposure to high regardless of original tag
        url = record["url"]
        if url and any(url.lower().endswith(ext) for ext in _SENSITIVE_EXTENSIONS):
            record["severity"] = "high"
            record["exposed_file"] = True
        else:
            record["exposed_file"] = False

        record["is_secret"] = "secret" in tags

        module   = record["module"]
        tags_set = set(record["tags"])

        # track lightfuzz signal modules
        if module in self._lightfuzz_signals:
            self._lightfuzz_signals[module] += 1

        # cms_advisor and gitdumper emit advisory findings, not exploitable vulnerabilities
        if module in ("cms_advisor", "gitdumper", "gitlab_onprem", "code_repository"):
            self._recommendations.append(record)
            return

        # API specs: structured endpoint data from discovery modules
        if module in ("swagger_probe", "graphql_introspection") or (
            module == "jsfuzzer" and "endpoint" in tags_set
        ):
            self._api_specs.append(record)
            return

        if event.type == "VULNERABILITY":
            record["name"] = data.get("name", record["description"])
            self._vulns.append(record)
        else:
            self._findings.append(record)

    # ── Report ────────────────────────────────────────────────────────────────

    async def report(self):
        self._backend = await self._detect_backend()
        if not self._backend:
            self.warning(
                "No AI backend available — generating plain structured summary. "
                "For AI analysis: start Ollama (ollama serve), set ANTHROPIC_API_KEY, or set GEMINI_API_KEY."
            )
            self._plain_report()
            return

        seeds    = list(self.scan.target.seeds.inputs)
        target   = seeds[0] if seeds else ""
        waf_hint = _waf_hint(self._wafs)
        wrote    = False

        print(f"\n{_CYN}[AI]{_R} Backend: {_WHT}{self._backend}{_R}", flush=True)

        # Fix 5: write header to disk immediately so html_report can start reading
        self._init_output_file(target)

        print(f"{_CYN}[AI]{_R} Analysing findings…", flush=True)
        findings_md = await self._analyze_findings(target, waf_hint)
        if findings_md:
            self._append_section(findings_md)
            self._print_section(findings_md)
            wrote = True

        if self._analyze_maps:
            if self._backend == "gemini":
                delay = _GEMINI_DELAY
            elif self._backend == "claude":
                delay = _ANTHROPIC_DELAY
            else:
                delay = _OLLAMA_DELAY
            # Fix 5: async generator — each chunk is written to disk as it completes
            async for section_md in self._analyze_source_maps(target, waf_hint, delay):
                self._append_section(section_md)
                wrote = True

        if not wrote:
            print(f"{_DIM}[AI] Nothing to report.{_R}", flush=True)
        else:
            print(f"{_GRN}[AI]{_R} Saved → {self.output_file}", flush=True)

    # ── Findings analysis ─────────────────────────────────────────────────────

    async def _analyze_findings(self, target: str, waf_hint: str) -> str:
        all_items = self._vulns + self._findings
        if not all_items and not self._technologies and not self._api_specs and not self._recommendations:
            return ""

        # Deduplicate by (url, description)
        seen, deduped = set(), []
        for f in all_items:
            key = (f.get("url", "").rstrip("/"), f.get("description", "")[:120].lower())
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        all_items = deduped

        secrets       = [f for f in all_items if f.get("is_secret")]
        exposed_files = [f for f in all_items if f.get("exposed_file") and not f.get("is_secret")]
        regular       = [f for f in all_items if not f.get("is_secret") and not f.get("exposed_file")]
        regular.sort(key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 4))

        # Build context blocks
        critical_lines = []
        if secrets:
            critical_lines.append("[HARDCODED SECRETS — treat as critical]")
            for f in secrets[:20]:
                desc = f.get("description", "")
                url  = f.get("url", "")
                critical_lines.append(f"  • {desc}" + (f"  →  {url}" if url else ""))
        if exposed_files:
            critical_lines.append("[SENSITIVE FILES DIRECTLY ACCESSIBLE]")
            for f in exposed_files[:20]:
                critical_lines.append(f"  • {f.get('url') or f.get('description', '')}")
        critical_block = "\n".join(critical_lines)

        api_lines = []
        if self._api_specs:
            api_lines.append("[VERIFIED API ENDPOINTS — swagger/graphql/jsfuzzer]")
            for f in self._api_specs[:30]:
                desc = f.get("description", "")
                url  = f.get("url", "")
                mod  = f.get("module", "")
                api_lines.append(f"  • [{mod}] {desc}" + (f"  →  {url}" if url else ""))
        api_block = "\n".join(api_lines)

        rec_lines = []
        if self._recommendations:
            rec_lines.append("[ADVISORY — specialized modules recommended or source code found]")
            for f in self._recommendations[:20]:
                mod  = f.get("module", "")
                desc = f.get("description", "")
                url  = f.get("url", "")
                rec_lines.append(f"  • [{mod}] {desc}" + (f"  →  {url}" if url else ""))

        lightfuzz_rec = self._build_lightfuzz_recommendation()
        if lightfuzz_rec:
            rec_lines.append(lightfuzz_rec)

        rec_block = "\n".join(rec_lines)

        by_sev = defaultdict(list)
        for f in regular:
            by_sev[f.get("severity", "info")].append(f)
        findings_lines = []
        for sev in ("critical", "high", "medium", "low", "info"):
            for f in by_sev.get(sev, [])[:30]:
                desc = f.get("name") or f.get("description", "")
                url  = f.get("url", "")
                mod  = f.get("module", "")
                findings_lines.append(f"[{sev.upper()}][{mod}] {desc}" + (f"  →  {url}" if url else ""))
        findings_block = "\n".join(findings_lines) or "No additional findings."
        tech_block     = ", ".join(sorted(set(self._technologies))) or "unknown"

        # ── Call 1: score regular findings by real exploitability ─────────────
        print(f"{_DIM}[AI] Step 1/3 — scoring {len(regular)} findings…{_R}", flush=True)
        ranked_regular = await self._score_findings(regular)

        # Critical exposures always included; take top 7 from scored regular findings
        top_items = secrets + exposed_files + ranked_regular[:7]

        # ── Call 2: generate focused commands for top items ─────────────────���──
        print(f"{_DIM}[AI] Step 2/3 — commands for {len(top_items)} items…{_R}", flush=True)
        commands_md = await self._generate_commands(
            top_items, target, waf_hint, critical_block, api_block, tech_block, rec_block
        )
        if not commands_md:
            return ""

        # ── Call 3: self-review — verify URLs and fix flags ────────────────────
        print(f"{_DIM}[AI] Step 3/3 — self-review…{_R}", flush=True)
        known_urls = {f.get("url", "") for f in all_items + self._api_specs if f.get("url")}
        final_md   = await self._self_review_commands(commands_md, known_urls, target)

        return final_md or commands_md  # fallback to unreviewed if review returns empty

    # ── Lightfuzz recommendation ──────────────────────────────────────────────

    def _build_lightfuzz_recommendation(self) -> str:
        s = self._lightfuzz_signals
        has_reflection   = s["reflected_parameters"] > 0
        has_hunt         = s["hunt"] > 0
        has_api          = s["swagger_probe"] > 0 or s["graphql_introspection"] > 0
        has_paramminer   = s["paramminer_getparams"] > 0 or s["paramminer_headers"] > 0 or s["paramminer_cookies"] > 0

        signal_count = sum([has_reflection, has_hunt, has_api, has_paramminer])
        if signal_count == 0:
            return ""

        lines = ["[LIGHTFUZZ RECOMMENDATION — parameter attack surface detected]"]

        if has_reflection:
            lines.append(
                f"  • reflected_parameters found {s['reflected_parameters']} reflected param(s) — "
                "confirmed reflection means direct XSS/SSTI candidates. "
                "Minimum: saudit [...] -p lightfuzz-xss | Full: saudit [...] -p lightfuzz-light"
            )
        if has_hunt:
            lines.append(
                f"  • hunt found {s['hunt']} dangerous parameter name(s) (redirect, file, cmd, url, etc.) — "
                "injection-prone surface confirmed by naming. "
                "Recommended: saudit [...] -p lightfuzz-medium"
            )
        if has_api:
            sources = []
            if s["swagger_probe"]:
                sources.append(f"swagger_probe ({s['swagger_probe']} findings)")
            if s["graphql_introspection"]:
                sources.append(f"graphql_introspection ({s['graphql_introspection']} findings)")
            lines.append(
                f"  • {' + '.join(sources)} — documented API surface with known parameters is ideal for fuzzing. "
                "Recommended: saudit [...] -p lightfuzz-medium"
            )
        if has_paramminer:
            discovered = s["paramminer_getparams"] + s["paramminer_headers"] + s["paramminer_cookies"]
            lines.append(
                f"  • paramminer discovered {discovered} hidden parameter(s) not present in source — "
                "undocumented surface warrants aggressive coverage. "
                "Recommended: saudit [...] -p lightfuzz-heavy"
            )

        # preset escalation summary
        if signal_count >= 3 or has_paramminer:
            lines.append(
                "  ► Multiple signals detected — consider lightfuzz-superheavy for maximum coverage: "
                "saudit [...] -p lightfuzz-superheavy"
            )
        elif signal_count == 1 and has_reflection and not has_hunt and not has_api:
            lines.append(
                "  ► Only reflection detected — lightfuzz-xss is the most surgical option: "
                "saudit [...] -p lightfuzz-xss"
            )

        return "\n".join(lines)

    # ── Source-map analysis ───────────────────────────────────────────────────

    async def _analyze_source_maps(self, target: str, waf_hint: str, delay: float):
        """Async generator — yields each analysed chunk as it completes."""
        jsfuzzer_dir = self.scan.home / "jsfuzzer_files"

        source_files = []
        if jsfuzzer_dir.is_dir():
            source_files = [
                f for f in (jsfuzzer_dir / "unpacked_sources").rglob("*")
                if f.is_file() and f.suffix in (".js", ".ts", ".jsx", ".tsx", ".vue")
            ]
            if not source_files:
                source_files = [f for f in jsfuzzer_dir.rglob("*.map") if f.is_file()]

        # Minified JS fallback
        if not source_files:
            if self._js_urls:
                print(f"{_CYN}[AI]{_R} No source maps — fetching {len(self._js_urls)} JS file(s)…",
                      flush=True)
                for section in await self._analyze_minified_js(target, waf_hint):
                    yield section
            return

        # ── Two-pass filter ───────────────────────────────────────────────────
        # Pass 1: discard obvious vendor/library bundles by filename
        _HV_KEYWORDS = {"auth", "api", "user", "login", "token", "secret",
                        "password", "admin", "config", "session", "permission", "role"}

        def _is_vendor(f):
            name = f.name.lower()
            # always keep high-value filenames regardless of vendor heuristic
            if any(kw in name for kw in _HV_KEYWORDS):
                return False
            return any(frag in name for frag in _VENDOR_FRAGMENTS)

        non_vendor = [f for f in source_files if not _is_vendor(f)]
        skipped_vendor = len(source_files) - len(non_vendor)

        # Pass 2: score by filename keywords + content signal count
        def _score(f):
            name_score    = sum(kw in f.name.lower() for kw in _HV_KEYWORDS)
            try:
                content   = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                return (name_score, 0)
            signal_count  = sum(1 for p in _CONTENT_SIGNAL_PATTERNS if p.search(content))
            return (name_score, signal_count)

        scored = sorted(non_vendor, key=_score, reverse=True)

        # Pass 3: hard cut — discard files below signal threshold (unless name is high-value)
        def _keep(f):
            name_score = sum(kw in f.name.lower() for kw in _HV_KEYWORDS)
            if name_score > 0:
                return True
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                return False
            return sum(1 for p in _CONTENT_SIGNAL_PATTERNS if p.search(content)) >= _JS_SIGNAL_THRESHOLD

        filtered = [f for f in scored if _keep(f)][:_JS_FILE_CAP]
        skipped_low_signal = len(scored) - len(filtered) - max(0, len(scored) - _JS_FILE_CAP)

        total_skipped = skipped_vendor + skipped_low_signal
        print(
            f"{_CYN}[AI]{_R} JS analysis: {len(filtered)}/{len(source_files)} files selected "
            f"({skipped_vendor} vendor, {skipped_low_signal} low-signal skipped, cap={_JS_FILE_CAP})…",
            flush=True,
        )

        if not filtered:
            print(f"{_DIM}[AI] No security-relevant JS files found after filtering.{_R}", flush=True)
            return

        chunks = self._chunk_files(filtered)
        for i, (label, code) in enumerate(chunks, 1):
            print(f"{_DIM}[AI] Map chunk {i}/{len(chunks)}: {label[:60]}{_R}", flush=True)
            md = await self._analyze_code_chunk(target, waf_hint, label, code)
            if md:
                yield md
            if i < len(chunks):
                await asyncio.sleep(delay)

    async def _analyze_minified_js(self, target: str, waf_hint: str) -> list[str]:
        """Fetch collected .js URLs and analyze the minified/bundled code."""
        code_parts = []
        total_chars = 0
        for js_url in self._js_urls:
            if total_chars >= _CHUNK_CHARS:
                break
            try:
                resp = await self.helpers.request(js_url)
                if resp and resp.text:
                    snippet = resp.text[:30_000]
                    code_parts.append(f"// === {js_url} ===\n{snippet}\n")
                    total_chars += len(snippet)
            except Exception:
                continue

        if not code_parts:
            return []

        label = f"{len(code_parts)} minified JS file(s)"
        code  = "".join(code_parts)
        prompt = f"""You are analyzing minified/bundled JavaScript from {target}.
No source maps were available — this is raw bundled/obfuscated JS.
Authorized penetration test.

WAF context:
{waf_hint}

Files: {label}

```javascript
{code[:_CHUNK_CHARS]}
```

Despite obfuscation, extract what you can find. Rules: use "{target}" in every command — no placeholders.

Produce exactly these sections:

## Endpoints Discovered
Table of every API endpoint or fetch/axios/XMLHttpRequest call found:
| Method | Path | Parameters | Notes |
|--------|------|------------|-------|

## Hardcoded Secrets
| Type | Value (truncated) | Context |
|------|-------------------|---------|
Only real secrets (API keys, tokens, passwords). Skip CDN IDs and tracking pixels.

## Attack Commands
Ready-to-run commands for interesting endpoints or secrets found.
Apply WAF evasion from the context above.

## Logic Flaws
Auth patterns, privilege checks, or IDOR indicators visible in the code."""

        result = await self._call(prompt)
        return [result] if result else []

    async def _analyze_code_chunk(self, target: str, waf_hint: str, label: str, code: str) -> str:
        # ── Call 1: extract structured endpoints + secrets as JSON ────────────
        endpoints_json = await self._extract_endpoints_json(code[:_CHUNK_CHARS], label)

        if not endpoints_json:
            # Fallback to single-call if JSON extraction failed
            return await self._analyze_code_chunk_single(target, waf_hint, label, code)

        # ── Call 2: generate attack commands from structured data ──────────────
        return await self._generate_map_commands(endpoints_json, code[:_CHUNK_CHARS],
                                                  label, target, waf_hint)

    async def _analyze_code_chunk_single(self, target: str, waf_hint: str,
                                          label: str, code: str) -> str:
        """Single-call fallback for when JSON extraction fails."""
        prompt = f"""Review JavaScript/TypeScript source code from webpack source maps.
Authorized penetration test against: {target}
WAF context: {waf_hint}
Source: {label}

```javascript
{code[:_CHUNK_CHARS]}
```

RULES: Use exact URL "{target}" — no placeholders.

## Endpoints Discovered
| Method | Path | Parameters | Auth required |
|--------|------|------------|---------------|

## Attack Commands
Ready-to-run commands using "{target}" and real param names. Apply WAF evasion.

## Hardcoded Secrets
| Type | Variable | Value (truncated) |
|------|----------|-------------------|
Only real secrets — skip CDN keys, tracking IDs, test values.

## Logic Flaws
Auth bypasses, IDOR patterns, privilege escalation. Include PoC where possible."""
        return await self._call(prompt)

    # ── Fix 5: incremental file writing ──────────────────────────────────────

    def _init_output_file(self, target: str):
        """Write the report header immediately so html_report can start reading."""
        if self._backend == "ollama":
            model_id = self._ollama_model
        elif self._backend == "claude":
            model_id = self._anthropic_model
        else:
            model_id = "gemini-1.5-flash"

        # ── Scan output file index ────────────────────────────────────────────
        index_lines = ["## Scan Output Files\n"]
        scan_home = self.scan.home

        _file_descriptions = {
            "output.json":    "All events in NDJSON — import into Burp, Splunk or custom tooling",
            "html_report.html": "Interactive HTML report — main deliverable for review",
            "AI_REVIEW.md":   "This file — AI-generated attack plan and next steps",
            "preset.yml":     "Resolved preset used for this scan",
            "scan.log":       "Full scan log",
            "wordcloud.tsv":  "Word frequency from discovered content",
        }

        with suppress(Exception):
            for f in sorted(scan_home.iterdir()):
                if f.is_file():
                    size = f.stat().st_size
                    size_str = f"{size // 1024} KB" if size >= 1024 else f"{size} B"
                    desc = _file_descriptions.get(f.name, "")
                    index_lines.append(f"| `{f.name}` | {size_str} | {desc} |")
                elif f.is_dir() and f.name not in ("temp", "cache"):
                    count = sum(1 for _ in f.rglob("*") if _.is_file())
                    dir_descs = {
                        "js_analysis":  "JS source map files (raw + deobfuscated)",
                        "filedownload": "Files downloaded from the target during scan",
                        "jsfuzzer_files": "jsfuzzer working directory",
                    }
                    desc = dir_descs.get(f.name, "")
                    index_lines.append(f"| `{f.name}/` | {count} files | {desc} |")

        index_md = (
            "| File | Size | Description |\n"
            "|------|------|-------------|\n"
            + "\n".join(index_lines[1:])  # skip the header line, already in table
        )

        header = (
            f"# AI Review — {target}\n"
            f"_Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} "
            f"via {self._backend} ({model_id})_\n\n"
            f"**WAF:** {', '.join(self._wafs) or 'None detected'}  \n"
            f"**Technologies:** {', '.join(sorted(set(self._technologies))) or 'Unknown'}\n\n"
            f"---\n\n"
            f"## Scan Output Files\n\n"
            f"| File | Size | Description |\n"
            f"|------|------|-------------|\n"
            + "\n".join(index_lines[1:])
            + "\n\n---\n"
        )
        with suppress(Exception):
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            self.output_file.write_text(header, encoding="utf-8")

    def _append_section(self, md: str):
        """Append a section to the report file as it completes."""
        with suppress(Exception):
            with self.output_file.open("a", encoding="utf-8") as f:
                f.write(f"\n\n{md}\n\n---\n")

    # ── Fix 4: three-call pipeline helpers ───────────────────────────────────

    async def _score_findings(self, items: list) -> list:
        """Call 1 — ask model to score findings by real exploitability, return sorted list."""
        if not items:
            return []

        lines = []
        for i, f in enumerate(items, 1):
            desc  = f.get("name") or f.get("description", "")
            url   = f.get("url", "")
            risk  = f.get("risk", "")
            flags = f.get("severity", "info").upper()
            line  = f"{i}. [{flags}] {desc}" + (f"  →  {url}" if url else "")
            if risk:
                line += f" | {risk}"
            lines.append(line)

        prompt = (
            "Score each security finding by real exploitability (1–10).\n"
            "10 = immediately exploitable with zero interaction.\n"
            "1  = theoretical, requires many assumptions.\n\n"
            "Findings:\n" + "\n".join(lines) + "\n\n"
            "Return ONLY a JSON array. No explanation, no markdown fences.\n"
            'Format: [{"id": 1, "score": 9}, {"id": 2, "score": 3}, ...]'
        )
        raw    = await self._call(prompt)
        scored = self._extract_json(raw, fallback=[])

        if not isinstance(scored, list) or not scored:
            return items  # fallback: keep original severity order

        score_map = {int(e.get("id", 0)): int(e.get("score", 0))
                     for e in scored if isinstance(e, dict)}
        indexed   = {id(f): i for i, f in enumerate(items, 1)}
        return sorted(items, key=lambda f: -score_map.get(indexed.get(id(f), 0), 0))

    async def _generate_commands(self, top_items: list, target: str, waf_hint: str,
                                  critical_block: str, api_block: str, tech_block: str,
                                  rec_block: str = "") -> str:
        """Call 2 — generate exact attack commands for the top-scored items only."""
        if not top_items:
            return ""

        items_text = []
        for f in top_items:
            desc  = f.get("name") or f.get("description", "")
            url   = f.get("url", "")
            risk  = f.get("risk", "")
            sev   = f.get("severity", "info").upper()
            label = "SECRET" if f.get("is_secret") else ("EXPOSED_FILE" if f.get("exposed_file") else sev)
            line  = f"• [{label}] {desc}" + (f"  →  {url}" if url else "")
            if risk:
                line += f"\n    Risk: {risk}"
            items_text.append(line)

        prompt = f"""Authorized penetration test.
Target: {target}
Technologies: {tech_block}
WAF context: {waf_hint}

Critical exposures (ALWAYS include in plan):
{critical_block or "None."}

Verified API endpoints:
{api_block or "None."}

Top findings to attack:
{chr(10).join(items_text)}

Advisory — specialized modules recommended or source code found:
{rec_block or "None."}

RULES:
- Use exact URL "{target}" in every command — zero placeholders.
- Apply WAF evasion from the WAF context.
- Critical exposures must always appear first in Attack Plan.
- Advisory items (cms_advisor, gitdumper, gitlab_onprem) go ONLY in Next Steps, never in Attack Plan.
- If gitdumper found source code, always include: grep -rE "(password|secret|api_key|token)" <recovered_repo_path>

Produce ONLY these sections (no other text):

## Attack Plan
3–5 vectors ranked by real impact. One sentence WHY each is exploitable NOW.

## Commands
One ### subsection per vector. Exact bash commands.

## Quick Wins
Max 3 items exploitable in under 5 minutes with exact URL or command.

## Next Steps
Specialized modules or manual actions not yet performed. Include exact saudit command to run each recommended module."""

        return await self._call(prompt)

    async def _self_review_commands(self, commands_md: str,
                                     known_urls: set, target: str) -> str:
        """Call 3 — model reviews its own output and corrects hallucinated URLs/flags."""
        if not commands_md:
            return ""

        url_sample = "\n".join(sorted(known_urls)[:40]) or "(no URLs recorded)"
        prompt = f"""You wrote these penetration testing commands for {target}.
Review them and fix any errors.

Known URLs confirmed to exist in this scan:
{url_sample}

Commands to review:
{commands_md}

Rules:
1. If a URL path in a command does NOT appear in the known URLs list, prepend that
   command line with: # [UNVERIFIED PATH — confirm manually]
2. Fix any invalid tool flags (e.g. sqlmap missing -u, curl missing URL argument).
3. Keep all ## and ### section headers exactly as-is.
4. Return the complete corrected commands. No explanation outside the commands."""

        reviewed = await self._call(prompt)
        return reviewed if reviewed else commands_md

    async def _extract_endpoints_json(self, code: str, label: str) -> list | None:
        """Call 1 for source maps — extract endpoints + secrets as JSON."""
        prompt = (
            f"Extract security-relevant information from this JavaScript/TypeScript source: {label}\n\n"
            "Return ONLY valid JSON. No markdown, no explanation.\n"
            "Format:\n"
            '{"endpoints": [{"method": "GET", "path": "/api/users", "params": ["id"], "auth": true}], '
            '"secrets": [{"type": "API_KEY", "name": "STRIPE_KEY", "value": "sk-..."}]}\n\n'
            f"Code:\n```javascript\n{code[:_CHUNK_CHARS]}\n```"
        )
        raw    = await self._call(prompt)
        result = self._extract_json(raw, fallback=None)
        if not isinstance(result, dict):
            return None
        endpoints = result.get("endpoints", [])
        secrets   = result.get("secrets", [])
        return {"endpoints": endpoints, "secrets": secrets} if (endpoints or secrets) else None

    async def _generate_map_commands(self, data: dict, code: str, label: str,
                                      target: str, waf_hint: str) -> str:
        """Call 2 for source maps — generate attack commands from structured endpoint data."""
        endpoints = data.get("endpoints", [])
        secrets   = data.get("secrets", [])

        ep_lines = [f"  {e.get('method','?')} {e.get('path','?')}  params={e.get('params',[])}  auth={e.get('auth','?')}"
                    for e in endpoints[:25]]
        sec_lines = [f"  {s.get('type','?')} — {s.get('name','?')}: {str(s.get('value',''))[:60]}"
                     for s in secrets[:10]]

        prompt = f"""Authorized penetration test against: {target}
WAF context: {waf_hint}
Source: {label}

Endpoints found:
{chr(10).join(ep_lines) or "  (none)"}

Secrets found:
{chr(10).join(sec_lines) or "  (none)"}

RULES: Use exact URL "{target}" — no placeholders. Apply WAF evasion.

## Endpoints Discovered
| Method | Path | Parameters | Auth required |
|--------|------|------------|---------------|

## Attack Commands
One ### subsection per interesting endpoint or secret. Exact bash commands.

## Logic Flaws
Auth bypasses, IDOR, privilege escalation patterns from the endpoint structure."""

        return await self._call(prompt)

    def _extract_json(self, text: str, fallback=None):
        """Robustly extract JSON from model output that may include prose or markdown."""
        import json, re
        # Strip markdown fences
        text = re.sub(r"```(?:json)?\s*", "", text).strip().rstrip("`").strip()
        # Try full text
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            pass
        # Find first complete JSON array or object
        for pattern in (r"\[[\s\S]*\]", r"\{[\s\S]*\}"):
            m = re.search(pattern, text)
            if m:
                try:
                    return json.loads(m.group())
                except (json.JSONDecodeError, ValueError):
                    continue
        return fallback

    # ── Backend abstraction ───────────────────────────────────────────────────

    async def _detect_backend(self) -> str | None:
        try:
            async with httpx.AsyncClient(timeout=3) as c:
                r = await c.get(_OLLAMA_TAGS_URL)
                if r.status_code == 200:
                    models = [m.get("name", "") for m in r.json().get("models", [])]
                    # accept if configured model (with or without tag suffix) is available
                    if any(self._ollama_model in m or m in self._ollama_model for m in models):
                        return "ollama"
                    self.warning(
                        f"Ollama running but model '{self._ollama_model}' not found "
                        f"(available: {', '.join(models) or 'none'}). "
                        f"Run: ollama pull {self._ollama_model}"
                    )
        except Exception:
            pass
        if self._anthropic_key:
            return "claude"
        if self._gemini_key:
            return "gemini"
        return None

    async def _call(self, prompt: str) -> str:
        if self._backend == "ollama":
            return await self._ollama_call(prompt)
        if self._backend == "claude":
            return await self._claude_call(prompt)
        return await self._gemini_call(prompt)

    async def _ollama_call(self, prompt: str) -> str:
        payload = {
            "model":    self._ollama_model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            "stream":   False,
            "options":  {"temperature": 0.1, "num_predict": 4096},
        }
        try:
            async with httpx.AsyncClient(timeout=300) as client:
                resp = await client.post(_OLLAMA_CHAT_URL, json=payload)
                resp.raise_for_status()
                return resp.json()["message"]["content"].strip()
        except Exception as e:
            self.warning(f"Ollama call failed: {e}")
            return ""

    async def _claude_call(self, prompt: str) -> str:
        payload = {
            "model":      self._anthropic_model,
            "max_tokens": 4096,
            "system":     _SYSTEM_PROMPT,
            "messages":   [{"role": "user", "content": prompt}],
        }
        headers = {
            "x-api-key":         self._anthropic_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type":      "application/json",
        }
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(_ANTHROPIC_URL, json=payload, headers=headers)
                resp.raise_for_status()
                return resp.json()["content"][0]["text"].strip()
        except httpx.HTTPStatusError as e:
            self.warning(f"Claude error: {e.response.status_code} — {e.response.text[:200]}")
        except Exception as e:
            self.warning(f"Claude call failed: {e}")
        return ""

    async def _gemini_call(self, prompt: str) -> str:
        url = _GEMINI_URL.format(key=self._gemini_key)
        payload = {
            "system_instruction": {"parts": [{"text": _SYSTEM_PROMPT}]},
            "contents":           [{"parts": [{"text": prompt}]}],
            "generationConfig":   {"temperature": 0.1, "maxOutputTokens": 4096},
        }
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                return resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        except httpx.HTTPStatusError as e:
            self.warning(f"Gemini error: {e.response.status_code} — {e.response.text[:200]}")
        except Exception as e:
            self.warning(f"Gemini call failed: {e}")
        return ""

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _chunk_files(self, files: list[Path]) -> list[tuple[str, str]]:
        chunks, parts, size, labels = [], [], 0, []
        for f in files:
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            block = f"// === {f.name} ===\n{content}\n"
            if size + len(block) > _CHUNK_CHARS and parts:
                chunks.append((", ".join(labels), "".join(parts)))
                parts, size, labels = [], 0, []
            parts.append(block)
            size += len(block)
            labels.append(f.name)
        if parts:
            chunks.append((", ".join(labels), "".join(parts)))
        return chunks

    def _resolve_env(self, env_var: str, default: str = "") -> str:
        val = os.environ.get(env_var, "")
        if val:
            return val
        env_file = Path(__file__).parent.parent.parent.parent / ".env"
        if env_file.is_file():
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if line.startswith(f"{env_var}="):
                    val = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if val:
                        return val
        return default

    def _print_section(self, md: str):
        print(_hdr("AI REVIEW"), flush=True)
        for line in md.splitlines():
            if line.startswith("## "):
                print(f"\n  {_CYN}{line[3:]}{_R}", flush=True)
            elif line.startswith("### "):
                print(f"  {_WHT}{line[4:]}{_R}", flush=True)
            elif line.startswith("```"):
                print(f"  {_DIM}{line}{_R}", flush=True)
            elif line.strip().startswith(("sqlmap", "curl", "ffuf", "for ", "nuclei", "hashcat")):
                print(f"  {_YEL}{line}{_R}", flush=True)
            elif line.strip():
                print(f"  {_DIM}{line}{_R}", flush=True)

    def _plain_report(self):
        """Structured markdown summary without any LLM — fallback when no backend is available."""
        seeds  = list(self.scan.target.seeds.inputs)
        target = seeds[0] if seeds else "unknown"

        lines = [
            f"# Scan Summary — {target}",
            f"_Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} — no AI backend, structured data only_",
            "",
            f"**WAF:** {', '.join(self._wafs) or 'None detected'}  ",
            f"**Technologies:** {', '.join(sorted(set(self._technologies))) or 'Unknown'}",
            "",
            "---",
        ]

        def _table(records: list, title: str):
            if not records:
                return
            lines.append(f"\n## {title} ({len(records)})\n")
            lines.append("| Severity | Module | Description | URL |")
            lines.append("|----------|--------|-------------|-----|")
            for r in sorted(records, key=lambda x: _SEV_ORDER.get(x.get("severity", "info"), 4)):
                sev  = r.get("severity", "info").upper()
                mod  = r.get("module", "")
                desc = (r.get("name") or r.get("description", ""))[:120].replace("|", "\\|")
                url  = r.get("url", "")
                lines.append(f"| {sev} | {mod} | {desc} | {url} |")

        _table(self._vulns,    "Vulnerabilities")
        _table(self._findings, "Findings")

        if self._api_specs:
            lines.append(f"\n## API Surface ({len(self._api_specs)})\n")
            lines.append("| Module | Description | URL |")
            lines.append("|--------|-------------|-----|")
            for r in self._api_specs[:50]:
                mod  = r.get("module", "")
                desc = r.get("description", "")[:120].replace("|", "\\|")
                url  = r.get("url", "")
                lines.append(f"| {mod} | {desc} | {url} |")

        if self._recommendations:
            lines.append(f"\n## Recommendations ({len(self._recommendations)})\n")
            for r in self._recommendations:
                mod  = r.get("module", "")
                desc = r.get("description", "")[:200]
                lines.append(f"- **[{mod}]** {desc}")

        lines += [
            "",
            "---",
            "",
            "## Next Steps",
            "",
            "No AI analysis was performed. To get an AI-generated attack plan, re-run with one of:",
            "```",
            "# Option 1 — Ollama (local, free)",
            "ollama serve && ollama pull qwen2.5-coder:7b",
            "# Option 2 — Claude",
            "export ANTHROPIC_API_KEY=sk-ant-...",
            "# Option 3 — Gemini",
            "export GEMINI_API_KEY=...",
            "```",
        ]

        md = "\n".join(lines)
        with suppress(Exception):
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            self.output_file.write_text(md, encoding="utf-8")

        print(_hdr("SCAN SUMMARY (no AI backend)"), flush=True)
        if self._vulns:
            print(f"  {_YEL}Vulnerabilities : {len(self._vulns)}{_R}", flush=True)
        if self._findings:
            print(f"  {_DIM}Findings        : {len(self._findings)}{_R}", flush=True)
        if self._api_specs:
            print(f"  {_CYN}API endpoints   : {len(self._api_specs)}{_R}", flush=True)
        if self._wafs:
            print(f"  {_WHT}WAF             : {', '.join(self._wafs)}{_R}", flush=True)
        print(f"{_GRN}[AI]{_R} Saved → {self.output_file}", flush=True)

    async def cleanup(self):
        pass
