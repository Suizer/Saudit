"""
ai_review.py — Local AI post-scan analysis for SuizerAudit.

Backend priority:
  1. Ollama  (local, free — preferred)
  2. Gemini  (cloud, free tier fallback)
  3. Skip    (warn and exit cleanly)

Produces:
  - Prioritized attack plan with ready-to-run commands
  - WAF-aware payloads (evasion techniques per detected WAF)
  - Source-map code review with targeted commands using real endpoints/params
  - Hardcoded secrets and directly exposed sensitive files

Config:
  OLLAMA_HOST=http://localhost:11434     (.env or env var — for Docker users)
  OLLAMA_MODEL=qwen2.5-coder:7b         (.env or env var)
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

_CHUNK_CHARS  = 110_000   # safe upper bound for 32k-context models (leaves room for prompt + 4k response)
_OLLAMA_DELAY = 0.5
_GEMINI_DELAY = 4.0

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
You are reviewing results from an authorized automated recon scan.
Your output is consumed directly by a human pentester who will execute your suggestions.

Rules:
- Always produce EXACT, ready-to-run commands using the actual target URL and parameters from the data.
- Never use placeholders like <target>, example.com, or <token> — use the real values provided.
- Adapt every payload to the WAF evasion context provided.
- Skip generic advice. If something is not directly actionable, omit it.
- Items in the CRITICAL EXPOSURE section must always appear in the Attack Plan, regardless of tag severity.
- Prioritize by real exploitability: exposed files > secrets > injection points > misconfigurations.
- Be concise but complete. A command block is worth more than a paragraph."""


class ai_review(BaseOutputModule):
    watched_events = ["FINDING", "VULNERABILITY", "TECHNOLOGY", "WAF", "URL_UNVERIFIED"]
    meta = {
        "description": "Local AI (Ollama) post-scan analysis with WAF-aware commands and source-map review",
        "created_date": "2025-01-01",
        "author": "@suizer",
    }
    options = {
        "ollama_model": "qwen2.5-coder:7b",
        "gemini_key":   "",
        "analyze_maps": True,
    }
    options_desc = {
        "ollama_model": "Ollama model to use (default: qwen2.5-coder:7b)",
        "gemini_key":   "Gemini API key fallback (or set GEMINI_API_KEY env var / .env)",
        "analyze_maps": "Review unpacked source-map files (default: true)",
    }

    output_filename = "AI_REVIEW.md"

    async def setup(self):
        self._analyze_maps = self.config.get("analyze_maps", True)
        self._ollama_model = self._resolve_env("OLLAMA_MODEL", self.config.get("ollama_model", "qwen2.5-coder:7b"))
        self._gemini_key   = self._resolve_env("GEMINI_API_KEY", self.config.get("gemini_key", ""))
        self._backend      = None

        self._findings     = []
        self._vulns        = []
        self._technologies = []
        self._wafs         = []
        self._api_specs    = []   # findings from swagger_probe / graphql_introspection
        self._js_urls      = []   # .js URLs for minified-JS fallback (capped at 15)
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

        # Route structured API findings to dedicated list instead of regular findings
        # swagger_probe / graphql_introspection → already structured endpoint data
        # jsfuzzer with tag "endpoint" → AST-extracted endpoint, more reliable than raw code
        module = record["module"]
        tags_set = set(record["tags"])
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
                "No AI backend available. "
                "Start Ollama (ollama serve) or set GEMINI_API_KEY."
            )
            return

        seeds  = list(self.scan.target.seeds.inputs)
        target = seeds[0] if seeds else ""
        waf_hint = _waf_hint(self._wafs)
        sections: list[str] = []

        print(f"\n{_CYN}[AI]{_R} Backend: {_WHT}{self._backend}{_R}", flush=True)

        print(f"{_CYN}[AI]{_R} Analysing findings…", flush=True)
        findings_md = await self._analyze_findings(target, waf_hint)
        if findings_md:
            sections.append(findings_md)
            self._print_section(findings_md)

        if self._analyze_maps:
            delay = _GEMINI_DELAY if self._backend == "gemini" else _OLLAMA_DELAY
            map_sections = await self._analyze_source_maps(target, waf_hint, delay)
            sections.extend(map_sections)

        if not sections:
            print(f"{_DIM}[AI] Nothing to report.{_R}", flush=True)
            return

        header = (
            f"# AI Review — {target}\n"
            f"_Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} "
            f"via {self._backend} "
            f"({self._ollama_model if self._backend == 'ollama' else 'gemini-1.5-flash'})_\n\n"
            f"**WAF:** {', '.join(self._wafs) or 'None detected'}  \n"
            f"**Technologies:** {', '.join(sorted(set(self._technologies))) or 'Unknown'}\n\n---\n"
        )
        md = header + "\n\n---\n".join(sections)
        with suppress(Exception):
            self.output_file.write_text(md, encoding="utf-8")
            print(f"{_GRN}[AI]{_R} Saved → {self.output_file}", flush=True)

    # ── Findings analysis ─────────────────────────────────────────────────────

    async def _analyze_findings(self, target: str, waf_hint: str) -> str:
        all_items = self._vulns + self._findings
        if not all_items and not self._technologies and not self._api_specs:
            return ""

        # 5.1 — Deduplicate by (url, description) to avoid model confusion
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

        # Critical exposure block
        critical_lines = []
        if secrets:
            critical_lines.append("\n[HARDCODED SECRETS — treat as critical]")
            for f in secrets[:20]:
                desc = f.get("description", "")
                url  = f.get("url", "")
                critical_lines.append(f"  • {desc}" + (f"  →  {url}" if url else ""))

        if exposed_files:
            critical_lines.append("\n[SENSITIVE FILES DIRECTLY ACCESSIBLE]")
            for f in exposed_files[:20]:
                url  = f.get("url", "")
                desc = f.get("description", "")
                critical_lines.append(f"  • {url or desc}")

        critical_block = "\n".join(critical_lines)

        # Regular findings block
        by_sev = defaultdict(list)
        for f in regular:
            by_sev[f.get("severity", "info")].append(f)

        findings_lines = []
        for sev in ("critical", "high", "medium", "low", "info"):
            items = by_sev.get(sev, [])
            if not items:
                continue
            findings_lines.append(f"\n[{sev.upper()}]")
            for f in items[:30]:
                desc = f.get("name") or f.get("description", "")
                url  = f.get("url", "")
                mod  = f.get("module", "")
                findings_lines.append(f"  • [{mod}] {desc}" + (f"  →  {url}" if url else ""))

        findings_block = "\n".join(findings_lines) or "No additional findings."
        tech_block     = ", ".join(sorted(set(self._technologies))) or "unknown"

        # 4.2 — Verified API endpoints from Swagger/GraphQL introspection
        api_lines = []
        if self._api_specs:
            api_lines.append("\n[SWAGGER / GRAPHQL — verified endpoints and schema]")
            for f in self._api_specs[:30]:
                desc = f.get("description", "")
                url  = f.get("url", "")
                mod  = f.get("module", "")
                api_lines.append(f"  • [{mod}] {desc}" + (f"  →  {url}" if url else ""))
        api_block = "\n".join(api_lines)

        prompt = f"""Target base URL: {target}
Technologies: {tech_block}

WAF context:
{waf_hint}

━━━ CRITICAL EXPOSURE (always prioritize these) ━━━
{critical_block or "None found."}

━━━ VERIFIED API ENDPOINTS (Swagger/GraphQL — use these for direct attacks) ━━━
{api_block or "None found."}

━━━ ADDITIONAL FINDINGS (sorted high → low) ━━━
{findings_block}

RULES:
- Every command must use the exact URL "{target}" — no placeholders.
- Items in CRITICAL EXPOSURE must always appear in the Attack Plan.
- Prioritize: exposed files > hardcoded secrets > injection points > misconfigs.

Produce exactly these sections:

## Attack Plan
3-5 attack vectors ranked by real exploitability. One sentence WHY each is high priority.
Start with any CRITICAL EXPOSURE items above.

## Commands
Exact ready-to-run command for each attack vector using "{target}" and real paths/params.
Apply WAF evasion from the WAF context.

### Example format:
### Exposed KeePass file — /ftp/incident-support.kdbx
```bash
curl -s "{target}/ftp/incident-support.kdbx" -o incident-support.kdbx
file incident-support.kdbx
# Then crack offline: hashcat -m 13400 incident-support.kdbx rockyou.txt
```

### SQL Injection — /api/Users
```bash
sqlmap -u "{target}/api/Users?id=1" \\
  --dbs --level 3 --risk 2 \\
  --tamper=space2comment,between \\
  --random-agent --batch
```

## Next saudit Modules
Only use real module names: ffuf, nuclei, jsfuzzer, swagger_probe, graphql_introspection,
wpscan, gitdumper, generic_ssrf, host_header, badsecrets, retirejs, hunt, httpx.
Format: `module_name` — reason

## Quick Wins
Max 3 items exploitable in under 5 minutes. Include exact curl/browser URL for each."""

        return await self._call(prompt)

    # ── Source-map analysis ───────────────────────────────────────────────────

    async def _analyze_source_maps(self, target: str, waf_hint: str, delay: float) -> list[str]:
        results = []
        jsfuzzer_dir = self.scan.home / "jsfuzzer_files"

        source_files = []
        if jsfuzzer_dir.is_dir():
            source_files = [
                f for f in (jsfuzzer_dir / "unpacked_sources").rglob("*")
                if f.is_file() and f.suffix in (".js", ".ts", ".jsx", ".tsx", ".vue")
            ]
            if not source_files:
                source_files = [f for f in jsfuzzer_dir.rglob("*.map") if f.is_file()]

        # Sort high-value files first so the model sees auth/api code before vendor bundles
        _HV_KEYWORDS = {"auth", "api", "user", "login", "token", "secret",
                        "password", "admin", "config", "session", "permission", "role"}
        source_files.sort(
            key=lambda f: -sum(kw in f.name.lower() for kw in _HV_KEYWORDS)
        )

        # 4.1 — Minified JS fallback: fetch .js URLs collected during scan
        if not source_files:
            if self._js_urls:
                print(f"{_CYN}[AI]{_R} No source maps — fetching {len(self._js_urls)} JS file(s) directly…",
                      flush=True)
                return await self._analyze_minified_js(target, waf_hint)
            return results

        print(f"{_CYN}[AI]{_R} Reviewing {len(source_files)} source file(s)…", flush=True)

        chunks = self._chunk_files(source_files)
        for i, (label, code) in enumerate(chunks, 1):
            print(f"{_DIM}[AI] Map chunk {i}/{len(chunks)}: {label[:60]}{_R}", flush=True)
            md = await self._analyze_code_chunk(target, waf_hint, label, code)
            if md:
                results.append(md)
            if i < len(chunks):
                await asyncio.sleep(delay)

        return results

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
        prompt = f"""You are reviewing JavaScript/TypeScript source code recovered from webpack source maps.
Authorized penetration test against: {target}

WAF context:
{waf_hint}

Source files: {label}

```javascript
{code[:_CHUNK_CHARS]}
```

RULES: Every command must use the exact URL "{target}" — no placeholders.

Produce exactly these sections:

## Endpoints Discovered
Table of every API endpoint found:
| Method | Path | Parameters | Auth required |
|--------|------|------------|---------------|

## Attack Commands
Ready-to-run command for each interesting endpoint using "{target}" and real param names.
Apply WAF evasion from the context above.

### IDOR — GET /api/users/:id
```bash
for i in $(seq 1 20); do
  curl -sk "{target}/api/users/$i" | python3 -m json.tool
done
```

## Hardcoded Secrets
| Type | Variable name | Value |
|------|--------------|-------|
Only real secrets — skip public CDN keys, tracking IDs, and test values.

## Logic Flaws
Auth bypasses, privilege escalation, IDOR patterns, business logic issues.
Include proof-of-concept code where possible."""

        return await self._call(prompt)

    # ── Backend abstraction ───────────────────────────────────────────────────

    async def _detect_backend(self) -> str | None:
        try:
            async with httpx.AsyncClient(timeout=3) as c:
                r = await c.get(_OLLAMA_TAGS_URL)
                if r.status_code == 200:
                    return "ollama"
        except Exception:
            pass
        if self._gemini_key:
            return "gemini"
        return None

    async def _call(self, prompt: str) -> str:
        if self._backend == "ollama":
            return await self._ollama_call(prompt)
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

    async def cleanup(self):
        pass
