# SuizerAudit

**Autonomous web reconnaissance and vulnerability detection scanner.**

SuizerAudit is a focused fork of [bbot](https://github.com/blacklanternsecurity/bbot) tailored for web application security auditing. It extends the bbot engine with purpose-built modules for JavaScript analysis, API discovery, and canary-based vulnerability detection — delivering Burp Scanner-level coverage in a single automated run.

---

## Features

- **JS Analysis** — Deep analysis of JavaScript bundles via JsFuzzer: secrets, API endpoints, source map unpacking, deobfuscation
- **OpenAPI/Swagger Discovery** — Automatically finds and parses API specs (JSON, YAML, or Swagger UI embedded specs) to extract real parameter names
- **Canary Reflection Probe** — Sends a unique canary token through every discovered API parameter and detects:
  - Reflected XSS (unescaped reflection)
  - SQL injection (error-based)
  - Input crashes (2xx → 5xx status change)
- **403 Bypass Detection** — Multi-signature path bypass testing against protected endpoints
- **NTLM / Bad Secrets / Security.txt** — Infrastructure exposure checks
- **WebPeas output** — Colour-coded, section-grouped terminal report with live HIGH/CRITICAL alerts during scan

---

## Quick Start

```bash
# Install
pip install -e .

# Run against a target
saudit -t https://target.example.com -p webpeas-stealth --output-dir ./results
```

---

## Stealth Preset (`webpeas-stealth`)

```yaml
modules:
  - httpx          # HTTP crawling and fingerprinting
  - robots         # robots.txt discovery
  - securitytxt    # security.txt exposure
  - ntlm           # NTLM auth info leakage
  - badsecrets     # Known default secrets detection
  - bypass403      # 403 bypass multi-signature test
  - jsfuzzer       # JavaScript analysis (secrets, endpoints, source maps)
  - swagger_probe  # OpenAPI/Swagger spec discovery
  - api_probe      # Canary-based XSS + SQLi + crash detection
```

Passive-first, no brute-force, no aggressive fuzzing. Designed for stealth recon and responsible disclosure workflows.

---

## Module Overview

### `jsfuzzer`
Integrates [JsFuzzer](https://github.com/Suizer/JsFuzzer) for deep JavaScript analysis:
- Downloads and deobfuscates JS files
- Unpacks webpack source maps when available
- Detects: secrets, API endpoints, entropy strings, subdomain references
- Built-in false-positive filtering (charsets, empty passwords, doc URLs)

Requires `tool_path` pointing to your JsFuzzer directory:
```yaml
config:
  modules:
    jsfuzzer:
      tool_path: /path/to/JsFuzzer
```

### `swagger_probe`
Discovers OpenAPI 2.0 / 3.0 specs across 15+ common paths. Also handles Swagger UI pages with embedded specs (e.g. `swagger-ui-init.js`). Emits one FINDING per documented endpoint with real parameter names attached for `api_probe` to consume.

### `api_probe`
Canary-based probe that tests every endpoint `jsfuzzer` or `swagger_probe` discovers:
- One request per parameter tests XSS + SQLi + crash simultaneously
- Unique canary per probe enables confirmed reflection detection
- Skips 401/403 endpoints unless `auth_token` is provided
- Parallel GET probes via `asyncio.gather`

```yaml
config:
  modules:
    api_probe:
      auth_token: "Bearer eyJ..."   # optional, for authenticated endpoints
```

---

## Output

```
══[ INFRASTRUCTURE ]══════════════════════════════════════
  [+] https://target.example.com/
  [+] https://target.example.com/api/
  ...

══[ TECHNOLOGIES DETECTED ]═══════════════════════════════
  [+] Angular 15.2

══[ JAVASCRIPT ANALYSIS ]═════════════════════════════════
  [>] 12 JS findings — secrets: 2  endpoints: 8  other: 2
  [~] [SECRET] Google OAuth Client ID | Match: 1005568...com
  [>] [ENDPOINT] REST API path | Match: /rest/admin
  ...

══[ VULNERABILITIES & FINDINGS ]══════════════════════════
  [~] [api_probe] Reflected XSS candidate [MEDIUM] — GET /rest/admin?id=sdt...
  [~] [api_probe] Input crash [MEDIUM] — POST /api/Feedbacks (200 → 500)
  [>] [bypass403] 403 Bypass MULTIPLE SIGNATURES — /ftp/secret.md
  ...

══[ SUMMARY ]═════════════════════════════════════════════
  HIGH: 1   MEDIUM: 6   INFO: 12
```

---

## Requirements

- Python 3.9+
- [JsFuzzer](https://github.com/Suizer/JsFuzzer) (for the `jsfuzzer` module)

---

## Credits

Built on top of [bbot](https://github.com/blacklanternsecurity/bbot) by Black Lantern Security.  
Custom modules and saudit engine by [@suizer](https://github.com/Suizer).
