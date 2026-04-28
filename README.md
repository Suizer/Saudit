# Saudit

Autonomous web reconnaissance and vulnerability scanning framework. Passive-first, plugin-based pipeline designed for authorized penetration testing and security assessments.

## Installation

```bash
pip install -e .
```

Requires Python 3.9+. External tool dependencies (ffuf, nuclei, masscan, wafw00f) are installed automatically on first use.

## Scan presets

Saudit is organized around four progressive presets. Each one extends the previous.

```
initial → web-basic → web-authenticated → web-authenticated-thorough
```

### 1. `initial` — Passive-first recon

No brute-force. Safe to run as the first step on any authorized target.

```bash
saudit -t https://app.example.com -p initial
```

Covers:
- **HTTP fingerprinting** — technology detection, WAF detection, NTLM endpoint discovery
- **Port scanning** — TCP port scan + service fingerprinting (RDP, SSH, MySQL, etc.)
- **SSL/TLS** — certificate inspection and subdomain discovery
- **JS analysis** — static analysis for secrets, endpoints and source maps (`jsfuzzer`), vulnerable libraries (`retirejs`)
- **API discovery** — Swagger/OpenAPI and GraphQL introspection
- **Secrets** — hardcoded secrets in HTTP headers/cookies (`badsecrets`)
- **Security posture** — security headers audit, robots.txt, security.txt
- **Source code exposure** — exposed `.git` detection, Git repo download, external repo link discovery, self-hosted GitLab enumeration
- **Nuclei** — technology fingerprinting templates only (`tags: tech`) — not the full template library
- **CMS advisor** — automatically detects WordPress, Mendix, IIS/ASP.NET and recommends the appropriate specialized preset and nuclei variant

> **Note:** `cms_advisor` emits actionable findings when a CMS or stack is detected, including the exact command to run the recommended module or preset.

---

### 2. `web-basic` — Standard web audit (no credentials)

Extends `initial` with active enumeration.

```bash
saudit -t https://app.example.com -p web-basic

# Custom wordlist
saudit -t https://app.example.com -p web-basic \
  -c modules.ffuf.wordlist=/opt/wordlists/raft-medium-dirs.txt
```

Adds:
- **403 bypass** — common bypass techniques against forbidden resources
- **Subdomain takeover** — dangling DNS detection (`baddns`)
- **Directory discovery** — surface-level ffuf (2000 lines, depth 1, 50 req/s)
- **File harvesting** — downloads exposed PDFs, DOCX, ZIP, SQL dumps, keys, configs and extracts their text content
- **API probing** — active canary injection on endpoints discovered by swagger/graphql

---

### 3. `web-authenticated` — Authenticated audit

Requires an active session. Extends `web-basic` with parameter mining and fuzzing.

```bash
# Bearer token
saudit -t https://app.example.com -p web-authenticated --bearer <token>

# Cookie
saudit -t https://app.example.com -p web-authenticated -C session=abc123
```

Adds:
- **Session validation** — verifies the provided credentials are actually authenticated before proceeding
- **Parameter mining** — GET params, headers and cookie parameter discovery
- **Reflected parameters** — confirms which parameters reflect in responses
- **SQLi on APIs** — error-based SQLi probe on discovered API endpoints
- **Lightfuzz** — parameter fuzzing for SQLi, XSS, SSTI, SSRF, path traversal, CMDi, ESI, crypto

> `ai_review` automatically recommends the appropriate lightfuzz sub-preset based on signals found during the scan (reflected params, hunt findings, API surface, hidden params).

---

### 4. `web-authenticated-thorough` — Full aggressive audit

All modules active. Authorized targets with explicit written approval only.

```bash
saudit -t https://app.example.com -p web-authenticated-thorough -C session=abc123
```

Adds:
- **Host header injection**
- **SSRF probing**
- **HTTP request smuggling**
- **URL manipulation bypasses**
- Lightfuzz reconfigured: POST enabled, force-fuzz common headers, test each param instance individually, speculate params from JSON/XML responses

---

## Optional sub-presets

Combine with any main preset using multiple `-p` flags.

### Nuclei strategy

Nuclei is intentionally excluded from `web-basic` to give you control over timing and noise. Choose the variant that matches the engagement context:

```bash
# Standard — full template library, directory roots only (safe default)
saudit -t https://app.example.com -p web-basic -p nuclei

# Budget — ~10 requests per host, low noise (use when WAF is present)
saudit -t https://app.example.com -p web-basic -p nuclei-budget

# Technology — only templates matching detected technologies (most surgical)
saudit -t https://app.example.com -p web-basic -p nuclei-technology

# Intense — all URLs, no directory_only restriction (use with spider)
saudit -t https://app.example.com -p web-basic -p spider -p nuclei-intense
```

> `cms_advisor` will recommend the appropriate nuclei variant automatically when it detects a specific stack or WAF.

### Directory brute-force

```bash
# Surface-level (IIS shortname enumeration included)
saudit -t https://app.example.com -p web-basic -p dirbust-light

# Aggressive recursive (depth 3, extensions, 5000-line wordlist)
saudit -t https://app.example.com -p web-basic -p ffuf-heavy

# IIS target — combine ffuf-heavy with iis-shortnames
saudit -t https://app.example.com -p web-basic -p ffuf-heavy -p iis-shortnames
```

### IIS / .NET stack

```bash
# Full IIS/.NET audit (Telerik, DotNetNuke, AjaxPro, shortnames, bin exposure)
saudit -t https://app.example.com -p web-basic -p dotnet-audit
```

> `cms_advisor` recommends `dotnet-audit` automatically when IIS or ASP.NET is detected.

### Parameter fuzzing

```bash
# Only XSS via GET — most surgical
saudit -t https://app.example.com -p web-basic -p lightfuzz-xss

# All vulns, no POST — safe default
saudit -t https://app.example.com -p web-basic -p lightfuzz-light

# All vulns, no POST, adds paramminer + badsecrets + hunt
saudit -t https://app.example.com -p web-basic -p lightfuzz-medium

# POST enabled, paramminer included
saudit -t https://app.example.com -p web-basic -p lightfuzz-heavy

# Maximum — force common headers, individual param instances, speculate params
saudit -t https://app.example.com -p web-basic -p lightfuzz-superheavy
```

### Specialized modules

These modules are not included in any preset and must be added manually with `-m`. `cms_advisor` recommends them when the relevant technology is detected.

```bash
# WordPress — user, plugin and theme enumeration + CVEs
saudit -t https://app.example.com -p web-basic -m wpscan

# Mendix — deep access-control testing
saudit -t https://app.example.com -p web-basic -m mendix_recon

# Re-seed from a previous scan (skip re-discovery, reuse known endpoints)
saudit -t https://app.example.com -p web-authenticated \
  -m from_report -c modules.from_report.report_file=scan.json --bearer <token>
```

### Sub-preset reference

| Sub-preset | Description |
|---|---|
| `nuclei` | Full Nuclei template library, directory roots only |
| `nuclei-budget` | Nuclei budget mode (~10 req/host) — recommended when WAF detected |
| `nuclei-technology` | Nuclei templates matching detected technologies only |
| `nuclei-intense` | Nuclei against ALL discovered URLs, no directory_only restriction |
| `dirbust-light` | Surface-level directory brute-force (includes IIS shortname enumeration) |
| `ffuf-heavy` | Recursive directory brute-force (depth 3, extensions, 5000-line wordlist) |
| `iis-shortnames` | IIS 8.3 shortname enumeration |
| `dotnet-audit` | Full IIS/.NET audit: Telerik, DotNetNuke, AjaxPro, bin exposure |
| `paramminer` | Parameter discovery only — GET params, headers, cookies |
| `lightfuzz-xss` | Parameter fuzzing limited to XSS via GET |
| `lightfuzz-light` | All vuln classes, no POST, minimal modules |
| `lightfuzz-medium` | All vuln classes, no POST, adds paramminer + badsecrets + hunt |
| `lightfuzz-heavy` | POST enabled, paramminer included |
| `lightfuzz-superheavy` | Maximum — force headers, individual instances, speculate params |

---

## Recommended workflows

**Unknown target, start here:**
```bash
saudit -t https://app.example.com -p initial
# Read cms_advisor findings, then decide next step
```

**Standard unauthenticated audit:**
```bash
saudit -t https://app.example.com -p web-basic -p nuclei
```

**Authenticated audit:**
```bash
saudit -t https://app.example.com -p web-authenticated -p nuclei --bearer <token>
```

**IIS / .NET target:**
```bash
saudit -t https://app.example.com -p web-basic -p dotnet-audit -p nuclei-technology
```

**WordPress target:**
```bash
saudit -t https://app.example.com -p web-basic -p nuclei-technology -m wpscan
```

**WAF present — stay quiet:**
```bash
saudit -t https://app.example.com -p web-basic -p nuclei-budget
```

**Full aggressive (approved):**
```bash
saudit -t https://app.example.com -p web-authenticated-thorough -p nuclei-intense --bearer <token>
```

---

## CLI reference

```
Target:
  -t TARGET             Target URL, domain, or IP
  -w WHITELIST          In-scope whitelist (defaults to target)
  -b BLACKLIST          Exclude these hosts/paths
  --strict-scope        Disable subdomain expansion
  --bearer TOKEN        Authorization: Bearer <TOKEN> on every request
  -C cookie=value       Custom cookies

Presets:
  -p PRESET [PRESET ..] One or more presets (main + optional sub-presets)
  -c key=value          Override config options
  -lp                   List all available presets

Modules:
  -m MODULE [MODULE ..]  Enable specific modules
  -f FLAG [FLAG ..]      Enable modules by flag (e.g. -f passive)
  -ef FLAG               Exclude modules with this flag (e.g. -ef aggressive)
  -em MODULE             Exclude a specific module
  -l                     List all scan modules
  -lo                    List all output modules
  -lf                    List all flags
  -mh MODULE             Show all config options for a module

Scan:
  -n SCAN_NAME           Name the scan
  -y                     Skip confirmation prompt
  -s                     Silent mode
  -v / -d                Verbose / debug output
  --dry-run              Validate config without running
  --current-preset       Print the active preset YAML and exit

Output:
  -o DIR                 Output directory (default: ./<scan_name>/)
  -om MODULE [MODULE ..]  Output modules
  -j / --json            JSON output to stdout

HTTP:
  --proxy URL            HTTP/HTTPS proxy
  -H header=value        Custom request headers
  -ua USER_AGENT         Override User-Agent
  --custom-yara-rules    Additional YARA rules for secret detection
```

---

## Modules

### Scan modules

| Module | Preset | Description |
|---|---|---|
| `httpx` | initial | HTTP crawler — required by most modules |
| `portscan` | initial | TCP port scan (masscan) |
| `fingerprintx` | initial | Service fingerprinting on open ports (RDP, SSH, MySQL…) |
| `robots` | initial | Parse robots.txt |
| `securitytxt` | initial | Parse security.txt |
| `ntlm` | initial | NTLM endpoint detection (exposes AD domain info) |
| `wafw00f` | initial | WAF detection |
| `sslcert` | initial | SSL/TLS certificate inspection + subdomain discovery |
| `oauth` | initial | OAuth/OIDC endpoint discovery |
| `azure_realm` | initial | Azure tenant discovery |
| `badsecrets` | initial | Detect known/weak secrets in web frameworks |
| `jsfuzzer` | initial | JS static analysis — secrets, endpoints, source maps |
| `retirejs` | initial | Detect vulnerable JavaScript libraries |
| `git` | initial | Exposed `.git` directory detection |
| `code_repository` | initial | Detect links to external repos (GitHub, GitLab, Docker Hub) |
| `gitdumper` | initial | Download and reconstruct exposed Git repositories |
| `gitlab_onprem` | initial | Self-hosted GitLab detection and repo enumeration |
| `swagger_probe` | initial | OpenAPI/Swagger endpoint discovery |
| `graphql_introspection` | initial | GraphQL introspection |
| `hunt` | initial | Flag parameters commonly linked to injection vulns |
| `security_headers` | initial | HTTP security headers audit |
| `nuclei` | initial (tech only) | Nuclei template scanner |
| `cms_advisor` | initial | Detect CMS/stack and recommend specialized presets and nuclei variants |
| `bypass403` | web-basic | 403 bypass techniques |
| `baddns` | web-basic | Subdomain takeover detection |
| `ffuf` | web-basic | Web directory/file brute-force |
| `filedownload` | web-basic | Download PDFs, DOCX, ZIP, SQL dumps, keys, configs |
| `extractous` | web-basic | Extract text from downloaded files |
| `api_probe` | web-basic | Active injection probe on discovered API endpoints |
| `session_check` | web-authenticated | Validate session before proceeding |
| `paramminer_getparams` | web-authenticated | GET parameter mining |
| `paramminer_headers` | web-authenticated | HTTP header parameter mining |
| `paramminer_cookies` | web-authenticated | Cookie parameter mining |
| `reflected_parameters` | web-authenticated | Reflected parameter detection |
| `api_sqli_probe` | web-authenticated | Error-based SQLi on API endpoints |
| `lightfuzz` | web-authenticated | Parameter fuzzer (SQLi, XSS, SSTI, SSRF, path, CMDi, ESI) |
| `host_header` | web-authenticated-thorough | Host header injection |
| `generic_ssrf` | web-authenticated-thorough | SSRF probing |
| `smuggler` | web-authenticated-thorough | HTTP request smuggling |
| `url_manipulation` | web-authenticated-thorough | URL normalization bypass |
| `iis_shortnames` | sub-preset | IIS 8.3 shortname enumeration |
| `ffuf_shortnames` | sub-preset | ffuf + IIS shortnames combo |
| `ajaxpro` | sub-preset | AjaxPro RCE detection |
| `aspnet_bin_exposure` | sub-preset | ASP.NET bin exposure |
| `dotnetnuke` | sub-preset | DotNetNuke vulnerability scan |
| `telerik` | sub-preset | Telerik UI vulnerability scan |
| `portfilter` | sub-preset | Filter open ports on CDNs/WAFs |
| `wpscan` | standalone | WordPress vulnerability scan (use when WordPress detected) |
| `mendix_recon` | standalone | Mendix access-control testing (use when Mendix detected) |
| `from_report` | standalone | Re-seed scan from a previous JSON output |

### Output modules

| Module | Description |
|---|---|
| `html_report` | Self-contained HTML report (default in all presets) |
| `ai_review` | AI-powered analysis — WAF-aware commands, lightfuzz recommendations, source map review |
| `json` | NDJSON file (`output.json`, default in all presets) |
| `stdout` | Plain-text terminal output |

---

## AI review

`ai_review` runs after the scan and produces a prioritized attack plan using Ollama (local) or Gemini (cloud fallback).

**Backend setup:**
```bash
# Ollama (recommended — local, free)
ollama pull qwen2.5-coder:7b
ollama serve

# Gemini fallback
export GEMINI_API_KEY=...
```

**What it produces:**
- Prioritized attack plan with ready-to-run commands using real target URLs and parameters
- WAF-aware payloads with specific evasion techniques per detected WAF vendor
- Source map / JS code review with targeted commands
- Hardcoded secrets and exposed sensitive files highlighted as critical
- **Lightfuzz recommendation** — suggests the appropriate lightfuzz sub-preset based on signals found (reflected params, hunt findings, API surface, hidden params)
- **Next steps** — specialized modules and manual actions not yet performed, with exact commands

**Override model or skip map review:**
```bash
saudit -t https://app.example.com -p initial \
  -c modules.ai_review.ollama_model=llama3.1:8b \
  -c modules.ai_review.analyze_maps=false
```

---

## Configuration

All config options can be overridden with `-c key=value`:

```bash
# Custom ffuf wordlist
saudit -t https://app.example.com -p web-basic \
  -c modules.ffuf.wordlist=/opt/wordlists/raft-medium-dirs.txt

# Deeper spider
saudit -t https://app.example.com -p initial \
  -c web.spider_distance=3 \
  -c web.spider_depth=6

# Run through Burp Suite
saudit -t https://app.example.com -p web-authenticated \
  --bearer <token> --proxy http://127.0.0.1:8080

# GitLab on-prem with API key for private repos
saudit -t https://app.example.com -p initial \
  -c modules.gitlab_onprem.api_key=glpat-xxxx

# Nuclei with specific tags
saudit -t https://app.example.com -p web-basic -p nuclei \
  -c modules.nuclei.tags=cve,sqli

# Show the resolved preset before running
saudit -t https://app.example.com -p web-authenticated --current-preset
```

Key config paths:

| Path | Default | Description |
|---|---|---|
| `web.spider_distance` | 3 | Max link hops from seed URL |
| `web.spider_depth` | 5 | Max directory depth |
| `web.spider_links_per_page` | 30 | Max links followed per page |
| `web.http_timeout` | 5 | HTTP timeout (seconds) |
| `modules.ffuf.wordlist` | raft-small-directories | ffuf wordlist URL or path |
| `modules.ffuf.lines` | 2000 | Max lines to read from wordlist |
| `modules.ffuf.rate` | 50 | ffuf requests per second |
| `modules.nuclei.tags` | `""` (all) | Nuclei template tags filter |
| `modules.gitlab_onprem.api_key` | `""` | GitLab API token (public repos only if unset) |
| `dns.threads` | 25 | DNS resolver threads |
| `scope.strict` | false | Disable subdomain expansion |

---

## Development

```bash
# Install dev dependencies
pip install -e .
pre-commit install

# Lint / format
ruff check saudit/
ruff format saudit/

# Run all tests
pytest --exitfirst --disable-warnings --log-cli-level=ERROR saudit/

# Run a single test by keyword
pytest -k test_preset_module_resolution saudit/

# Run module tests only
saudit/test/run_tests.sh [module_name]
```
