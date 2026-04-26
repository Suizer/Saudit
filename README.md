# Saudit

Autonomous web reconnaissance and vulnerability scanning framework. Passive-first, plugin-based pipeline designed for authorized penetration testing and security assessments.

## Installation

```bash
pip install -e .
```

Requires Python 3.9+. External tool dependencies (ffuf, nuclei, masscan, wafw00f) are installed automatically on first use.

## Scan presets

Saudit is organized around four progressive presets. Each one extends the previous.

### 1. `initial` — Passive-first recon

No brute-force. Safe to run as the first step on any authorized target.

```bash
saudit -t https://app.example.com -p initial
```

Covers: technology fingerprinting, JS analysis, API discovery (Swagger, GraphQL), exposed secrets (`badsecrets`), vulnerable JS libraries, exposed Git, security headers, subdomain discovery via SSL certs and OAuth endpoints, WAF detection.

---

### 2. `web-basic` — Standard web audit (no credentials)

Extends `initial` with full Nuclei template coverage, 403 bypass, subdomain takeover detection, and surface-level directory discovery.

```bash
saudit -t https://app.example.com -p web-basic

# Custom wordlist
saudit -t https://app.example.com -p web-basic \
  -c modules.ffuf.wordlist=/opt/wordlists/raft-medium-dirs.txt
```

ffuf defaults: `raft-small-directories`, 2000 lines, depth 1, 50 req/s.

---

### 3. `web-authenticated` — Authenticated audit

Requires an active session. Extends `web-basic` with parameter mining and lightfuzz.

```bash
# Bearer token
saudit -t https://app.example.com -p web-authenticated --bearer <token>

# Cookie
saudit -t https://app.example.com -p web-authenticated -C session=abc123
```

Adds: GET/header/cookie parameter mining, reflected parameter detection, error-based SQLi on discovered endpoints, lightfuzz (SQLi, XSS, SSTI, SSRF, path traversal, CMDi).

---

### 4. `web-authenticated-thorough` — Full aggressive audit

All modules active. Authorized targets with explicit written approval only.

```bash
saudit -t https://app.example.com -p web-authenticated-thorough -C session=abc123
```

Adds: POST parameter fuzzing, force-fuzz common headers, host header injection, SSRF probing, HTTP request smuggling, URL manipulation bypasses.

---

## Optional sub-presets

Combine with any main preset using multiple `-p` flags:

```bash
saudit -t https://app.example.com -p web-basic -p dotnet-audit
saudit -t https://app.example.com -p web-authenticated -p nuclei
```

| Sub-preset | Description |
|------------|-------------|
| `dotnet-audit` | Full IIS/.NET audit: Telerik, DotNetNuke, AjaxPro, ASP.NET bin exposure |
| `dirbust-light` | Surface-level directory brute-force (ffuf) |
| `dirbust-heavy` | Recursive directory brute-force with file extensions |
| `paramminer` | Full parameter discovery: GET params, headers, cookies |
| `lightfuzz-light` | Lightweight parameter fuzzing (minimal modules) |
| `lightfuzz-medium` | Standard parameter fuzzing, no POST requests |
| `lightfuzz-heavy` | Full fuzzing with POST, paramminer included |
| `lightfuzz-superheavy` | All lightfuzz with POST, force headers, individual param instances |
| `nuclei` | Run all Nuclei templates |
| `nuclei-budget` | Nuclei in budget mode (low request count) |
| `nuclei-technology` | Nuclei technology-detection templates only |

## CLI reference

```
Target:
  -t TARGET             Target URL, domain, or IP
  -w WHITELIST          In-scope whitelist (defaults to target)
  -b BLACKLIST          Exclude these hosts/paths
  --strict-scope        Disable subdomain expansion
  --bearer TOKEN        Authorization: Bearer <TOKEN> on every request
  -r FILE               Re-seed from a previous scan's output.json

Presets:
  -p PRESET [PRESET ..] One or more presets (main + optional sub-presets)
  -c key=value          Override config options
  -lp                   List all available presets

Modules:
  -m MODULE [MODULE ..]  Enable specific modules
  -f FLAG [FLAG ..]      Enable modules by flag (e.g. -f passive)
  -rf FLAG               Only enable modules that have this flag
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
  --fast-mode            Minimal discovery, scan targets directly
  --current-preset       Print the active preset YAML and exit
  --allow-deadly         Enable deadly modules (vhost, legba, medusa)

Output:
  -o DIR                 Output directory (default: ./<scan_name>/)
  -om MODULE [MODULE ..]  Output modules
  -j / --json            JSON output to stdout
  --event-types TYPES    Filter stdout event types

HTTP:
  --proxy URL            HTTP/HTTPS proxy
  -H header=value        Custom request headers
  -C cookie=value        Custom cookies
  -ua USER_AGENT         Override User-Agent
  --custom-yara-rules    Additional YARA rules for secret detection
```

## Modules

### Scan modules

| Module | Flags | Description |
|--------|-------|-------------|
| `httpx` | active, safe | HTTP crawler — required by most modules |
| `robots` | active, safe | Parse robots.txt |
| `securitytxt` | active, safe | Parse security.txt |
| `ntlm` | active, safe | NTLM endpoint detection (exposes AD domain info) |
| `wafw00f` | active, aggressive | WAF detection |
| `badsecrets` | active, safe | Detect known/weak secrets in web frameworks |
| `baddns` | active, safe | Subdomain takeover detection |
| `sslcert` | active, safe, subdomain-enum | SSL/TLS certificate inspection + subdomain discovery |
| `oauth` | active, safe, subdomain-enum | OAuth/OIDC endpoint discovery + subdomain discovery |
| `azure_realm` | passive, safe, cloud-enum | Azure tenant discovery |
| `git` | active, safe, code-enum | Exposed `.git` directory detection |
| `graphql_introspection` | active, safe | GraphQL introspection |
| `swagger_probe` | active, safe | OpenAPI/Swagger endpoint discovery |
| `jsfuzzer` | active, safe | JS static analysis: secrets, endpoints, source maps |
| `retirejs` | active, safe | Detect vulnerable JavaScript libraries |
| `hunt` | active, safe | Flag parameters commonly linked to injection vulns |
| `bypass403` | active, aggressive | 403 bypass techniques |
| `api_probe` | active, aggressive | Canary XSS + SQLi probe on discovered API endpoints |
| `api_sqli_probe` | active, aggressive | Error-based SQLi on JsFuzzer-discovered endpoints |
| `reflected_parameters` | active, safe | Reflected parameter detection |
| `host_header` | active, aggressive | Host header injection |
| `generic_ssrf` | active, aggressive | SSRF probing |
| `smuggler` | active, slow | HTTP request smuggling |
| `url_manipulation` | active, aggressive | URL normalization bypass |
| `ffuf` | active, aggressive, deadly | Web directory/file brute-force |
| `nuclei` | active, aggressive, deadly | Nuclei template scanner |
| `lightfuzz` | active, aggressive, deadly | Parameter fuzzer (SQLi, XSS, SSTI, SSRF, path, CMDi) |
| `paramminer_getparams` | active, aggressive, slow, web-paramminer | GET parameter mining |
| `paramminer_headers` | active, aggressive, slow, web-paramminer | HTTP header parameter mining |
| `paramminer_cookies` | active, aggressive, slow, web-paramminer | Cookie parameter mining |
| `iis_shortnames` | active, safe, iis-shortnames | IIS 8.3 shortname enumeration |
| `ffuf_shortnames` | active, aggressive, iis-shortnames | ffuf + IIS shortnames combo |
| `ajaxpro` | active, safe | AjaxPro RCE detection |
| `aspnet_bin_exposure` | active, safe | ASP.NET bin exposure (CVE-2023-36899/36560) |
| `dotnetnuke` | active, aggressive | DotNetNuke vulnerability scan |
| `telerik` | active, aggressive | Telerik UI vulnerability scan |
| `vhost` | active, slow, deadly | Virtual host brute-force |
| `medusa` | active, aggressive, deadly | Credential brute-force |
| `legba` | active, aggressive, deadly | Multi-protocol credential testing |
| `wpscan` | active, aggressive | WordPress vulnerability scan |
| `portscan` | active, safe, portscan | TCP port scan (masscan, requires root) |
| `fingerprintx` | active, safe, service-enum | Service fingerprinting (RDP, SSH, MySQL…) |
| `gitdumper` | passive, safe, code-enum | Download exposed Git repos |
| `code_repository` | passive, safe, code-enum | Code repository detection |
| `gitlab_onprem` | active, safe, code-enum | Self-hosted GitLab detection |
| `mendix_recon` | active, safe | Mendix application-specific recon |
| `filedownload` | active, safe | Download PDFs, DOCX, PPTX for offline review |
| `extractous` | passive, safe | Text extraction from downloaded files |
| `newsletters` | active, safe | Newsletter subscription endpoint detection |
| `portfilter` | passive, safe | Filter open ports on CDNs/WAFs |
| `from_report` | passive, safe | Re-seed scan from a previous JSON output |

### Output modules

| Module | Description |
|--------|-------------|
| `html_report` | Self-contained HTML report (default in all presets) |
| `consulting_report` | HTML report with severity classification and reproduction steps |
| `ai_review` | AI-powered finding review — requires Ollama or OpenAI (default in all presets) |
| `json` | NDJSON file (`output.json`, default in all presets) |
| `stdout` | Plain-text terminal output |
| `webpeas` | Colour-coded, section-grouped terminal output |
| `web_report` | Lightweight HTML report |
| `csv` | CSV file |
| `txt` | Plain-text hosts list |
| `subdomains` | Unique subdomains TXT file |
| `emails` | Unique email addresses TXT file |
| `web_parameters` | Discovered web parameters CSV |
| `asset_inventory` | Host/port/service inventory CSV |
| `progress` | Live progress bar |
| `http` | POST events to an HTTP endpoint |
| `websocket` | Stream events over WebSocket |
| `slack` / `discord` / `teams` | Webhook notifications |
| `sqlite` / `postgres` / `mysql` / `neo4j` | Database output |

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

# Nuclei with specific tags
saudit -t https://app.example.com -p web-basic \
  -c modules.nuclei.tags=cve,sqli

# Add custom YARA rules to secret detection
saudit -t https://app.example.com -p initial \
  --custom-yara-rules /path/to/rules.yar

# Show the resolved preset before running
saudit -t https://app.example.com -p web-authenticated --current-preset
```

Key config paths (from `defaults.yml`):

| Path | Default | Description |
|------|---------|-------------|
| `web.spider_distance` | 1 | Max link hops from seed URL |
| `web.spider_depth` | 4 | Max directory depth |
| `web.spider_links_per_page` | 20 | Max links followed per page |
| `web.http_timeout` | 5 | HTTP timeout (seconds) |
| `modules.ffuf.wordlist` | raft-small-directories | ffuf wordlist URL or path |
| `modules.ffuf.lines` | 2000 | Max lines to read from wordlist |
| `modules.ffuf.rate` | 50 | ffuf requests per second |
| `modules.nuclei.tags` | `""` (all) | Nuclei template tags filter |
| `dns.threads` | 25 | DNS resolver threads |
| `scope.strict` | false | Disable subdomain expansion |

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
