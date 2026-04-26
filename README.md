# Saudit

Autonomous web reconnaissance and vulnerability scanning framework. Passive-first, plugin-based pipeline designed for authorized penetration testing and security assessments.

## Installation

```bash
pip install -e .
```

Requires Python 3.9+. Some modules have external tool dependencies (ffuf, nuclei, masscan, wafw00f) that are installed automatically on first use via Ansible.

## Quick start

```bash
# Stealth recon (primary use case — minimal noise, no brute-force)
saudit -t https://app.example.com -p webpeas-stealth

# Authenticated scan (add session via bearer token or cookie)
saudit -t https://app.example.com -p authenticated --bearer <token>
saudit -t https://app.example.com -p authenticated -C session=abc123

# Active initial recon (crawl + JS analysis + nuclei tech scan + dir brute-force)
saudit -t https://app.example.com -p initial

# Consulting engagement — single URL scope
saudit -t https://app.example.com -p consulting-url-only -o ./results

# Consulting engagement — full domain/IP scope
saudit -t example.com -p consulting-full-scope -o ./results
```

## Presets

| Preset | Description |
|--------|-------------|
| `webpeas-stealth` | Passive-first recon: httpx, robots, NTLM, badsecrets, bypass403, JsFuzzer, swagger probe, API probe. WebPeas terminal output. |
| `authenticated` | Extends `initial` with parameter mining (`paramminer_*`) and reflected parameter detection. Requires active session. |
| `initial` | Active fingerprinting: crawl, JS analysis, API discovery, nuclei (tech tags), retirejs, secret detection, dir brute-force. **Authorized use only.** |
| `consulting-url-only` | Narrow scope (single URL). SQLi probe, bypass403, JsFuzzer, Mendix recon, retirejs. No subdomain expansion. |
| `consulting-full-scope` | Full domain/IP scope. Adds subdomain enumeration, SSL cert analysis, OAuth discovery, IIS shortnames. |
| `web-basic` | Non-intrusive web modules: robots, NTLM, badsecrets, git, IIS shortnames, GraphQL, sslcert. |
| `web-thorough` | Aggressive web audit: all web-basic + lightfuzz, host header injection, SSRF, smuggling, param mining. |
| `spider` | Recursive web crawler only. |
| `spider-intense` | Spider with deep crawl settings. |
| `subdomain-enum` | Passive subdomain discovery via SSL certificates and OAuth endpoints. |
| `cloud-enum` | Detect cloud infrastructure: Azure realm, OAuth endpoints, bad DNS records. |
| `email-enum` | Collect email addresses from SSL certificates. |
| `code-enum` | Discover exposed Git repositories and source-code hosting endpoints. |
| `tech-detect` | Technology detection via Nuclei and FingerprintX. |
| `baddns-intense` | Full baddns suite for subdomain takeover detection. |
| `web/dirbust-light` | Surface-level directory brute-force with ffuf. |
| `web/dirbust-heavy` | Recursive directory brute-force with ffuf. |
| `web/dotnet-audit` | Full IIS/.NET audit: Telerik, DotNetNuke, AjaxPro, ASP.NET bin exposure. |
| `web/lightfuzz-light` | Lightweight parameter fuzzing (XSS, SQLi, path traversal). |
| `web/lightfuzz-medium` | Standard parameter fuzzing across all vulnerability classes. |
| `web/paramminer` | Full parameter discovery: GET params, headers, cookies. |
| `nuclei/nuclei` | Run all Nuclei templates. |
| `nuclei/nuclei-technology` | Nuclei technology-detection templates only. |
| `nuclei/nuclei-budget` | Nuclei with a conservative template set. |

## CLI reference

```
Target:
  -t TARGET             Target URL, domain, or IP
  -w WHITELIST          In-scope whitelist (defaults to target)
  -b BLACKLIST          Exclude these hosts/paths
  --strict-scope        No subdomain expansion
  --bearer TOKEN        Authorization: Bearer <TOKEN> on every request
  -r FILE               Re-seed from a previous scan's output.json

Presets:
  -p PRESET [PRESET ..] One or more presets to enable
  -c key=value          Override config options (e.g. -c web.spider_depth=5)
  -lp                   List all available presets

Modules:
  -m MODULE [MODULE ..]  Enable specific modules
  -f FLAG [FLAG ..]      Enable modules by flag (e.g. -f web-basic)
  -rf FLAG               Only enable modules that have this flag (e.g. -rf passive)
  -ef FLAG               Exclude modules with this flag (e.g. -ef aggressive)
  -em MODULE             Exclude a specific module
  -l                     List all scan modules
  -lo                    List all output modules
  -lf                    List all flags
  -mh MODULE             Show detailed help for a module

Scan:
  -n SCAN_NAME           Name the scan
  -y                     Skip confirmation prompt
  -s                     Silent mode
  -v / -d                Verbose / debug output
  --dry-run              Validate config without running
  --fast-mode            Minimal discovery, scan targets directly
  --current-preset       Print the active preset YAML and exit
  --allow-deadly         Enable deadly modules (vhost, legba, medusa, ffuf, nuclei, lightfuzz)

Output:
  -o DIR                 Output directory (default: ./<scan_name>/)
  -om MODULE [MODULE ..]  Output modules (default: python, csv, txt, json)
  -j / --json            JSON output to stdout
  --event-types TYPES    Filter stdout event types

HTTP:
  --proxy URL            HTTP/HTTPS proxy
  -H header=value        Custom request headers
  -C cookie=value        Custom cookies
  -ua USER_AGENT         Override User-Agent
  --custom-yara-rules    Additional YARA rules for excavate
```

## Modules

### Scan modules

| Module | Flags | Description |
|--------|-------|-------------|
| `httpx` | active, safe, web-basic | HTTP crawler. Required by most other modules. |
| `robots` | active, safe, web-basic | Parse robots.txt |
| `securitytxt` | active, safe, web-basic | Parse security.txt |
| `ntlm` | active, safe, web-basic | NTLM endpoint detection (exposes AD domain info) |
| `badsecrets` | active, safe, web-basic | Detect known/weak secrets in web frameworks |
| `baddns` | active, safe, web-basic | Subdomain takeover detection |
| `graphql_introspection` | active, safe, web-basic | GraphQL introspection |
| `git` | active, safe, web-basic | Exposed `.git` directory detection |
| `iis_shortnames` | active, safe, web-basic | IIS 8.3 shortname enumeration |
| `sslcert` | active, safe, web-basic | SSL/TLS certificate inspection |
| `oauth` | active, safe, web-basic | OAuth/OIDC endpoint discovery |
| `azure_realm` | passive, safe, web-basic | Azure tenant discovery |
| `filedownload` | active, safe, web-basic | Download PDFs, DOCX, PPTX for offline review |
| `jsfuzzer` | active, safe | JS static analysis: secrets, endpoints, source maps |
| `swagger_probe` | active, safe, web-thorough | OpenAPI/Swagger endpoint discovery |
| `bypass403` | active, aggressive, web-thorough | 403 bypass techniques |
| `api_probe` | active, aggressive, web-thorough | Canary XSS + SQLi probe on discovered API endpoints |
| `api_sqli_probe` | active, aggressive, web-thorough | Error-based SQLi on JsFuzzer-discovered endpoints |
| `hunt` | active, safe, web-thorough | Flag parameters commonly linked to injection vulns |
| `retirejs` | active, safe, web-thorough | Detect vulnerable JavaScript libraries |
| `reflected_parameters` | active, safe, web-thorough | Reflected parameter detection |
| `host_header` | active, aggressive, web-thorough | Host header injection |
| `generic_ssrf` | active, aggressive, web-thorough | SSRF probing |
| `smuggler` | active, slow, web-thorough | HTTP request smuggling |
| `url_manipulation` | active, aggressive, web-thorough | URL normalization bypass |
| `ajaxpro` | active, safe, web-thorough | AjaxPro RCE detection |
| `aspnet_bin_exposure` | active, safe, web-thorough | ASP.NET bin exposure (CVE-2023-36899/36560) |
| `dotnetnuke` | active, aggressive, web-thorough | DotNetNuke vulnerability scan |
| `telerik` | active, aggressive, web-thorough | Telerik UI vulnerability scan |
| `ffuf` | active, aggressive, **deadly** | Web directory/file brute-force |
| `nuclei` | active, aggressive, **deadly** | Nuclei template scanner |
| `lightfuzz` | active, aggressive, **deadly** | Parameter fuzzer (SQLi, XSS, SSTI, SSRF, path, cmdi) |
| `vhost` | active, slow, **deadly** | Virtual host brute-force |
| `medusa` | active, aggressive, **deadly** | Credential brute-force |
| `legba` | active, aggressive, **deadly** | Multi-protocol credential testing |
| `wafw00f` | active, aggressive | WAF detection |
| `wpscan` | active, aggressive | WordPress vulnerability scan |
| `ffuf_shortnames` | active, aggressive, iis-shortnames | ffuf + IIS shortnames combo |
| `paramminer_headers` | active, aggressive, slow, web-paramminer | HTTP header parameter mining |
| `paramminer_getparams` | active, aggressive, slow, web-paramminer | GET parameter mining |
| `paramminer_cookies` | active, aggressive, slow, web-paramminer | Cookie parameter mining |
| `portscan` | active, safe, portscan | TCP port scan (masscan, requires root) |
| `fingerprintx` | active, safe, service-enum | Service fingerprinting (RDP, SSH, MySQL…) |
| `asn` | passive, safe, subdomain-enum | ASN lookup |
| `gitdumper` | passive, safe, code-enum | Download exposed Git repos |
| `code_repository` | passive, safe, code-enum | Code repository detection |
| `gitlab_onprem` | active, safe, code-enum | Self-hosted GitLab detection |
| `extractous` | passive, safe | Text extraction from downloaded files |
| `from_report` | passive, safe | Re-seed scan from a previous JSON output |
| `mendix_recon` | active, safe | Mendix application-specific recon |
| `newsletters` | active, safe | Newsletter subscription endpoint detection |
| `portfilter` | passive, safe | Filter open ports on CDNs/WAFs |

### Output modules

| Module | Description |
|--------|-------------|
| `webpeas` | Colour-coded, section-grouped terminal output (primary output for `webpeas-stealth`) |
| `stdout` | Plain-text terminal output |
| `json` | NDJSON file (`output.json`) |
| `html_report` | Self-contained HTML report |
| `consulting_report` | HTML report with severity classification and reproduction steps |
| `web_report` | Lightweight HTML report |
| `ai_review` | AI-powered finding review (requires Ollama or OpenAI) |
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
# Increase spider depth
saudit -t https://app.example.com -p webpeas-stealth \
  -c web.spider_distance=3 \
  -c web.spider_depth=5

# Custom JsFuzzer path
saudit -t https://app.example.com -p webpeas-stealth \
  -c modules.jsfuzzer.tool_path=/opt/JsFuzzer

# Disable request delay (consulting presets add jitter by default)
saudit -t https://app.example.com -p consulting-url-only \
  -c consulting.request_delay_min=0 \
  -c consulting.request_delay_max=0

# Set Nuclei tags
saudit -t https://app.example.com -m nuclei \
  -c modules.nuclei.tags=cve,tech

# Add custom YARA rules to secret detection
saudit -t https://app.example.com -p webpeas-stealth \
  --custom-yara-rules /path/to/rules.yar
```

Key config paths (from `defaults.yml`):

| Path | Default | Description |
|------|---------|-------------|
| `web.spider_distance` | 1 | Max link hops from seed URL |
| `web.spider_depth` | 4 | Max directory depth |
| `web.spider_links_per_page` | 20 | Max links followed per page |
| `web.http_timeout` | 5 | HTTP timeout (seconds) |
| `web.http_proxy` | — | Proxy URL |
| `dns.search_distance` | 1 | DNS subdomain expansion depth |
| `dns.threads` | 25 | DNS resolver threads |
| `scope.strict` | false | Disable subdomain expansion |
| `home` | `.` | Output base directory |

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

# Run a single test by name
pytest -k test_preset_module_resolution saudit/

# Run module tests only
saudit/test/run_tests.sh [module_name]
```
