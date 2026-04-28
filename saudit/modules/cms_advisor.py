from collections import defaultdict

from saudit.modules.base import BaseModule


class cms_advisor(BaseModule):
    watched_events = ["TECHNOLOGY", "WAF", "URL"]
    produced_events = ["FINDING"]
    flags = ["passive", "safe"]
    meta = {
        "description": (
            "Detect CMS/stack platforms and WAFs, then recommend the most appropriate "
            "specialized preset or module for deeper coverage, including the right nuclei variant."
        ),
        "created_date": "2026-04-28",
        "author": "@saudit",
    }

    # technology keyword (lowercase) → advisory config
    _tech_advisories = {
        "wordpress": {
            "label": "WordPress",
            "tool_cmd": "saudit [...] -m wpscan",
            "tool_why": "wpscan enumerates WordPress users, plugins and themes and checks them against WPVulnDB.",
            "nuclei_preset": "nuclei-technology",
            "nuclei_why": (
                "nuclei-technology runs only templates that match already-detected technologies. "
                "For WordPress this means WP-specific CVE checks (xmlrpc, user enumeration, plugin vulns) "
                "with zero template noise from unrelated stacks."
            ),
        },
        "mendix": {
            "label": "Mendix",
            "tool_cmd": "saudit [...] -m mendix_recon",
            "tool_why": "mendix_recon performs deep access-control testing specific to the Mendix platform.",
            "nuclei_preset": "nuclei-technology",
            "nuclei_why": (
                "nuclei-technology restricts execution to Mendix-matched templates, "
                "avoiding thousands of irrelevant requests against a platform with a small template surface."
            ),
        },
        "iis": {
            "label": "IIS",
            "tool_cmd": "saudit [...] -p dotnet-audit",
            "tool_why": (
                "dotnet-audit runs the full IIS/.NET surface: shortname enumeration, Telerik UI exploitation, "
                "AjaxPro RCE probe, DotNetNuke checks and exposed .ashx/.asmx/.aspx endpoint brute-force."
            ),
            "nuclei_preset": "nuclei-technology",
            "nuclei_why": (
                "nuclei-technology targets IIS-specific templates: shortname disclosure, "
                "HTTP.sys vulnerabilities, trace.axd exposure, and ASP.NET debug endpoints — "
                "without running the full template library against a Windows stack."
            ),
        },
        "asp.net": {
            "label": "ASP.NET",
            "tool_cmd": "saudit [...] -p dotnet-audit",
            "tool_why": (
                "dotnet-audit runs the full IIS/.NET surface: shortname enumeration, Telerik UI exploitation, "
                "AjaxPro RCE probe, DotNetNuke checks and exposed .ashx/.asmx/.aspx endpoint brute-force."
            ),
            "nuclei_preset": "nuclei-technology",
            "nuclei_why": (
                "nuclei-technology targets ASP.NET-specific templates: ViewState MAC validation, "
                "elmah.axd log exposure, trace.axd, debug mode detection and known CVEs "
                "— runs only what applies to the detected stack."
            ),
        },
    }

    # URL path fragments that confirm HubSpot CMS (SaaS — no plugin vulns, different attack surface)
    _HUBSPOT_PATHS = frozenset({"/_hcms/", "/hs-fs/", "/hs/hsstatic/", "/hubfs/", "/hs/"})

    async def setup(self):
        # host → set of detected tech keys
        self._detected_tech = defaultdict(set)
        # host → WAF name (None if no WAF)
        self._detected_waf = {}
        # host → set of already-emitted tool advisory keys (to deduplicate across report() calls)
        self._emitted = defaultdict(set)
        # hosts where HubSpot paths were confirmed via URL events
        self._hubspot_hosts = set()
        return True

    async def handle_event(self, event):
        host = str(event.host)

        if event.type == "WAF":
            waf_name = event.data.get("waf", "unknown WAF") if isinstance(event.data, dict) else str(event.data)
            if host not in self._detected_waf:
                self._detected_waf[host] = waf_name

        elif event.type == "TECHNOLOGY":
            technology = event.data.get("technology", "").lower() if isinstance(event.data, dict) else str(event.data).lower()
            for key in self._tech_advisories:
                if key in technology:
                    self._detected_tech[host].add(key)

        elif event.type == "URL":
            url = str(event.data) if isinstance(event.data, str) else event.data.get("url", "")
            if any(frag in url for frag in self._HUBSPOT_PATHS):
                self._hubspot_hosts.add(host)

    async def report(self):
        all_hosts = set(self._detected_tech) | set(self._detected_waf) | self._hubspot_hosts

        for host in all_hosts:
            waf = self._detected_waf.get(host)
            tech_keys = self._detected_tech.get(host, set())

            # WAF advisory — emit once per host
            if waf and "waf" not in self._emitted[host]:
                self._emitted[host].add("waf")
                await self.emit_event(
                    {
                        "host": host,
                        "description": (
                            f"{waf} detected — nuclei recommendation: use nuclei-budget to avoid "
                            f"rate-limiting and detection. nuclei-budget limits requests to ~10 per host "
                            f"and skips individual non-directory URLs. Command: saudit [...] -p nuclei-budget"
                        ),
                    },
                    "FINDING",
                    context=f"{{module}} recommends nuclei-budget due to detected WAF ({waf})",
                )

            # HubSpot advisory — SaaS CMS, different attack surface than self-hosted CMSes
            if host in self._hubspot_hosts and "hubspot" not in self._emitted[host]:
                self._emitted[host].add("hubspot")
                await self.emit_event(
                    {
                        "host": host,
                        "description": (
                            "HubSpot CMS detected (SaaS) — attack surface differs from self-hosted CMSes: "
                            "1) Check HubDB public tables: https://<host>/api/v3/hubdb/tables (may expose structured data without auth). "
                            "2) Search JS for HubSpot API keys: grep -r 'hapikey=' or 'HAPI_KEY' in downloaded JS. "
                            "3) Test contact/form endpoints for injection: /dejanos-blindarte, /contact, /hs-search-results?term=. "
                            "4) Check for private content accessible without auth (HubSpot memberships misconfiguration). "
                            "5) nuclei-technology will cover HubSpot-specific CVE templates. "
                            "Command: saudit [...] -p nuclei-technology"
                        ),
                    },
                    "FINDING",
                    context="{module} detected HubSpot CMS — recommending HubSpot-specific attack surface checks",
                )

            for key in tech_keys:
                cfg = self._tech_advisories[key]

                # Specialized tool/preset recommendation
                tool_key = f"tool:{key}"
                if tool_key not in self._emitted[host]:
                    self._emitted[host].add(tool_key)
                    await self.emit_event(
                        {
                            "host": host,
                            "description": (
                                f"{cfg['label']} detected — run specialized tooling: {cfg['tool_cmd']} | "
                                f"Why: {cfg['tool_why']}"
                            ),
                        },
                        "FINDING",
                        context=f"{{module}} recommends specialized tooling for {cfg['label']}",
                    )

                # Nuclei recommendation — only if NO WAF on this host
                nuclei_key = f"nuclei:{key}"
                if nuclei_key not in self._emitted[host] and not waf:
                    self._emitted[host].add(nuclei_key)
                    await self.emit_event(
                        {
                            "host": host,
                            "description": (
                                f"{cfg['label']} detected — nuclei recommendation: use {cfg['nuclei_preset']} "
                                f"instead of full nuclei. {cfg['nuclei_why']} "
                                f"Command: saudit [...] -p {cfg['nuclei_preset']}"
                            ),
                        },
                        "FINDING",
                        context=f"{{module}} recommends {cfg['nuclei_preset']} for {cfg['label']} stack",
                    )
