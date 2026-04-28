import json
import os

import httpx

from saudit.modules.base import BaseModule


class osint_enum(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "FINDING"]
    flags = ["passive", "safe"]
    meta = {
        "description": (
            "OSINT-based host/subdomain discovery via crt.sh (free) and Shodan (API key). "
            "Useful for finding origin IPs behind CDN/WAF and historical infrastructure. "
            "Add API keys to .env: SHODAN_API_KEY. "
            "Run standalone: saudit -t domain.com -m osint_enum"
        ),
        "created_date": "2026-04-28",
        "author": "@saudit",
    }
    options = {
        "shodan_key": "",
    }
    options_desc = {
        "shodan_key": "Shodan API key (or set SHODAN_API_KEY env var / .env)",
    }

    # Only process the root domain seed, not every DNS_NAME downstream
    per_domain_only = True

    async def setup(self):
        self._shodan_key = self._resolve_env("SHODAN_API_KEY", self.config.get("shodan_key", ""))
        self._processed = set()
        return True

    async def handle_event(self, event):
        domain = str(event.data).lower().strip()

        # Only process root domains (no subdomains)
        if domain.count(".") > 1:
            return
        if domain in self._processed:
            return
        self._processed.add(domain)

        found = set()

        # ── crt.sh — free, no key ─────────────────────────────────────────────
        try:
            async with httpx.AsyncClient(timeout=20) as c:
                r = await c.get(
                    "https://crt.sh/",
                    params={"q": f"%.{domain}", "output": "json"},
                    headers={"Accept": "application/json"},
                )
                if r.status_code == 200:
                    for entry in r.json():
                        for name in entry.get("name_value", "").splitlines():
                            name = name.strip().lstrip("*.")
                            if name.endswith(f".{domain}") or name == domain:
                                found.add(name)
        except Exception as e:
            self.debug(f"crt.sh error: {e}")

        # ── Shodan — requires API key ─────────────────────────────────────────
        if self._shodan_key:
            try:
                async with httpx.AsyncClient(timeout=20) as c:
                    r = await c.get(
                        "https://api.shodan.io/dns/domain/{domain}".format(domain=domain),
                        params={"key": self._shodan_key},
                    )
                    if r.status_code == 200:
                        data = r.json()
                        for sub in data.get("subdomains", []):
                            found.add(f"{sub}.{domain}")

                        # Shodan also returns IPs — emit as FINDING so the pentester
                        # can check if any bypass Cloudflare
                        ips = {e.get("value") for e in data.get("data", [])
                               if e.get("type") in ("A", "AAAA") and e.get("value")}
                        if ips:
                            await self.emit_event(
                                {
                                    "host": domain,
                                    "description": (
                                        f"Shodan — historical IPs for {domain}: {', '.join(sorted(ips))}. "
                                        "Check if any resolve directly (possible origin behind WAF/CDN): "
                                        + " | ".join(f"curl -H 'Host: {domain}' https://{ip}/ -k" for ip in sorted(ips))
                                    ),
                                },
                                "FINDING",
                                context=f"{{module}} found historical IPs for {domain} via Shodan",
                            )
            except Exception as e:
                self.debug(f"Shodan error: {e}")

        # Emit discovered subdomains
        for subdomain in sorted(found):
            await self.emit_event(subdomain, "DNS_NAME", event)

        if found:
            self.verbose(f"osint_enum: {len(found)} hosts discovered for {domain} (crt.sh + Shodan)")
        else:
            self.verbose(f"osint_enum: no hosts found for {domain}")

    def _resolve_env(self, env_var: str, default: str = "") -> str:
        val = os.environ.get(env_var, "")
        if val:
            return val
        from pathlib import Path
        env_file = Path(__file__).parent.parent.parent / ".env"
        if env_file.is_file():
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if line.startswith(f"{env_var}="):
                    val = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if val:
                        return val
        return default
