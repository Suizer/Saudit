import sys
import json
import asyncio
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from saudit.modules.base import BaseModule


# Response patterns that strongly indicate a Mendix application
MENDIX_SIGNATURES = [
    "x-mendix-version",   # response header
    "mxui.js",            # core Mendix JS bundle
    "/xas/",              # client-server bridge path
    "mx.session",         # JS API surface
    "mendix",             # generic brand mention
    "com.mendix",         # Java package namespace
]


class mendix_recon(BaseModule):
    """
    Integration module: detects Mendix low-code applications in HTTP responses
    and automatically runs MendixRecon against them.

    Detection is passive (signature matching on responses BBOT already fetched).
    The MendixRecon subprocess is spawned only once per unique host.

    Requires MendixRecon to be present on disk. Set the path via:
        -c consulting.mendix_recon_path=/path/to/mendix_recon
    """

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING", "TECHNOLOGY"]
    flags = ["active", "safe"]
    meta = {
        "description": "Detect Mendix apps and run MendixRecon for deep access-control testing",
        "created_date": "2024-01-01",
        "author": "@consulting",
    }

    options = {
        "tool_path": "",
        "modules": ["endpoints", "session"],
        "full": False,
    }
    options_desc = {
        "tool_path": "Absolute path to the mendix_recon directory (overrides consulting.mendix_recon_path)",
        "modules": "MendixRecon modules to run (endpoints, session, entities, pages, access)",
        "full": "Run all MendixRecon modules (equivalent to --full flag)",
    }

    # HTTP_RESPONSE events are internal by default; accept them anyway
    scope_distance_modifier = None

    async def setup(self):
        self._seen_hosts = set()
        self._tool_path = None

        tool_path = self.config.get("tool_path") or self.scan.config.get("consulting", {}).get("mendix_recon_path", "")
        if not tool_path:
            self.warning(
                "MendixRecon path not configured — module disabled. "
                "Set consulting.mendix_recon_path or modules.mendix_recon.tool_path"
            )
            return None, "mendix_recon_path not set"

        tool_path = Path(tool_path).expanduser().resolve()
        if not (tool_path / "main.py").is_file():
            return None, f"MendixRecon main.py not found at: {tool_path}"

        self._tool_path = tool_path
        self._run_full = self.config.get("full", False)
        self._modules = self.config.get("modules", ["endpoints", "session"])
        return True

    async def filter_event(self, event):
        # Only process actual HTTP responses (dict with url + headers)
        if not isinstance(event.data, dict):
            return False, "not an HTTP_RESPONSE dict"
        return True, ""

    async def handle_event(self, event):
        data = event.data
        url = data.get("url", "")
        if not url:
            return

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        host_key = parsed.netloc

        if host_key in self._seen_hosts:
            return
        if not self._is_mendix(data):
            return

        self._seen_hosts.add(host_key)
        self.verbose(f"Mendix application detected at {base_url} — launching MendixRecon")

        await self.emit_event(
            {"host": str(event.host), "technology": "Mendix", "url": base_url},
            "TECHNOLOGY",
            parent=event,
            context=f"{{module}} detected {{event.type}} Mendix at {base_url}",
        )

        findings = await asyncio.get_event_loop().run_in_executor(
            None, self._run_mendix_recon, base_url
        )

        for finding in findings:
            severity = finding.get("severity", "Info").lower()
            title = finding.get("title", "Mendix finding")
            description = finding.get("description", "")
            evidence = finding.get("evidence", "")
            endpoint = finding.get("endpoint", "")

            desc_parts = [title]
            if endpoint:
                desc_parts.append(f"Endpoint: {endpoint}")
            if description:
                desc_parts.append(description)
            if evidence:
                desc_parts.append(f"Evidence: {evidence[:200]}")

            await self.emit_event(
                {
                    "host": str(event.host),
                    "url": base_url + (endpoint if endpoint.startswith("/") else f"/{endpoint}"),
                    "description": " | ".join(desc_parts),
                },
                "FINDING",
                parent=event,
                tags=["mendix-recon", f"severity-{severity}", finding.get("type", "unknown").replace("_", "-")],
                context=f"{{module}} found {{event.type}} ({severity.upper()}) via MendixRecon on {base_url}: {title}",
            )

    def _is_mendix(self, response_data: dict) -> bool:
        headers = response_data.get("header", {})
        body = response_data.get("body", "") or ""

        for sig in MENDIX_SIGNATURES:
            sig_lower = sig.lower()
            # Check response headers (keys are lowercased by BBOT)
            for hk, hv in headers.items():
                if sig_lower in hk.lower() or sig_lower in str(hv).lower():
                    return True
            # Check response body (case-insensitive)
            if sig_lower in body.lower():
                return True
        return False

    def _run_mendix_recon(self, base_url: str) -> list:
        json_output_path = self._tool_path / f"mendix_findings_{hash(base_url)}.json"
        cmd = [
            sys.executable,
            str(self._tool_path / "main.py"),
            "-t", base_url,
            "--json-output", str(json_output_path),
            "-q",
        ]
        if self._run_full:
            cmd.append("--full")
        else:
            cmd += ["--modules"] + list(self._modules)

        try:
            result = subprocess.run(
                cmd,
                cwd=str(self._tool_path),
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                self.verbose(f"MendixRecon stderr: {result.stderr[:500]}")
        except subprocess.TimeoutExpired:
            self.warning(f"MendixRecon timed out for {base_url}")
            return []
        except Exception as e:
            self.warning(f"MendixRecon subprocess error: {e}")
            return []

        if not json_output_path.is_file():
            return []

        try:
            raw = json.loads(json_output_path.read_text(encoding="utf-8"))
            return raw.get("findings", [])
        except Exception as e:
            self.verbose(f"Failed to parse MendixRecon output: {e}")
            return []
        finally:
            try:
                json_output_path.unlink(missing_ok=True)
            except Exception:
                pass
