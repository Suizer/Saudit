import sys
import asyncio
from pathlib import Path

from bbot.modules.base import BaseModule


class jsfuzzer(BaseModule):
    """
    Integration module: downloads JavaScript files discovered by BBOT and
    passes them through the JsFuzzer static analysis engine (AST deobfuscation +
    secret/endpoint pattern matching).

    Requires JsFuzzer to be present on disk. Set the path via:
        -c consulting.jsfuzzer_path=/path/to/JsFuzzer/JsFuzzer
    """

    watched_events = ["URL"]
    produced_events = ["FINDING", "TECHNOLOGY"]
    flags = ["active", "safe"]
    meta = {
        "description": "Analyse discovered JavaScript files with JsFuzzer (secrets, endpoints, frameworks)",
        "created_date": "2024-01-01",
        "author": "@consulting",
    }

    # JS URLs are marked "special" in BBOT — opt-in required
    accept_url_special = True

    options = {
        "tool_path": "",
        "severity_filter": ["critical", "high", "medium"],
    }
    options_desc = {
        "tool_path": "Absolute path to the JsFuzzer directory (overrides consulting.jsfuzzer_path)",
        "severity_filter": "Only emit findings at or above these severity levels",
    }

    in_scope_only = True

    async def setup(self):
        self._seen_urls = set()
        self._scanner = None

        tool_path = self.config.get("tool_path") or self.scan.config.get("consulting", {}).get("jsfuzzer_path", "")
        if not tool_path:
            self.warning("JsFuzzer path not configured — module disabled. Set consulting.jsfuzzer_path or modules.jsfuzzer.tool_path")
            return None, "jsfuzzer_path not set"

        tool_path = Path(tool_path).expanduser().resolve()
        if not tool_path.is_dir():
            return None, f"JsFuzzer path does not exist: {tool_path}"

        self._tool_path = tool_path
        if str(tool_path) not in sys.path:
            sys.path.insert(0, str(tool_path))

        try:
            from core.scanner import JScanner
            from core.downloader import download_js_file
            from core.ast_engine import deobfuscate

            self._JScanner = JScanner
            self._download_js_file = download_js_file
            self._deobfuscate = deobfuscate
        except ImportError as e:
            return None, f"Failed to import JsFuzzer modules: {e}"

        self._severity_filter = set(self.config.get("severity_filter", ["critical", "high", "medium"]))
        self._tmp_dir = self.scan.home / "jsfuzzer_tmp"
        self._tmp_dir.mkdir(parents=True, exist_ok=True)
        return True

    async def filter_event(self, event):
        url = event.data
        if not isinstance(url, str):
            return False, "not a string URL"
        lower = url.lower().split("?")[0]
        if not lower.endswith(".js"):
            return False, "not a .js URL"
        if url in self._seen_urls:
            return False, "already processed"
        return True, ""

    async def handle_event(self, event):
        url = event.data
        self._seen_urls.add(url)

        # Download JS file to temp dir
        try:
            loop = asyncio.get_event_loop()
            success, js_path = await loop.run_in_executor(
                None, self._download_js_file, url, self._tmp_dir
            )
        except Exception as e:
            self.debug(f"Download failed for {url}: {e}")
            return

        if not success or not js_path:
            self.debug(f"Could not download {url}")
            return

        # Deobfuscate
        try:
            ast_result = await asyncio.get_event_loop().run_in_executor(
                None, self._deobfuscate, js_path
            )
            if ast_result and ast_result.success:
                scan_path = js_path.with_suffix(".deob.js")
                scan_path.write_text(ast_result.code, encoding="utf-8", errors="replace")
            else:
                scan_path = js_path
        except Exception as e:
            self.debug(f"Deobfuscation error for {url}: {e}")
            scan_path = js_path

        # Static analysis
        try:
            scanner = self._JScanner()
            findings = await asyncio.get_event_loop().run_in_executor(
                None, scanner.scan_file, scan_path
            )
        except Exception as e:
            self.verbose(f"JsFuzzer scan error for {url}: {e}")
            return

        if not findings:
            return

        host = event.host
        emitted_frameworks = set()

        for finding in findings:
            severity = finding.get("severity", "info").lower()
            ftype = finding.get("type", "").upper()

            # Emit framework detections as TECHNOLOGY events
            if ftype == "FRAMEWORK":
                name = finding.get("name", "")
                if name and name not in emitted_frameworks:
                    emitted_frameworks.add(name)
                    await self.emit_event(
                        {"host": str(host), "technology": name, "url": url},
                        "TECHNOLOGY",
                        parent=event,
                        context=f"{{module}} detected {{event.type}} {name} in JavaScript at {url}",
                    )
                continue

            # Filter non-interesting severities
            if severity not in self._severity_filter and "info" not in self._severity_filter:
                continue

            desc_parts = [f"[{ftype}] {finding.get('name', 'Unknown')}"]
            if finding.get("match"):
                desc_parts.append(f"Match: {finding['match']}")
            if finding.get("context"):
                desc_parts.append(f"Context: {finding['context']}")
            if finding.get("line"):
                desc_parts.append(f"Line: {finding['line']}")

            await self.emit_event(
                {
                    "host": str(host),
                    "url": url,
                    "description": " | ".join(desc_parts),
                },
                "FINDING",
                parent=event,
                tags=[f"jsfuzzer", f"severity-{severity}", ftype.lower()],
                context=f"{{module}} found {{event.type}} ({severity.upper()}) in {url}: {finding.get('name', '')}",
            )

    async def cleanup(self):
        import shutil
        try:
            if hasattr(self, "_tmp_dir") and self._tmp_dir.exists():
                shutil.rmtree(self._tmp_dir, ignore_errors=True)
        except Exception:
            pass
