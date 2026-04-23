import sys
import json
import re
import asyncio
import shutil
from pathlib import Path

from saudit.modules.base import BaseModule

_CHUNK_NAME_RE = re.compile(
    r"(?:^|[-_.])(?:\d+|chunk[-_][a-f0-9]+|runtime[~-]|vendors[-_]|framework[-_]|polyfill)"
    r"(?:\.chunk)?\.js$",
    re.IGNORECASE,
)


def _is_chunk_map(map_path: Path) -> bool:
    """Skip webpack chunk maps that contain only framework internals or empty sources."""
    if _CHUNK_NAME_RE.search(map_path.name):
        return True
    try:
        data = json.loads(map_path.read_text(encoding="utf-8", errors="replace"))
        sources = data.get("sources", [])
        contents = data.get("sourcesContent", [])
        if not sources:
            return True
        if all("webpack" in (s or "").lower() or (s or "").startswith("(") for s in sources):
            return True
        non_empty = sum(1 for c in contents if c and len(c.strip()) > 50)
        if contents and non_empty / len(contents) < 0.3:
            return True
    except Exception:
        return True
    return False


class jsfuzzer(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING", "TECHNOLOGY"]
    flags = ["active", "safe"]
    meta = {
        "description": "Analyse JS files with JsFuzzer — secrets, endpoints, source maps",
        "created_date": "2024-01-01",
        "author": "@suizer",
    }

    accept_url_special = True

    options = {
        "tool_path": "",
        "severity_filter": ["critical", "high", "medium", "info"],
    }
    options_desc = {
        "tool_path": "Absolute path to the JsFuzzer directory",
        "severity_filter": "Only emit findings at or above these severity levels",
    }

    in_scope_only = True

    async def setup(self):
        self._seen_urls = set()

        tool_path = (
            self.config.get("tool_path")
            or self.scan.config.get("consulting", {}).get("jsfuzzer_path", "")
        )
        if not tool_path:
            self.warning("JsFuzzer path not configured — set modules.jsfuzzer.tool_path in your preset")
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
            from core.map import unpack_map

            self._JScanner = JScanner
            self._download_js_file = download_js_file
            self._deobfuscate = deobfuscate
            self._unpack_map = unpack_map
        except ImportError as e:
            return None, f"Failed to import JsFuzzer modules: {e}"

        self._severity_filter = set(self.config.get("severity_filter", ["critical", "high", "medium", "info"]))
        self._tmp_dir = self.scan.home / "jsfuzzer_files"
        self._tmp_dir.mkdir(parents=True, exist_ok=True)
        return True

    async def filter_event(self, event):
        url = event.data
        if not isinstance(url, str):
            return False, "not a string URL"
        if not url.lower().split("?")[0].endswith(".js"):
            return False, "not a .js URL"
        if url in self._seen_urls:
            return False, "already processed"
        self._seen_urls.add(url)
        return True, ""

    async def handle_event(self, event):
        url = event.data
        loop = asyncio.get_event_loop()

        # Download JS
        try:
            success, js_path = await loop.run_in_executor(
                None, self._download_js_file, url, self._tmp_dir
            )
        except Exception as e:
            self.debug(f"Download failed for {url}: {e}")
            return

        if not success or not js_path:
            return

        js_path = Path(js_path)
        files_to_scan = []

        # Check for source map alongside the JS
        map_path = Path(str(js_path) + ".map")
        if map_path.exists() and not _is_chunk_map(map_path):
            unpack_dir = self._tmp_dir / "unpacked_sources"
            try:
                await loop.run_in_executor(None, self._unpack_map, map_path, unpack_dir)
                for src in unpack_dir.rglob("*"):
                    if src.is_file() and src.suffix in (".js", ".ts", ".jsx", ".tsx", ".vue"):
                        files_to_scan.append(src)
            except Exception as e:
                self.debug(f"Map unpack error for {map_path.name}: {e}")

        # Deobfuscate + scan the original JS if no source files extracted
        if not files_to_scan:
            try:
                ast_result = await loop.run_in_executor(None, self._deobfuscate, js_path)
                if ast_result and ast_result.success:
                    deob_path = js_path.with_suffix(".deob.js")
                    deob_path.write_text(ast_result.code, encoding="utf-8", errors="replace")
                    files_to_scan.append(deob_path)
                else:
                    files_to_scan.append(js_path)
            except Exception:
                files_to_scan.append(js_path)

        host = event.host
        emitted_frameworks = set()
        scanner = self._JScanner(config_dir=str(self._tool_path / "config"))

        for scan_path in files_to_scan:
            try:
                findings = await loop.run_in_executor(None, scanner.scan_file, scan_path)
            except Exception as e:
                self.verbose(f"Scan error on {scan_path.name}: {e}")
                continue

            if not findings:
                continue

            for finding in findings:
                severity = finding.get("severity", "info").lower()
                ftype = finding.get("type", "").upper()

                if ftype == "FRAMEWORK":
                    name = finding.get("name", "")
                    if name and name not in emitted_frameworks:
                        emitted_frameworks.add(name)
                        await self.emit_event(
                            {"host": str(host), "technology": name, "url": url},
                            "TECHNOLOGY",
                            parent=event,
                            context=f"{{module}} detected {{event.type}} {name} in JS at {url}",
                        )
                    continue

                if severity not in self._severity_filter:
                    continue

                if self._is_false_positive(finding):
                    continue

                source_file = scan_path.name if scan_path != js_path else ""
                desc_parts = [f"[{ftype}] {finding.get('name', 'Unknown')}"]
                if source_file:
                    desc_parts.append(f"Source: {source_file}")
                if finding.get("match"):
                    desc_parts.append(f"Match: {finding['match']}")
                if finding.get("context"):
                    desc_parts.append(f"Context: {finding['context']}")
                if finding.get("line"):
                    desc_parts.append(f"Line: {finding['line']}")

                await self.emit_event(
                    {"host": str(host), "url": url, "description": " | ".join(desc_parts)},
                    "FINDING",
                    parent=event,
                    tags=["jsfuzzer", f"severity-{severity}", ftype.lower()],
                    context=f"{{module}} found {{event.type}} ({severity.upper()}) in {url}: {finding.get('name', '')}",
                )

    def _is_false_positive(self, finding: dict) -> bool:
        ftype   = finding.get("type", "").upper()
        match   = finding.get("match", "") or ""
        context = finding.get("context", "") or ""
        name    = finding.get("name", "") or ""

        # ENTROPY: base64/hex charsets — just alphabets, not secrets
        if ftype == "ENTROPY":
            clean = match.replace("...", "")
            if all(c in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/=-_" for c in clean if c.strip()):
                return True
            # Angular form validator arrays: [J.required, J.minLength, J.maxLength...]
            if any(kw in context for kw in ("minLength", "maxLength", "required", "Validators")):
                return True

        # SECRET: empty string assignment  password="" / password=''
        if ftype == "SECRET" and "Password" in name:
            stripped = match.strip("\"'* ")
            if stripped == "" or stripped == "***":
                # check context — empty string init is not a real credential
                if 'password=""' in context.lower() or "password=''" in context.lower():
                    return True

        # URL: external documentation links — no attack surface
        if ftype == "URL":
            doc_domains = (
                "angular.dev", "owasp.org", "socket.io/docs",
                "developer.mozilla", "w3.org", "schema.org",
                "freeprivacypolicy.com",
            )
            if any(d in match for d in doc_domains):
                return True

        return False

    async def cleanup(self):
        # Move JS files to scan output dir for manual review instead of deleting
        try:
            if hasattr(self, "_tmp_dir") and self._tmp_dir.exists():
                dest = self.scan.home / "js_analysis"
                if dest.exists():
                    shutil.rmtree(dest, ignore_errors=True)
                shutil.move(str(self._tmp_dir), str(dest))
                self.info(f"JS files preserved for review at {dest}")
        except Exception:
            pass
