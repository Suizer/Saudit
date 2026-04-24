from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger("saudit.modules.jsfuzzer")


def download_js_file(url: str, target_dir) -> tuple[bool, Path | None]:
    """Download a JS file and attempt to fetch its accompanying .map file."""
    import httpx

    target_dir = Path(target_dir)
    filename = url.split("/")[-1].split("?")[0] or "index.js"
    target_path = target_dir / filename

    try:
        response = httpx.get(url, timeout=10, verify=False, follow_redirects=True)
        if response.status_code != 200:
            return False, None
        target_path.write_text(response.text, encoding="utf-8", errors="replace")

        # Attempt to fetch source map
        map_response = httpx.get(f"{url}.map", timeout=5, verify=False, follow_redirects=True)
        if map_response.status_code == 200 and map_response.text.lstrip().startswith("{"):
            map_path = target_dir / f"{filename}.map"
            map_path.write_text(map_response.text, encoding="utf-8", errors="replace")
            log.debug(f"Source map found: {filename}.map")

        return True, target_path
    except Exception as e:
        log.debug(f"Download failed for {url}: {e}")
        return False, None
