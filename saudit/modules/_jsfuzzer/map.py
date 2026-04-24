from __future__ import annotations

import json
import logging
import os
from pathlib import Path

log = logging.getLogger("saudit.modules.jsfuzzer")


def unpack_map(map_file, output_base_dir) -> bool:
    """Unpack a .map file extracting original source files."""
    map_path = Path(map_file)
    if not map_path.exists():
        return False

    try:
        data = json.loads(map_path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        log.debug(f"Failed to parse map {map_path.name}: {e}")
        return False

    if "sources" not in data or "sourcesContent" not in data:
        return False

    unpack_dir = (
        Path(output_base_dir)
        / "unpacked_sources"
        / map_path.name.replace(".js.map", "").replace(".map", "")
    )
    extracted = 0

    for path, content in zip(data["sources"], data["sourcesContent"]):
        clean = (
            path.replace("webpack:///", "")
            .replace("webpack://", "")
            .replace("../", "")
            .lstrip("/")
        )
        out = unpack_dir / clean
        os.makedirs(os.path.dirname(out), exist_ok=True)
        try:
            out.write_text(content if content else "// empty", encoding="utf-8", errors="replace")
            extracted += 1
        except Exception:
            pass

    log.debug(f"Unpacked {extracted} sources from {map_path.name}")
    return extracted > 0
