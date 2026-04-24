from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import NamedTuple

log = logging.getLogger("saudit.modules.jsfuzzer")

_ENGINE_DIR = Path(__file__).resolve().parent.parent.parent.parent / "engine"
_TRANSFORMER = _ENGINE_DIR / "transformer.js"
AST_TIMEOUT = 30
AST_MAX_FILE_SIZE = 5 * 1024 * 1024


class ASTResult(NamedTuple):
    code: str
    method: str
    stats: dict
    success: bool


def _check_node_available() -> bool:
    return shutil.which("node") is not None


def _check_engine_installed() -> bool:
    return (_ENGINE_DIR / "node_modules").is_dir()


def _run_transformer(input_path: Path, output_path: Path) -> tuple[bool, dict]:
    cmd = ["node", str(_TRANSFORMER), str(input_path), "--output", str(output_path)]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=AST_TIMEOUT, cwd=str(_ENGINE_DIR)
        )
        stats = {}
        for line in result.stderr.splitlines():
            if line.startswith("[AST_STATS]"):
                try:
                    stats = json.loads(line.replace("[AST_STATS] ", ""))
                except json.JSONDecodeError:
                    pass
        if result.returncode != 0:
            return False, stats
        if not output_path.exists() or output_path.stat().st_size == 0:
            return False, stats
        return True, stats
    except subprocess.TimeoutExpired:
        return False, {}
    except FileNotFoundError:
        return False, {}


def _beautify_fallback(code: str) -> str:
    try:
        import jsbeautifier
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        opts.unescape_strings = True
        return jsbeautifier.beautify(code, opts)
    except ImportError:
        return code


def deobfuscate(file_path: Path) -> ASTResult:
    file_path = Path(file_path)
    if not file_path.exists():
        return ASTResult(code="", method="original", stats={}, success=False)

    original_code = file_path.read_text(encoding="utf-8", errors="replace")

    if file_path.stat().st_size > AST_MAX_FILE_SIZE:
        beautified = _beautify_fallback(original_code)
        file_path.write_text(beautified, encoding="utf-8")
        return ASTResult(code=beautified, method="beautifier", stats={}, success=True)

    if not _check_node_available() or not _TRANSFORMER.exists():
        beautified = _beautify_fallback(original_code)
        file_path.write_text(beautified, encoding="utf-8")
        return ASTResult(code=beautified, method="beautifier", stats={}, success=True)

    with tempfile.NamedTemporaryFile(suffix=".js", delete=False, mode="w") as tmp:
        tmp_output = Path(tmp.name)

    try:
        success, stats = _run_transformer(file_path, tmp_output)
        if success and tmp_output.exists():
            transformed = tmp_output.read_text(encoding="utf-8", errors="replace")
            if len(transformed.strip()) < len(original_code.strip()) * 0.1:
                beautified = _beautify_fallback(original_code)
                file_path.write_text(beautified, encoding="utf-8")
                return ASTResult(code=beautified, method="beautifier", stats=stats, success=True)
            file_path.write_text(transformed, encoding="utf-8")
            return ASTResult(code=transformed, method="ast", stats=stats, success=True)
        else:
            beautified = _beautify_fallback(original_code)
            file_path.write_text(beautified, encoding="utf-8")
            return ASTResult(code=beautified, method="beautifier", stats={}, success=True)
    finally:
        try:
            tmp_output.unlink(missing_ok=True)
        except OSError:
            pass
