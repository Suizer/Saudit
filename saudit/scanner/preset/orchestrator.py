from __future__ import annotations

from dataclasses import dataclass
from contextlib import suppress
from pathlib import Path

import yaml

# Resolve preset dirs without importing path.py (avoids circular init chain).
# Search both saudit/presets/ (built-ins) and the outer presets/ (custom).
_HERE = Path(__file__).parent
_PRESET_DIRS: list[Path] = [
    (_HERE.parent.parent / "presets").resolve(),          # saudit/presets/
    (_HERE.parent.parent.parent / "presets").resolve(),   # repo-root/presets/
]


@dataclass(frozen=True)
class PresetRecommendation:
    current: str
    next: str | None
    escalation_desc: str


# Escalation prose — topology data stays in YAML, descriptions stay here
_ESCALATION: dict[str, tuple[str | None, str]] = {
    "initial": (
        "web-basic",
        "Adds: bypass403, directory busting (ffuf), subdomain takeover (baddns), "
        "file harvesting (filedownload/extractous), API endpoint probing (api_probe). "
        "No authentication required.",
    ),
    "web-basic": (
        "web-authenticated",
        "Adds: session validation, parameter discovery (paramminer GET/headers/cookies), "
        "reflected parameter detection, SQL injection probing on APIs (api_sqli_probe), "
        "full fuzzing suite (lightfuzz: sqli/xss/ssti/cmdi/path/crypto/serial/esi). "
        "REQUIRES a valid session — pass --cookie or --bearer.",
    ),
    "web-authenticated": (
        "web-authenticated-thorough",
        "Adds: host header injection, generic SSRF probing, HTTP smuggling (smuggler), "
        "URL manipulation bypasses. Forces common headers, probes all parameter instances. "
        "Aggressive — use only with explicit written authorization.",
    ),
    "web-authenticated-thorough": (
        None,
        "Maximum coverage reached. Consider targeted sub-presets: "
        "nuclei/nuclei-intense for CVE coverage, web/lightfuzz-superheavy for deeper fuzzing, "
        "web/ffuf-heavy for exhaustive directory discovery.",
    ),
}

# Check order: most specific first so infer() stops at highest matching level
_CHECK_ORDER = ["web-authenticated-thorough", "web-authenticated", "web-basic"]


class PresetOrchestrator:
    """
    Infers which preset level ran from a module set and recommends the next step.
    Signatures are derived from preset YAML files — no hardcoded module lists.
    """

    def __init__(self, presets_dirs: list[Path] | None = None):
        self._signatures = self._build_signatures(presets_dirs or _PRESET_DIRS)

    def _build_signatures(self, presets_dirs: list[Path]) -> dict[str, set[str]]:
        sigs = {}
        for name in _CHECK_ORDER:
            modules = self._read_modules(presets_dirs, name)
            if modules:
                sigs[name] = modules
        return sigs

    def _read_modules(self, presets_dirs: list[Path], name: str) -> set[str]:
        for presets_dir in presets_dirs:
            for ext in (".yml", ".yaml"):
                path = presets_dir / f"{name}{ext}"
                if path.is_file():
                    with suppress(Exception):
                        data = yaml.safe_load(path.read_text(encoding="utf-8"))
                        return set(data.get("modules", []))
        return set()

    def recommend(self, ran_modules: set[str]) -> PresetRecommendation:
        current = self._infer(ran_modules)
        next_preset, desc = _ESCALATION.get(current, (None, "No escalation path available."))
        return PresetRecommendation(current=current, next=next_preset, escalation_desc=desc)

    def _infer(self, ran_modules: set[str]) -> str:
        for preset, signature in self._signatures.items():
            if signature & ran_modules:
                return preset
        return "initial"
