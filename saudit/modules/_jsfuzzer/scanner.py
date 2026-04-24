from __future__ import annotations

import bisect
import logging
import math
import re
from collections import Counter
from pathlib import Path

import yaml

log = logging.getLogger("saudit.modules.jsfuzzer")

# ─── Entropy helpers ──────────────────────────────────────────────────────────

def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


# ─── Noise Filters ────────────────────────────────────────────────────────────

_URL_NOISE_PATTERNS = re.compile(
    r"(?:"
    r"w3\.org/|polymer\.github\.io/|vuejs\.org/|reactjs\.org/|react\.dev/"
    r"|nextjs\.org/|momentjs\.com/|ckeditor\.com/"
    r"|github\.com/[a-zA-Z-]+/[a-zA-Z-]+(?:/issues|/blob|#)"
    r"|bit\.ly/|schema\.org|iframe-resizer\.com/|googleapis\.com/css"
    r"|cdnjs\.cloudflare\.com/|fb\.me/|err\.47ng\.com/|salesforce\.com/charts/"
    r"|json-schema\.org/|lwc\.dev/|sfdc\.co/|unpkg\.com/|cdn\.jsdelivr\.net/"
    r"|gstatic\.com/|youtube\.com/(?:iframe_api|embed/|subscribe)"
    r"|google-analytics\.com/|googletagmanager\.com/"
    r"|accounts\.google\.com/o/oauth2|plus\.google\.com|plus\.googleapis\.com"
    r"|play\.google\.com/|classroom\.google\.com/|families\.google\.com/"
    r"|workspace\.google\.com/|drive\.google\.com/|pay\.google\.com/"
    r"|talkgadget\.google\.com/|clients3\.google\.com/|apis\.google\.com/"
    r"|www\.google\.com/shopping/|dataconnector\.corp\.google\.com/"
    r"|apache\.org/licenses|lightningdesignsystem\.com/|ct\.de/|cke4\.ckeditor\.com/"
    r"|yarnpkg\.com/|facebook\.com/sharer|twitter\.com/intent|x\.com/intent"
    r"|linkedin\.com/shareArticle|pinterest\.com/pin/|reddit\.com/submit"
    r"|t\.me/share|tumblr\.com/widgets|vk\.com/share|xing\.com/spi"
    r"|buffer\.com/add|getpocket\.com/save|stumbleupon\.com/submit"
    r"|flipboard\.com/bookmarklet|diasporafoundation\.org/|addthis\.com/"
    r"|weibo\.com/share|qzone\.qq\.com/|lidlplus\.com/"
    r")",
    re.IGNORECASE,
)

_SUBDOMAIN_NOISE_PATTERNS = re.compile(
    r"(?:"
    r"[a-z]{2}-[A-Z]{2}_(?:dev|test|prod)"
    r"|\.(?:js|css|json|mjs|map)(?:[\"'\s,)\]])"
    r"|Kameleoon\.|\.API\.|\.runWhenElementPresent"
    r"|new URL\(|api\.salesforce\.com|api\.reciteme\.com|dev\.virtualearth\.net"
    r")",
    re.IGNORECASE,
)

_ENTROPY_NOISE_PATTERNS = re.compile(
    r"(?:"
    r"(?:[a-z]+\.){3,}|(?:[a-z]+-){2,}[a-z]+"
    r"|deliveryCosts\.|deliveryOptions\.|pages\.|form\.|footer\."
    r"|TooltipTitle|TooltipText|SpecificProduct_|ArticleDetails_"
    r"|background-color|border-radius|position:\s*absolute|content:\s*[\"']"
    r"|viewBox=|xmlns=|\\u[0-9a-fA-F]{4}|%[0-9a-fA-F]{2}"
    r")",
)

_CODE_TOKENS = re.compile(
    r"\b(?:"
    r"function|return|var|let|const|this|if|else|for|while|switch|case|break"
    r"|throw|catch|try|new|typeof|instanceof|void|delete|null|undefined|true|false"
    r"|document|window|console|addEventListener|removeEventListener|createElement"
    r"|getAttribute|setAttribute|appendChild|removeChild|querySelector"
    r"|indexOf|substring|toString|prototype|hasOwnProperty"
    r"|\.push|\.pop|\.shift|\.splice|\.slice|\.map|\.filter|\.reduce|\.forEach"
    r"|\.length|\.split|\.join|\.replace|\.match|\.test|\.exec"
    r"|\.get\(|\.set\(|\.add\(|\.has\("
    r"|keyCode|keydown|keyup|keypress|click|focus|blur|mouseover|mousedown"
    r"|preventDefault|stopPropagation|getCallback|fireEvent"
    r"|getParam|setParam|getComponent|getElement|getReference"
    r")\b",
    re.IGNORECASE,
)

_KNOWN_CHARSETS = frozenset({
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "0123456789abcdef",
    "0123456789abcdefABCDEF",
    "0123456789abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=",
})

_MINIFIED_CODE_PATTERNS = re.compile(
    r"(?:"
    r"===?\s*[\"']|!==?\s*[\"']|\(\s*function|\.prototype\."
    r"|\.call\(|\.apply\(|\.bind\(|=>\s*\{|\?\s*\w+\s*:"
    r"|&&\s*\w+|[\|]{2}\s*\w+|\\x3d|\\x3e|\\x3c"
    r"|aura://|markup://|\$A\.util\.|\$A\.get\(|getEvt\("
    r"|metricsService|force_record|RecordTemplate|MetadataStore"
    r")",
)

_FRAMEWORK_SIGNATURES = {
    "React": [r"\bReact\b", r"\bcreateElement\b", r"\buseState\b", r"\buseEffect\b", r"\bReactDOM\b", r"__REACT_DEVTOOLS"],
    "Vue.js": [r"\bVue\b", r"\bcreateApp\b", r"\bv-bind\b", r"\bv-model\b", r"__VUE__", r"__vue__"],
    "Angular": [r"\bng-\w+", r"\bangular\b", r"@Component", r"@Injectable", r"__ng_", r"platformBrowserDynamic"],
    "jQuery": [r"\bjQuery\b", r"\$\(\s*[\"'#\.]", r"\$\.ajax\b", r"\$\.get\b"],
    "Svelte": [r"__svelte", r"\bSvelteComponent\b", r"svelte/internal"],
    "Next.js": [r"__NEXT_DATA__", r"next/router", r"_next/static"],
    "Nuxt": [r"__NUXT__", r"nuxt:reload", r"\bnuxt\b.*\bplugin\b"],
    "Salesforce Aura/LWC": [r"\$A\.", r"aura://", r"markup://", r"lightning-", r"__AURA__", r"Aura\.Component"],
}


class JScanner:
    """Static JS analysis engine — secret, endpoint and framework detection."""

    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.rules = self._load_rules()
        self._compiled_secrets = self._compile_secrets()
        self._compiled_endpoints = self._compile_endpoints()
        self._compiled_frameworks = self._compile_frameworks()
        self._entropy_cfg = self.rules.get("secrets", {}).get("entropy", {})
        self._entropy_enabled = self._entropy_cfg.get("enabled", False)
        self._entropy_skip = [re.compile(p) for p in self._entropy_cfg.get("skip_patterns", [])]
        self._quoted_string_re = re.compile(r"""["'`]([^"'`]{16,256})["'`]""")

    def _load_rules(self) -> dict:
        rules = {}
        for name in ("secrets.yaml", "endpoints.yaml"):
            path = self.config_dir / name
            if path.exists():
                with open(path, encoding="utf-8") as f:
                    rules[name.split(".")[0]] = yaml.safe_load(f) or {}
            else:
                log.warning(f"Config not found: {path}")
                rules[name.split(".")[0]] = {}
        return rules

    def _compile_secrets(self) -> list[dict]:
        compiled = []
        for item in self.rules.get("secrets", {}).get("patterns", []):
            p = item.get("pattern", "")
            if not p:
                continue
            try:
                compiled.append({**item, "_compiled": re.compile(p)})
            except re.error as e:
                log.debug(f"Invalid regex in {item.get('name')}: {e}")
        return compiled

    def _compile_endpoints(self) -> list[dict]:
        compiled = []
        ep_rules = self.rules.get("endpoints", {})
        for section_key in ("endpoints", "cloud_buckets", "urls"):
            for item in ep_rules.get(section_key, []):
                patterns = []
                for p in item.get("patterns", []):
                    try:
                        patterns.append(re.compile(p))
                    except re.error as e:
                        log.debug(f"Invalid regex in {item.get('name')}: {e}")
                if patterns:
                    compiled.append({**item, "_compiled": patterns, "_section": section_key})
        return compiled

    def _compile_frameworks(self) -> dict[str, list[re.Pattern]]:
        return {name: [re.compile(p) for p in patterns] for name, patterns in _FRAMEWORK_SIGNATURES.items()}

    def scan_file(self, file_path: Path) -> list[dict]:
        file_path = Path(file_path)
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            log.debug(f"Error reading {file_path}: {e}")
            return []
        if not content.strip():
            return []
        line_starts = self._build_line_index(content)
        findings: list[dict] = []
        findings.extend(self._scan_secrets(content, line_starts))
        if self._entropy_enabled:
            findings.extend(self._scan_entropy(content, line_starts))
        findings.extend(self._scan_endpoints(content, line_starts))
        findings.extend(self._detect_frameworks(content))
        return self._deduplicate(findings)

    def _scan_secrets(self, content: str, line_starts: list[int]) -> list[dict]:
        results = []
        for secret in self._compiled_secrets:
            for match in secret["_compiled"].finditer(content):
                matched = match.group(1) if match.lastindex else match.group(0)
                results.append({
                    "type": "SECRET",
                    "name": secret["name"],
                    "severity": secret["severity"],
                    "line": self._get_line_number(line_starts, match.start()),
                    "match": self._redact(matched),
                    "context": self._get_context(content, match.start(), match.end()),
                })
        return results

    def _scan_entropy(self, content: str, line_starts: list[int]) -> list[dict]:
        results = []
        threshold = self._entropy_cfg.get("shannon_threshold", 4.5)
        min_len = self._entropy_cfg.get("min_length", 16)
        max_len = self._entropy_cfg.get("max_length", 256)
        seen: set[str] = set()

        for match in self._quoted_string_re.finditer(content):
            value = match.group(1)
            if len(value) < min_len or len(value) > max_len or value in seen:
                continue
            seen.add(value)
            if any(skip.match(value) for skip in self._entropy_skip):
                continue
            if value.startswith(("http://", "https://", "/", "./", "../", "data:")):
                continue
            if " " in value or _ENTROPY_NOISE_PATTERNS.search(value):
                continue
            if value in _KNOWN_CHARSETS:
                continue
            if value.count(".") >= 3 and all(c.isalnum() or c in "._-" for c in value):
                continue
            if "{" in value and "}" in value and (":" in value or ";" in value):
                continue
            if "${" in value or _MINIFIED_CODE_PATTERNS.search(value):
                continue
            if len(_CODE_TOKENS.findall(value)) >= 3:
                continue
            ctx = self._get_raw_context(content, match.start(), 120, 120)
            if _MINIFIED_CODE_PATTERNS.search(ctx) and any(c in value for c in "(){}[];=<>!&|"):
                continue
            entropy = _shannon_entropy(value)
            if entropy < threshold:
                continue
            ctx_around = self._get_raw_context(content, match.start(), 60, 10).lower()
            has_secret_ctx = any(kw in ctx_around for kw in (
                "key", "secret", "token", "password", "passwd", "apikey",
                "api_key", "auth", "credential", "private", "bearer",
            ))
            if not has_secret_ctx and entropy < 5.5:
                continue
            if not has_secret_ctx and any(fw in ctx_around for fw in (
                "$a.", "aura://", "markup://", "getparam", "setparam", "getcallback",
                "getelement", "getcomponent", "fireevent", "addeventlistener",
                "removeeventlistener", "keydown", "keyup", "keycode", "keypress",
                "metricsservice", "force_record", "recordtemplate", "metadatastore",
                "descriptor", "controller", "action$", "regexp(", "\\x3d", "\\x3e",
                "createelement", "appendchild", "queryselector", "classlist",
                "setattribute", "getattribute",
            )):
                continue
            results.append({
                "type": "ENTROPY",
                "name": "High-entropy string",
                "severity": "high" if has_secret_ctx else "medium",
                "line": self._get_line_number(line_starts, match.start()),
                "match": self._redact(value),
                "context": self._get_context(content, match.start(), match.end()),
                "entropy": round(entropy, 2),
            })
        return results

    def _scan_endpoints(self, content: str, line_starts: list[int]) -> list[dict]:
        results = []
        seen: set[str] = set()
        type_map = {"endpoints": "ENDPOINT", "cloud_buckets": "CLOUD", "urls": "URL"}

        for rule in self._compiled_endpoints:
            section = rule.get("_section", "endpoint")
            type_label = type_map.get(section, "ENDPOINT")
            for regex in rule["_compiled"]:
                for match in regex.finditer(content):
                    matched = match.group(0)
                    if rule["name"] == "Absolute URL" and _URL_NOISE_PATTERNS.search(matched):
                        continue
                    if rule["name"] == "Subdomain reference":
                        ctx = self._get_raw_context(content, match.start(), 30, 30)
                        if _SUBDOMAIN_NOISE_PATTERNS.search(ctx) or _SUBDOMAIN_NOISE_PATTERNS.search(matched):
                            continue
                    key = f"{rule['name']}:{matched}"
                    if key in seen:
                        continue
                    seen.add(key)
                    results.append({
                        "type": type_label,
                        "name": rule["name"],
                        "severity": rule.get("severity", "info"),
                        "category": rule.get("category", ""),
                        "line": self._get_line_number(line_starts, match.start()),
                        "match": matched[:120],
                        "context": self._get_context(content, match.start(), match.end()),
                    })
        return results

    def _detect_frameworks(self, content: str) -> list[dict]:
        results = []
        for name, patterns in self._compiled_frameworks.items():
            hits = sum(1 for p in patterns if p.search(content))
            if hits >= max(3, len(patterns) // 2):
                results.append({
                    "type": "FRAMEWORK",
                    "name": name,
                    "severity": "info",
                    "line": "N/A",
                    "context": f"{hits}/{len(patterns)} signatures matched",
                })
        return results

    @staticmethod
    def _build_line_index(content: str) -> list[int]:
        starts = [0]
        for i, ch in enumerate(content):
            if ch == "\n":
                starts.append(i + 1)
        return starts

    @staticmethod
    def _get_line_number(line_starts: list[int], index: int) -> int:
        return bisect.bisect_right(line_starts, index)

    @staticmethod
    def _get_raw_context(content: str, index: int, before: int, after: int) -> str:
        return content[max(0, index - before):min(len(content), index + after)]

    @staticmethod
    def _get_context(content: str, start: int, end: int, before: int = 50, after: int = 80) -> str:
        snippet = content[max(0, start - before):min(len(content), end + after)]
        snippet = " ".join(snippet.split()).replace("|", "&#124;")
        return f"...{snippet[:200]}..." if len(snippet) > 200 else f"...{snippet}..."

    @staticmethod
    def _redact(value: str) -> str:
        if len(value) <= 12:
            return value[:3] + "***" + value[-2:]
        return value[:6] + "..." + value[-4:]

    @staticmethod
    def _deduplicate(findings: list[dict]) -> list[dict]:
        seen: set[str] = set()
        unique: list[dict] = []
        endpoint_lines: set = {f.get("line", "") for f in findings if f["type"] == "ENDPOINT" and f.get("line", "") not in ("N/A", "")}
        for f in findings:
            key = f"{f['type']}:{f['name']}:{f.get('line', '')}"
            if key in seen:
                continue
            if f["type"] == "URL" and f["name"] == "Absolute URL" and f.get("line", "") in endpoint_lines:
                continue
            seen.add(key)
            unique.append(f)
        return unique
