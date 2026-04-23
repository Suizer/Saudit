import json
import re
from urllib.parse import urlparse

from saudit.modules.base import BaseModule

SWAGGER_PATHS = [
    "/api-docs",
    "/api-docs.json",
    "/api/docs",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/docs/swagger.json",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
]

# Swagger UI HTML pattern — signals a hosted Swagger UI page
_SWAGGER_UI_RE = re.compile(r'id=["\']swagger-ui["\']', re.IGNORECASE)
# Extracts the swaggerDoc object embedded in swagger-ui-init.js
_SWAGGER_DOC_RE = re.compile(r'"swaggerDoc"\s*:\s*(\{.*?\})\s*,\s*"customOptions"', re.DOTALL)

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}


def _base_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _extract_params(operation: dict, spec_version: int) -> list[str]:
    """Extract parameter names from an OpenAPI operation."""
    params = []
    for p in operation.get("parameters", []):
        name = p.get("name", "")
        if name and p.get("in") in ("query", "path"):
            params.append(name)
    if spec_version == 3:
        rb = operation.get("requestBody", {})
        schema = (
            rb.get("content", {})
            .get("application/json", {})
            .get("schema", {})
        )
        for name in schema.get("properties", {}):
            params.append(name)
    else:
        for p in operation.get("parameters", []):
            if p.get("in") in ("body", "formData"):
                schema = p.get("schema", {})
                for name in schema.get("properties", {}):
                    params.append(name)
    return list(dict.fromkeys(params))


class swagger_probe(BaseModule):
    """
    Discovers OpenAPI / Swagger specs and emits one FINDING per documented
    endpoint so that api_probe can test each one with real parameter names.
    Handles both standalone JSON specs and Swagger UI pages with embedded specs.
    """

    watched_events = ["URL"]
    produced_events = ["FINDING", "TECHNOLOGY"]
    flags = ["active", "safe", "web-thorough"]
    meta = {
        "description": "Discover OpenAPI/Swagger specs and extract documented API endpoints",
        "author": "@suizer",
        "created_date": "2026-04-23",
    }
    options = {"auth_token": ""}
    options_desc = {"auth_token": "Bearer token for authenticated spec endpoints"}

    in_scope_only = True

    async def setup(self):
        self._seen_hosts = set()
        token = self.config.get("auth_token", "").strip()
        self._auth_headers = {"Authorization": token} if token else {}
        return True

    async def filter_event(self, event):
        url = event.data
        if not isinstance(url, str):
            return False, "not a string URL"
        p = urlparse(url)
        if "." in p.path.split("/")[-1]:
            return False, "not a root URL"
        return True, ""

    async def handle_event(self, event):
        base = _base_url(event.data)
        if base in self._seen_hosts:
            return
        self._seen_hosts.add(base)

        swagger_ui_paths = []  # paths that returned Swagger UI HTML

        for path in SWAGGER_PATHS:
            resp = await self.helpers.request(
                f"{base}{path}",
                headers=self._auth_headers,
                allow_redirects=True,
            )
            if resp is None or resp.status_code != 200:
                continue

            spec = self._parse_spec(resp)
            if spec:
                self.info(f"Found OpenAPI spec at {base}{path}")
                await self._emit_spec(spec, base, path, event)
                return

            # Track Swagger UI HTML pages for init.js fallback
            if _SWAGGER_UI_RE.search(resp.text):
                swagger_ui_paths.append(path)

        # Fallback: try to extract embedded spec from swagger-ui-init.js
        for ui_path in swagger_ui_paths:
            init_url = f"{base}{ui_path}/swagger-ui-init.js"
            resp = await self.helpers.request(
                init_url,
                headers=self._auth_headers,
                allow_redirects=True,
            )
            if resp is None or resp.status_code != 200:
                continue
            spec = self._parse_spec_from_js(resp.text)
            if spec:
                self.info(f"Found embedded OpenAPI spec in {init_url}")
                await self._emit_spec(spec, base, f"{ui_path}/swagger-ui-init.js", event)
                return

    def _parse_spec(self, resp) -> dict | None:
        ct = resp.headers.get("content-type", "")
        try:
            if "json" in ct or resp.text.strip().startswith("{"):
                data = resp.json()
            else:
                try:
                    import yaml
                    data = yaml.safe_load(resp.text)
                except ImportError:
                    return None
            if isinstance(data, dict) and "paths" in data:
                return data
        except Exception:
            pass
        return None

    def _parse_spec_from_js(self, js_text: str) -> dict | None:
        """Extract swaggerDoc embedded in swagger-ui-init.js."""
        m = _SWAGGER_DOC_RE.search(js_text)
        if not m:
            return None
        try:
            data = json.loads(m.group(1))
            if isinstance(data, dict) and "paths" in data:
                return data
        except Exception:
            pass
        return None

    async def _emit_spec(self, spec: dict, base: str, spec_path: str, parent_event):
        spec_version = 3 if "openapi" in spec else 2
        info = spec.get("info", {})
        api_title = info.get("title", "API")
        api_version = info.get("version", "")

        await self.emit_event(
            {
                "host":       str(parent_event.host),
                "technology": f"{api_title} {api_version}".strip(),
                "url":        f"{base}{spec_path}",
            },
            "TECHNOLOGY",
            parent=parent_event,
            context=f"{{module}} found OpenAPI spec: {api_title}",
        )

        paths = spec.get("paths", {})
        emitted = 0
        for endpoint_path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, operation in methods.items():
                if method.lower() not in HTTP_METHODS:
                    continue
                if not isinstance(operation, dict):
                    continue

                params = _extract_params(operation, spec_version)
                param_str = ",".join(params) if params else ""
                summary = operation.get("summary", "") or operation.get("operationId", "")

                desc = (
                    f"[ENDPOINT] Swagger {method.upper()} {endpoint_path}"
                    + (f" | {summary}" if summary else "")
                    + f" | Match: {endpoint_path}"
                    + (f" | Params: {param_str}" if param_str else "")
                )

                await self.emit_event(
                    {
                        "host":            str(parent_event.host),
                        "url":             base,
                        "description":     desc,
                        "_swagger_method": method.upper(),
                        "_swagger_params": params,
                    },
                    "FINDING",
                    parent=parent_event,
                    tags=["swagger-probe", "endpoint", f"method-{method.lower()}"],
                    context=f"{{module}} found documented endpoint {method.upper()} {endpoint_path}",
                )
                emitted += 1

        self.info(f"Emitted {emitted} endpoints from {api_title} spec")
