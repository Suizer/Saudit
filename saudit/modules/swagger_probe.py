import json
from urllib.parse import urlparse

from saudit.modules.base import BaseModule

# Paths comunes donde suele vivir la spec OpenAPI/Swagger
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

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}


def _base_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _extract_params(operation: dict, spec_version: int) -> list[str]:
    """Extract parameter names from an OpenAPI operation."""
    params = []
    # query / path / header params (OpenAPI 2 & 3)
    for p in operation.get("parameters", []):
        name = p.get("name", "")
        if name and p.get("in") in ("query", "path"):
            params.append(name)
    # OpenAPI 3 requestBody JSON schema
    if spec_version == 3:
        rb = operation.get("requestBody", {})
        schema = (
            rb.get("content", {})
            .get("application/json", {})
            .get("schema", {})
        )
        for name in schema.get("properties", {}):
            params.append(name)
    # OpenAPI 2 body / formData params
    else:
        for p in operation.get("parameters", []):
            if p.get("in") in ("body", "formData"):
                schema = p.get("schema", {})
                for name in schema.get("properties", {}):
                    params.append(name)
    return list(dict.fromkeys(params))  # dedupe preserving order


class swagger_probe(BaseModule):
    """
    Discovers OpenAPI / Swagger specs and emits one FINDING per documented
    endpoint so that api_probe can test each one with real parameter names.
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
        # only process root / host-level URLs, not .js files etc.
        p = urlparse(url)
        if "." in p.path.split("/")[-1]:
            return False, "not a root URL"
        return True, ""

    async def handle_event(self, event):
        base = _base_url(event.data)
        if base in self._seen_hosts:
            return
        self._seen_hosts.add(base)

        for path in SWAGGER_PATHS:
            resp = await self.helpers.request(
                f"{base}{path}",
                headers=self._auth_headers,
                allow_redirects=True,
            )
            if resp is None or resp.status_code != 200:
                continue

            spec = self._parse_spec(resp)
            if not spec:
                continue

            self.info(f"Found OpenAPI spec at {base}{path}")
            await self._emit_spec(spec, base, path, event)
            return  # stop after first valid spec

    def _parse_spec(self, resp) -> dict | None:
        ct = resp.headers.get("content-type", "")
        try:
            if "json" in ct or resp.text.strip().startswith("{"):
                data = resp.json()
            else:
                # minimal YAML fallback — only if yaml available
                try:
                    import yaml
                    data = yaml.safe_load(resp.text)
                except ImportError:
                    return None
            # must have paths key to be a real spec
            if isinstance(data, dict) and "paths" in data:
                return data
        except Exception:
            pass
        return None

    async def _emit_spec(self, spec: dict, base: str, spec_path: str, parent_event):
        # detect version
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
