# adapted from https://github.com/bugcrowd/HUNT

from saudit.modules.base import BaseModule

# Static asset extensions — parameters on these URLs are CDN delivery params, not app inputs
_STATIC_EXTENSIONS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".bmp", ".tiff",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".mov", ".webm",
    ".css", ".map",
})

# CDN/platform path fragments where parameters are asset-delivery controls, not app logic
_CDN_PATH_FRAGMENTS = frozenset({
    "/hs-fs/hubfs/",        # HubSpot file system CDN
    "/hs/hsstatic/",        # HubSpot static assets
    "/hubfs/",              # HubSpot CDN
    "/wp-content/uploads/", # WordPress media uploads
    "/sites/default/files/",# Drupal file storage
})

hunt_param_dict = {
    "Command Injection": [
        "daemon",
        "host",
        "upload",
        "dir",
        "execute",
        "download",
        "log",
        "ip",
        "cli",
        "cmd",
        "exec",
        "command",
        "func",
        "code",
        "update",
        "shell",
        "eval",
    ],
    "Debug": [
        "access",
        "admin",
        "dbg",
        "debug",
        "edit",
        "grant",
        "test",
        "alter",
        "clone",
        "create",
        "delete",
        "disable",
        "enable",
        "exec",
        "execute",
        "load",
        "make",
        "modify",
        "rename",
        "reset",
        "shell",
        "toggle",
        "adm",
        "root",
        "cfg",
        "config",
    ],
    "Directory Traversal": [
        "entry",
        "download",
        "attachment",
        "basepath",
        "path",
        "file",
        "source",
        "dest",
    ],
    "Local File Include": [
        "file",
        "document",
        "folder",
        "root",
        "path",
        "pg",
        "style",
        "pdf",
        "template",
        "php_path",
        "doc",
        "lang",
        "include",
        "img",
        "view",
        "layout",
        "export",
        "log",
        "configFile",
        "stylesheet",
        "configFileUrl",
    ],
    "Insecure Direct Object Reference": [
        "id",
        "user",
        "account",
        "number",
        "order",
        "no",
        "doc",
        "key",
        "email",
        "group",
        "profile",
        "edit",
        "report",
        "docId",
        "accountId",
        "customerId",
        "reportId",
        "jobId",
        "sessionId",
        "api_key",
        "instance",
        "identifier",
        "access",
    ],
    "SQL Injection": [
        "id",
        "select",
        "report",
        "role",
        "update",
        "query",
        "user",
        "name",
        "sort",
        "where",
        "search",
        "params",
        "category",
        "process",
        "row",
        "view",
        "table",
        "from",
        "sel",
        "results",
        "sleep",
        "fetch",
        "order",
        "keyword",
        "column",
        "field",
        "delete",
        "string",
        "number",
        "filter",
        "limit",
        "offset",
        "item",
        "input",
        "date",
        "value",
        "orderBy",
        "groupBy",
        "pageNum",
        "pageSize",
        "tag",
        "author",
        "postId",
        "parentId",
        "d",
    ],
    "Server-side Request Forgery": [
        "dest",
        "redirect",
        "uri",
        "path",
        "continue",
        "url",
        "window",
        "next",
        "data",
        "reference",
        "site",
        "html",
        "val",
        "validate",
        "domain",
        "callback",
        "return",
        "page",
        "feed",
        "host",
        "port",
        "to",
        "out",
        "view",
        "dir",
        "show",
        "navigation",
        "open",
        "proxy",
        "target",
        "server",
        "domain",
        "connect",
        "fetch",
        "apiEndpoint",
    ],
    "Server-Side Template Injection": [
        "template",
        "preview",
        "id",
        "view",
        "activity",
        "name",
        "content",
        "redirect",
        "expression",
        "statement",
        "tpl",
        "render",
        "format",
        "engine",
    ],
    "XML external entity injection": [
        "xml",
        "dtd",
        "xsd",
        "xmlDoc",
        "xmlData",
        "entityType",
        "entity",
        "xmlUrl",
        "schema",
        "xmlFile",
        "xmlPath",
        "xmlSource",
        "xmlEndpoint",
        "xslt",
        "xmlConfig",
        "xmlCallback",
        "attributeName",
        "wsdl",
        "xmlDocUrl",
    ],
    "Insecure Cryptography": [
        "encrypted",
        "cipher",
        "iv",
        "checksum",
        "hash",
        "salt",
        "hmac",
        "secret",
        "key",
        "signatureAlgorithm",
        "keyId",
        "sharedSecret",
        "privateKeyId",
        "privateKey",
        "publicKey",
        "publicKeyId",
        "encryptedData",
        "encryptedMessage",
        "encryptedPayload",
        "encryptedFile",
        "cipherText",
        "cipherAlgorithm",
        "keySize",
        "keyPair",
        "keyDerivation",
        "encryptionMethod",
        "decryptionKey",
    ],
    "Unsafe Deserialization": [
        "serialized",
        "object",
        "dataObject",
        "serialization",
        "payload",
        "encoded",
        "marshalled",
        "pickled",
        "jsonData",
        "state",
        "sessionData",
        "cache",
        "tokenData",
        "serializedSession",
        "objectState",
        "jsonDataPayload",
    ],
}


class hunt(BaseModule):
    watched_events = ["WEB_PARAMETER"]
    produced_events = ["FINDING"]
    flags = ["active", "safe", "web-thorough"]
    meta = {
        "description": "Watch for commonly-exploitable HTTP parameters",
        "author": "@liquidsec",
        "created_date": "2022-07-20",
    }

    async def filter_event(self, event):
        url = event.data.get("url", "")
        if url:
            # Strip query string to check path only
            path = url.split("?")[0].lower()
            if any(path.endswith(ext) for ext in _STATIC_EXTENSIONS):
                return False, "parameter on static asset URL — not an application input"
            if any(frag in path for frag in _CDN_PATH_FRAGMENTS):
                return False, "parameter on CDN/platform asset path — not an application input"
        return True, "accepted"

    async def handle_event(self, event):
        p = event.data["name"]
        matching_categories = []

        # Collect all matching categories
        for k in hunt_param_dict.keys():
            if p.lower() in hunt_param_dict[k]:
                matching_categories.append(k)

        if matching_categories:
            # Create a comma-separated string of categories
            category_str = ", ".join(matching_categories)
            description = f"Found potentially interesting parameter. Name: [{p}] Parameter Type: [{event.data['type']}] Categories: [{category_str}]"

            if (
                "original_value" in event.data.keys()
                and event.data["original_value"] != ""
                and event.data["original_value"] is not None
            ):
                description += (
                    f" Original Value: [{self.helpers.truncate_string(str(event.data['original_value']), 200)}]"
                )

            data = {"host": str(event.host), "description": description}
            url = event.data.get("url", "")
            if url:
                data["url"] = url
            await self.emit_event(data, "FINDING", event)
