from saudit.modules.base import BaseModule


# Headers checked for absence — emit a FINDING when missing
MISSING_HEADER_CHECKS = {
    "strict-transport-security": {
        "severity": "MEDIUM",
        "description": "Missing Strict-Transport-Security (HSTS)",
        "risk": (
            "Without HSTS, browsers accept HTTP connections to the site. "
            "An attacker on the same network (coffee shop, corporate proxy) can intercept traffic via "
            "SSL stripping — downgrading HTTPS to HTTP transparently and stealing session cookies or credentials."
        ),
        "recommendation": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "content-security-policy": {
        "severity": "MEDIUM",
        "description": "Missing Content-Security-Policy (CSP)",
        "risk": (
            "Without CSP, any XSS vulnerability found in the application has full impact: "
            "attackers can load external scripts, exfiltrate data, or hijack sessions. "
            "CSP is the primary defence-in-depth control that limits XSS blast radius."
        ),
        "recommendation": "Content-Security-Policy: default-src 'self'",
    },
    "x-frame-options": {
        "severity": "MEDIUM",
        "description": "Missing X-Frame-Options",
        "risk": (
            "Without X-Frame-Options (or CSP frame-ancestors), the application can be embedded "
            "in an iframe on an attacker-controlled page. This enables clickjacking attacks where "
            "users are tricked into clicking invisible buttons (e.g. confirm transfers, change email, grant OAuth permissions)."
        ),
        "recommendation": "X-Frame-Options: SAMEORIGIN",
    },
    "x-content-type-options": {
        "severity": "LOW",
        "description": "Missing X-Content-Type-Options",
        "risk": (
            "Without nosniff, older browsers may MIME-sniff responses and execute content with a wrong "
            "Content-Type as HTML or JavaScript. If the application serves user-uploaded files "
            "(images, CSVs), an attacker can upload an HTML/JS payload disguised as another file type."
        ),
        "recommendation": "X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "severity": "LOW",
        "description": "Missing Referrer-Policy",
        "risk": (
            "Without a Referrer-Policy, the browser sends the full URL (including path and query string) "
            "in the Referer header to third-party resources. Sensitive tokens or IDs in URLs "
            "(e.g. /reset-password?token=abc123) may be leaked to analytics providers or CDNs."
        ),
        "recommendation": "Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "severity": "INFO",
        "description": "Missing Permissions-Policy",
        "risk": (
            "Without Permissions-Policy, the application does not restrict which browser APIs "
            "are available. An XSS payload could silently activate the camera, microphone, or "
            "geolocation. Low risk on its own but increases XSS impact."
        ),
        "recommendation": "Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
}

# Headers checked for insecure values even when present
INSECURE_HEADER_CHECKS = {
    "x-xss-protection": {
        "bad_values": {"1", "1; mode=block"},
        "severity": "LOW",
        "description": "Insecure X-XSS-Protection header value",
        "risk": (
            "X-XSS-Protection: 1; mode=block is deprecated and exploitable in IE/Edge. "
            "A specially crafted payload can use the XSS filter itself as an oracle to extract "
            "page content cross-origin. Modern browsers ignore this header; it should be set to 0."
        ),
        "recommendation": "X-XSS-Protection: 0",
    },
}


class security_headers(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING"]
    flags = ["active", "safe"]
    meta = {
        "description": "Check HTTP responses for missing or misconfigured security headers",
        "created_date": "2024-01-01",
        "author": "@suizer",
    }

    in_scope_only = True
    per_hostport_only = True

    async def setup(self):
        return True

    async def handle_event(self, event):
        headers = event.data.get("header-dict", {})
        url = event.data.get("url", str(event.host))

        for header, check in MISSING_HEADER_CHECKS.items():
            if header not in headers:
                await self.emit_event(
                    {
                        "host": str(event.host),
                        "url": url,
                        "description": check["description"],
                        "severity": check["severity"],
                        "risk": check["risk"],
                        "recommendation": check["recommendation"],
                    },
                    "FINDING",
                    parent=event,
                    context=f"{{module}} detected missing header '{header}' on {{event.host}}",
                    tags=["missing-header", check["severity"].lower()],
                )

        for header, check in INSECURE_HEADER_CHECKS.items():
            value = headers.get(header, [""])[0].strip().lower()
            if value in check["bad_values"]:
                await self.emit_event(
                    {
                        "host": str(event.host),
                        "url": url,
                        "description": check["description"],
                        "severity": check["severity"],
                        "risk": check["risk"],
                        "recommendation": check["recommendation"],
                    },
                    "FINDING",
                    parent=event,
                    context=f"{{module}} detected insecure header '{header}: {value}' on {{event.host}}",
                    tags=["insecure-header", check["severity"].lower()],
                )
