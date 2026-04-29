from .base import ModuleTestBase


class TestSecurityHeadersMissing(ModuleTestBase):
    """Response with no security headers → FINDING for each missing header."""

    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "security_headers"]

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/"},
            respond_args={"response_data": "<html>ok</html>"},
        )

    def check(self, module_test, events):
        descriptions = [e.data["description"] for e in events if e.type == "FINDING"]
        assert any("Strict-Transport-Security" in d for d in descriptions), (
            "Expected FINDING for missing HSTS"
        )
        assert any("Content-Security-Policy" in d for d in descriptions), (
            "Expected FINDING for missing CSP"
        )
        assert any("X-Frame-Options" in d for d in descriptions), (
            "Expected FINDING for missing X-Frame-Options"
        )
        assert any("X-Content-Type-Options" in d for d in descriptions), (
            "Expected FINDING for missing X-Content-Type-Options"
        )


class TestSecurityHeadersPresent(ModuleTestBase):
    """Response with all required security headers → no 'Missing' FINDING."""

    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "security_headers"]

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/"},
            respond_args={
                "response_data": "<html>ok</html>",
                "headers": {
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                    "Content-Security-Policy": "default-src 'self'",
                    "X-Frame-Options": "SAMEORIGIN",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "strict-origin-when-cross-origin",
                    "Permissions-Policy": "geolocation=()",
                },
            },
        )

    def check(self, module_test, events):
        assert not any(
            e.type == "FINDING" and "Missing" in e.data.get("description", "")
            for e in events
        ), "No 'Missing header' findings expected when all headers are present"


class TestSecurityHeadersInsecureXSSProtection(ModuleTestBase):
    """Response with X-XSS-Protection: 1; mode=block → FINDING for insecure value."""

    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "security_headers"]

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/"},
            respond_args={
                "response_data": "<html>ok</html>",
                "headers": {"X-XSS-Protection": "1; mode=block"},
            },
        )

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING" and "Insecure X-XSS-Protection" in e.data["description"]
            for e in events
        ), "Expected FINDING for deprecated X-XSS-Protection: 1; mode=block"
