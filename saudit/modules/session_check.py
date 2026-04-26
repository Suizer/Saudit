from saudit.modules.base import BaseModule


LOGIN_PATTERNS = ["/login", "/signin", "/sign-in", "/authenticate", "/auth/login", "/sso/"]


class session_check(BaseModule):
    watched_events = []
    produced_events = []
    flags = ["active", "safe"]
    meta = {
        "description": "Validate session credentials against the target before running authenticated modules",
        "created_date": "2024-01-01",
        "author": "@suizer",
    }

    async def setup(self):
        has_bearer = "Authorization" in self.scan.custom_http_headers
        has_cookies = bool(self.scan.custom_http_cookies)

        if not has_bearer and not has_cookies:
            return None, "No auth credentials configured — add --bearer <token> or -C cookie=value"

        inputs = list(self.scan.preset.target.seeds.inputs)
        if not inputs:
            return None, "No target URL found — skipping session validation"

        target_url = str(inputs[0])
        self.info(f"Validating session against {target_url} ...")

        response = await self.helpers.request(target_url, follow_redirects=True)

        if response is None:
            return None, f"Could not reach {target_url} — skipping session validation"

        status = response.status_code
        final_url = str(response.url).lower()

        if status == 401:
            return False, (
                f"Session rejected (401 Unauthorized) on {target_url}. "
                "Verify your --bearer token or -C cookies and try again."
            )

        if status == 403:
            return False, (
                f"Session rejected (403 Forbidden) on {target_url}. "
                "Credentials may be invalid, expired, or lack sufficient permissions."
            )

        if any(pattern in final_url for pattern in LOGIN_PATTERNS):
            return False, (
                f"Redirected to login page ({response.url}). "
                "Session is invalid or expired — provide fresh credentials."
            )

        self.info(f"Session validated — HTTP {status} from {target_url}")
        return True
