from .base import ModuleTestBase


class TestGoogle_Playstore(ModuleTestBase):
    modules_overrides = ["google_playstore", "speculate"]

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.99"]}})
        module_test.httpx_mock.add_response(
            url="https://play.google.com/store/search?q=blacklanternsecurity&c=apps",
            text="""<!DOCTYPE html>
            <html>
            <head>
            <title>"blacklanternsecurity" - Android Apps on Google Play</title>
            </head>
            <body>
            <a href="/store/apps/details?id=com.saudit.test&pcampaignid=dontmatchme&pli=1"/>
            <a href="/store/apps/details?id=com.saudit.other"/>
            </body>
            </html>""",
        )
        module_test.httpx_mock.add_response(
            url="https://play.google.com/store/apps/details?id=com.saudit.test",
            text="""<!DOCTYPE html>
            <html>
            <head>
            <title>SAUDIT</title>
            </head>
            <body>
            <meta name="appstore:developer_url" content="https://www.blacklanternsecurity.com">
            </div>
            </div>
            </body>
            </html>""",
        )
        module_test.httpx_mock.add_response(
            url="https://play.google.com/store/apps/details?id=com.saudit.other",
            text="""<!DOCTYPE html>
            <html>
            <head>
            <title>SAUDIT</title>
            </head>
            <body>
            <meta name="appstore:developer_url" content="">
            <a href="mailto:support@blacklanternsecurity.com"></a>
            </div>
            </div>
            </body>
            </html>""",
        )

    def check(self, module_test, events):
        assert len(events) == 6
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME" and e.data == "blacklanternsecurity.com" and e.scope_distance == 0
            ]
        ), "Failed to emit target DNS_NAME"
        assert 1 == len(
            [e for e in events if e.type == "ORG_STUB" and e.data == "blacklanternsecurity" and e.scope_distance == 0]
        ), "Failed to find ORG_STUB"
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "MOBILE_APP"
                and "android" in e.tags
                and e.data["id"] == "com.saudit.test"
                and e.data["url"] == "https://play.google.com/store/apps/details?id=com.saudit.test"
            ]
        ), "Failed to find saudit android app"
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "MOBILE_APP"
                and "android" in e.tags
                and e.data["id"] == "com.saudit.other"
                and e.data["url"] == "https://play.google.com/store/apps/details?id=com.saudit.other"
            ]
        ), "Failed to find other saudit android app"
