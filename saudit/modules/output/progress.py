import sys
import time
import asyncio
from collections import defaultdict

from saudit.modules.output.base import BaseOutputModule


class progress(BaseOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Live scan progress display on stderr",
        "created_date": "2025-01-01",
        "author": "@suizer",
    }
    options = {"refresh_interval": 1}
    options_desc = {"refresh_interval": "Seconds between display refreshes"}
    _stats_exclude = True

    _SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    async def setup(self):
        self._counts = defaultdict(int)
        self._total = 0
        self._start = time.monotonic()
        self._spin = 0
        self._task = asyncio.create_task(self._loop())
        return True

    async def handle_event(self, event):
        if event.type == "FINISHED":
            return
        mod = getattr(event, "module", "") or "?"
        self._counts[str(mod)] += 1
        self._total += 1

    async def cleanup(self):
        if hasattr(self, "_task"):
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        # clear the progress line before exiting
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()

    async def _loop(self):
        interval = float(self.config.get("refresh_interval", 1))
        while True:
            await asyncio.sleep(interval)
            self._draw()

    def _draw(self):
        elapsed = time.monotonic() - self._start
        rate = self._total / elapsed if elapsed > 0 else 0.0
        icon = self._SPINNER[self._spin % len(self._SPINNER)]
        self._spin += 1
        top = sorted(self._counts.items(), key=lambda x: -x[1])[:4]
        parts = "  ".join(f"{m}:{c}" for m, c in top)
        line = f"\r{icon}  {self._total} events  {parts}  ({rate:.1f}/s)\033[K"
        sys.stderr.write(line)
        sys.stderr.flush()
