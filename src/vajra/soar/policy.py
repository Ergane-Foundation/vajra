"""When an alert is allowed to turn into a block.

Pure decision logic with no firewall calls. The engine asks `decide` once it
has an alert or ML prediction that would justify a block, and acts on the answer.
It is called from the packet inspector thread as well, so it takes a lock.
"""

import threading
import time
from collections import deque
from typing import Callable, Deque, Dict

BLOCK = "block"
BELOW_THRESHOLD = "below_threshold"
COOLDOWN = "cooldown"
RATE_LIMITED = "rate_limited"


class BlockPolicy:
    """Require repeated evidence before blocking a source, and limit how fast blocks happen.

    - A critical alert blocks on the first hit. Anything else needs `threshold`
      alerts from the same source within `window` seconds.
    - After a source is blocked it is not blocked again for `cooldown` seconds,
      counted from the block. A ban removed by hand in that time isn't put
      straight back, and a failing firewall call isn't retried on every alert.
    - No more than `max_per_minute` new blocks in any 60 seconds. Past that the
      engine is more likely misfiring than under a real attack from that many
      sources, so it stops blocking and only logs.
    """

    def __init__(
        self,
        threshold: int = 3,
        window: int = 60,
        cooldown: int = 300,
        max_per_minute: int = 20,
        clock: Callable[[], float] = time.monotonic,
    ):
        if threshold < 1 or window < 1 or cooldown < 0 or max_per_minute < 1:
            raise ValueError("threshold, window and max_per_minute must be at least 1, cooldown at least 0")
        self.threshold = threshold
        self.window = window
        self.cooldown = cooldown
        self.max_per_minute = max_per_minute
        self.clock = clock
        self._hits: Dict[str, Deque[float]] = {}
        self._last_block: Dict[str, float] = {}
        self._recent_blocks: Deque[float] = deque()
        self._last_sweep = clock()
        self._lock = threading.Lock()

    def decide(self, source: str, critical: bool = False) -> str:
        """Record one alert from `source` and return BLOCK or the reason it isn't blocked"""
        with self._lock:
            return self._decide(source, critical)

    def _decide(self, source: str, critical: bool) -> str:
        now = self.clock()
        self._sweep(now)

        last = self._last_block.get(source)
        if last is not None and now - last < self.cooldown:
            return COOLDOWN

        hits = self._hits.setdefault(source, deque())
        hits.append(now)
        while hits and now - hits[0] >= self.window:
            hits.popleft()
        if not critical and len(hits) < self.threshold:
            return BELOW_THRESHOLD

        while self._recent_blocks and now - self._recent_blocks[0] >= 60:
            self._recent_blocks.popleft()
        if len(self._recent_blocks) >= self.max_per_minute:
            return RATE_LIMITED

        self._recent_blocks.append(now)
        self._last_block[source] = now
        del self._hits[source]
        return BLOCK

    def _sweep(self, now: float):
        """Forget sources with no recent alerts, so memory doesn't grow with every address seen"""
        if now - self._last_sweep < self.window:
            return
        self._last_sweep = now
        for source in [s for s, hits in self._hits.items() if not hits or now - hits[-1] >= self.window]:
            del self._hits[source]
        for source in [s for s, at in self._last_block.items() if now - at >= self.cooldown]:
            del self._last_block[source]
