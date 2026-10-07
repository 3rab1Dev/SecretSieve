"""Lightweight stage timing for ``--verbose`` output (stdlib only)."""

from __future__ import annotations

import time
from contextlib import contextmanager


class StageTimer:
    def __init__(self) -> None:
        self.marks: dict[str, float] = {}
        self._total_start = time.perf_counter()

    @contextmanager
    def stage(self, name: str):  # type: ignore[no-untyped-def]
        start = time.perf_counter()
        try:
            yield
        finally:
            self.marks[name] = self.marks.get(name, 0.0) + (time.perf_counter() - start)

    def total_ms(self) -> int:
        return int((time.perf_counter() - self._total_start) * 1000)
