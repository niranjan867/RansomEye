"""Composite collector for RansomEye.

Coordinates multiple child BaseCollector instances (e.g., LiveProcessCollector,
LiveFileCollector, LiveNetworkCollector, CanaryCollector) concurrently while
providing unified lifecycle management, truthful aggregated metrics, and fault isolation.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Sequence

from ransomeye.collectors.base import BaseCollector, CollectorState

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CompositeCollector(BaseCollector):
    """Container that manages multiple child evidence collectors concurrently.

    Parameters
    ----------
    collectors:
        Sequence of child BaseCollector instances to manage.
    on_event:
        Optional unified event callback forwarded to all child collectors that
        accept an ``on_event`` handler.
    name:
        Display name for the composite collector.
    """

    def __init__(
        self,
        collectors: Sequence[BaseCollector] | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
        name: str = "CompositeCollector",
    ) -> None:
        super().__init__(name=name)
        self.collectors: list[BaseCollector] = list(collectors) if collectors else []
        self._on_event = on_event

        if self._on_event is not None:
            self._bind_on_event(self._on_event)

    def _bind_on_event(self, callback: Callable[[dict[str, Any]], None]) -> None:
        """Propagate on_event callback to all child collectors having an on_event attribute."""
        for col in self.collectors:
            if hasattr(col, "on_event"):
                setattr(col, "on_event", callback)

    def add_collector(self, collector: BaseCollector) -> None:
        """Add a child collector to the composite."""
        if self._on_event is not None and hasattr(collector, "on_event"):
            setattr(collector, "on_event", self._on_event)
        self.collectors.append(collector)

    def get_collector(self, name: str) -> BaseCollector | None:
        """Retrieve a child collector by its name."""
        for col in self.collectors:
            if col.name == name:
                return col
        return None

    def start(self) -> None:
        """Start all child collectors with fault isolation.

        If one child collector fails to start or encounters an error, the error
        is recorded and remaining collectors continue to start normally.
        """
        if self.state == CollectorState.RUNNING:
            logger.warning("%s is already running.", self.name)
            return

        self.state = CollectorState.STARTING
        self.started_at = _now_iso()
        self.error_message = None

        started_count = 0
        failed_count = 0

        for col in self.collectors:
            try:
                col.start()
                if col.state == CollectorState.RUNNING:
                    started_count += 1
                elif col.state == CollectorState.ERROR:
                    failed_count += 1
                    logger.error(
                        "%s: child collector %s failed with error: %s",
                        self.name,
                        col.name,
                        col.error_message,
                    )
            except Exception as exc:
                failed_count += 1
                col.state = CollectorState.ERROR
                col.error_message = str(exc)
                logger.error(
                    "%s: exception starting child collector %s: %s",
                    self.name,
                    col.name,
                    exc,
                )

        if started_count > 0:
            self.state = CollectorState.RUNNING
        elif failed_count > 0 and len(self.collectors) > 0:
            self.state = CollectorState.ERROR
            self.error_message = "All child collectors failed to start."
        else:
            self.state = CollectorState.RUNNING

    def stop(self) -> None:
        """Stop all child collectors cleanly and record stopped timestamp."""
        if self.state not in (CollectorState.RUNNING, CollectorState.STARTING, CollectorState.ERROR):
            return

        self.state = CollectorState.STOPPING

        for col in self.collectors:
            try:
                col.stop()
            except Exception as exc:
                logger.error(
                    "%s: exception stopping child collector %s: %s",
                    self.name,
                    col.name,
                    exc,
                )

        self.state = CollectorState.STOPPED
        self.stopped_at = _now_iso()

    def collect(self) -> Iterable[dict[str, Any]]:
        """BaseCollector contract. In live streaming mode events are pushed via on_event."""
        return []

    def status(self) -> dict[str, Any]:
        """Return truthful aggregated metrics and per-collector child statuses."""
        total_collected = sum(c.events_collected for c in self.collectors)
        total_accepted = sum(c.events_accepted for c in self.collectors)
        total_rejected = sum(c.events_rejected for c in self.collectors)

        last_event_timestamps = [
            c.last_event_at for c in self.collectors if c.last_event_at
        ]
        latest_event_at = max(last_event_timestamps) if last_event_timestamps else None

        child_statuses: dict[str, dict[str, Any]] = {}
        for c in self.collectors:
            child_statuses[c.name] = c.status()

        return {
            "name": self.name,
            "state": self.state.value,
            "events_collected": total_collected,
            "events_accepted": total_accepted,
            "events_rejected": total_rejected,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "last_event_at": latest_event_at,
            "error_message": self.error_message,
            "collectors": child_statuses,
        }
