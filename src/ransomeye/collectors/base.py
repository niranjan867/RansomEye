"""Base collector interface for RansomEye continuous evidence collection."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable


class CollectorState(Enum):
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    ERROR = "ERROR"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class BaseCollector(ABC):
    """Abstract base class for evidence collectors."""

    def __init__(self, name: str = "BaseCollector"):
        self.name = name
        self.state = CollectorState.STOPPED
        self.started_at: str | None = None
        self.stopped_at: str | None = None
        self.last_event_at: str | None = None
        self.events_collected: int = 0
        self.events_accepted: int = 0
        self.events_rejected: int = 0
        self.error_message: str | None = None

    @abstractmethod
    def start(self) -> None:
        """Start the collector."""
        ...

    @abstractmethod
    def stop(self) -> None:
        """Stop the collector."""
        ...

    def status(self) -> dict[str, Any]:
        """Return truthful status and collection metrics."""
        return {
            "name": self.name,
            "state": self.state.value,
            "events_collected": self.events_collected,
            "events_accepted": self.events_accepted,
            "events_rejected": self.events_rejected,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "last_event_at": self.last_event_at,
            "error_message": self.error_message,
        }

    @abstractmethod
    def collect(self) -> Iterable[Any]:
        """Yield collected evidence events."""
        ...
