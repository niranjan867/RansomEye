"""Live network collector for RansomEye.

Monitors active established network connections using psutil and generates
RansomEye-compatible network_connect evidence events.

Algorithm adapted from:
    12X-RANSOMWARE-ANALYSIS/SentinelGuard/sentinelguard/monitors/network_monitor.py

Key design decisions
--------------------
* Does NOT import any 12X modules.
* Does NOT write to any database directly. Calls on_event callback.
* Does NOT fabricate DNS names; tracks only IP addresses.
* Gracefully handles AccessDenied and other permission/process errors.
* Maps connection details into the standard RansomEye network schema.
"""

from __future__ import annotations

import logging
import socket
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Set, Tuple

from ransomeye.collectors.base import BaseCollector, CollectorState

logger = logging.getLogger(__name__)

try:
    import psutil  # type: ignore[import-untyped]
    _PSUTIL_AVAILABLE = True
    _AccessDenied = psutil.AccessDenied
    _NoSuchProcess = psutil.NoSuchProcess
except ImportError:
    psutil = None  # type: ignore[assignment]
    _PSUTIL_AVAILABLE = False
    class _AccessDeniedFallback(Exception): pass
    class _NoSuchProcessFallback(Exception): pass
    _AccessDenied = _AccessDeniedFallback  # type: ignore[misc,assignment]
    _NoSuchProcess = _NoSuchProcessFallback  # type: ignore[misc,assignment]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Connection identity is a tuple of (pid, local_ip, local_port, remote_ip, remote_port, protocol)
ConnectionId = Tuple[int | None, str, int, str, int, str]


class LiveNetworkCollector(BaseCollector):
    """Monitors established connections and generates network evidence.

    Parameters
    ----------
    case_id:
        Optional case identifier forwarded into every emitted event dict.
    on_event:
        Callback invoked synchronously for each emitted raw evidence dict.
        Signature: ``on_event(raw: dict[str, Any]) -> None``.
    poll_interval:
        Seconds between connection table scans. Default 2.0.
    """

    def __init__(
        self,
        case_id: str | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
        poll_interval: float = 2.0,
        name: str = "LiveNetworkCollector",
    ) -> None:
        super().__init__(name=name)
        self.case_id = case_id
        self.on_event = on_event
        self.poll_interval = max(0.1, float(poll_interval))
        self._known_connections: Set[ConnectionId] = set()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not _PSUTIL_AVAILABLE:
            self.state = CollectorState.ERROR
            self.error_message = "psutil is not installed; LiveNetworkCollector requires it."
            logger.error(self.error_message)
            return

        if self.state == CollectorState.RUNNING:
            logger.warning("%s is already running.", self.name)
            return

        self.state = CollectorState.STARTING
        self.started_at = _now_iso()
        self._stop_event.clear()

        # Gather initial snapshot of established connections
        try:
            self._known_connections = self._get_established_connections()
        except Exception as exc:
            logger.warning("Initial connection table snapshot failed: %s", exc)
            self._known_connections = set()

        self._thread = threading.Thread(
            target=self._poll_loop,
            name=f"{self.name}-thread",
            daemon=True,
        )
        self._thread.start()
        self.state = CollectorState.RUNNING
        logger.info("%s started (poll_interval=%.2fs).", self.name, self.poll_interval)

    def stop(self) -> None:
        if self.state not in (CollectorState.RUNNING, CollectorState.STARTING):
            return

        self.state = CollectorState.STOPPING
        self._stop_event.set()

        if self._thread is not None:
            self._thread.join(timeout=self.poll_interval * 3 + 2.0)

        self.state = CollectorState.STOPPED
        self.stopped_at = _now_iso()
        logger.info("%s stopped.", self.name)

    def collect(self) -> Iterable[dict[str, Any]]:
        return []

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception as exc:
                logger.error("Unexpected error in %s poll loop: %s", self.name, exc)

            self._stop_event.wait(self.poll_interval)

    def _get_established_connections(self) -> Set[ConnectionId]:
        connections: Set[ConnectionId] = set()
        if not _PSUTIL_AVAILABLE or psutil is None:
            return connections

        try:
            current_conns = psutil.net_connections(kind="inet")
        except (_AccessDenied, OSError) as exc:
            logger.error("Failed to read connection table: %s", exc)
            return connections

        for conn in current_conns:
            # Check established state
            if conn.status == "ESTABLISHED" or conn.status == psutil.CONN_ESTABLISHED:
                if not conn.laddr or not conn.raddr:
                    continue

                sip, sport = conn.laddr.ip, conn.laddr.port
                dip, dport = conn.raddr.ip, conn.raddr.port
                proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
                pid = conn.pid

                connections.add((pid, sip, sport, dip, dport, proto))

        return connections

    def _poll_once(self) -> None:
        try:
            current_conns = self._get_established_connections()
        except Exception as exc:
            logger.error("%s: failed to scan connections: %s", self.name, exc)
            return

        new_conns = current_conns - self._known_connections
        for conn in new_conns:
            self._emit_network_connect(conn)

        # Update known state to currently established connections
        self._known_connections = current_conns

    def _emit_network_connect(self, conn: ConnectionId) -> None:
        self.events_collected += 1
        pid, sip, sport, dip, dport, proto = conn

        proc_name: str | None = None
        if pid:
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
            except (_NoSuchProcess, _AccessDenied):
                pass

        # Build standard network dictionary
        network_data: dict[str, Any] = {
            "source_ip": sip,
            "source_port": sport,
            "destination_ip": dip,
            "destination_port": dport,
            "protocol": proto,
        }

        meta: dict[str, Any] = {
            "source_collector": "LiveNetworkCollector",
            "connection_status": "ESTABLISHED",
        }

        raw: dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "timestamp": _now_iso(),
            "source": "live_network_collector",
            "event_type": "network_connect",
            "pid": pid,
            "process_name": proc_name,
            "network": network_data,
            "metadata": meta,
        }

        if self.case_id:
            raw["case_id"] = self.case_id

        self.events_accepted += 1
        self.last_event_at = _now_iso()

        if self.on_event:
            try:
                self.on_event(raw)
            except Exception as exc:
                logger.error("%s callback exception: %s", self.name, exc)
