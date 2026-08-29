"""Unit tests for ransomeye.collectors.live_network.

Deterministically tests the LiveNetworkCollector code using mocks.
"""

from __future__ import annotations

import os
import sys
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Allow running with `python -m pytest tests/` when the package is not installed.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ransomeye.collectors.base import CollectorState
from ransomeye.collectors.live_network import LiveNetworkCollector
from ransomeye.evidence import EvidenceEvent


class TestLiveNetworkCollector:

    def _make_collector(self, received: list[dict] | None = None) -> LiveNetworkCollector:
        received = received if received is not None else []
        return LiveNetworkCollector(
            case_id="CASE-456",
            on_event=received.append,
            poll_interval=0.05,
        )

    def test_psutil_unavailable_handling(self) -> None:
        import ransomeye.collectors.live_network as ln_module
        original_avail = ln_module._PSUTIL_AVAILABLE

        try:
            ln_module._PSUTIL_AVAILABLE = False
            collector = self._make_collector()
            collector.start()
            assert collector.state == CollectorState.ERROR
            assert "psutil is not installed" in collector.error_message
        finally:
            ln_module._PSUTIL_AVAILABLE = original_avail

    @patch("ransomeye.collectors.live_network._PSUTIL_AVAILABLE", True)
    @patch("ransomeye.collectors.live_network.psutil")
    def test_lifecycle_mocks(self, mock_psutil: MagicMock) -> None:
        mock_psutil.pids.return_value = []
        mock_psutil.net_connections.return_value = []
        mock_psutil.NoSuchProcess = type("NSP", (Exception,), {})
        mock_psutil.AccessDenied = type("AD", (Exception,), {})

        collector = self._make_collector()
        collector.start()
        assert collector.state == CollectorState.RUNNING

        collector.stop()
        assert collector.state == CollectorState.STOPPED

    @patch("ransomeye.collectors.live_network._PSUTIL_AVAILABLE", True)
    @patch("ransomeye.collectors.live_network.psutil")
    def test_connection_discovered_and_emitted(self, mock_psutil: MagicMock) -> None:
        received: list[dict] = []
        collector = self._make_collector(received)

        # Mock psutil net_connections returning one established TCP connection
        mock_conn = MagicMock()
        mock_conn.status = "ESTABLISHED"
        mock_conn.laddr.ip = "192.168.1.50"
        mock_conn.laddr.port = 44444
        mock_conn.raddr.ip = "8.8.8.8"
        mock_conn.raddr.port = 443
        mock_conn.type = 1  # SOCK_STREAM
        mock_conn.pid = 9999
        mock_psutil.net_connections.return_value = [mock_conn]

        # Mock psutil Process info
        mock_proc = MagicMock()
        mock_proc.name.return_value = "malware.exe"
        mock_psutil.Process.return_value = mock_proc

        collector._poll_once()

        assert len(received) == 1
        event = received[0]
        assert event["event_type"] == "network_connect"
        assert event["pid"] == 9999
        assert event["process_name"] == "malware.exe"
        assert event["case_id"] == "CASE-456"

        net_dict = event["network"]
        assert net_dict["source_ip"] == "192.168.1.50"
        assert net_dict["source_port"] == 44444
        assert net_dict["destination_ip"] == "8.8.8.8"
        assert net_dict["destination_port"] == 443
        assert net_dict["protocol"] == "tcp"

        assert "destination_hostname" not in net_dict  # no DNS fabrication

        # Verify round-trip parsing
        parsed = EvidenceEvent.from_dict(event)
        assert parsed.event_type == "network_connect"
        assert parsed.pid == 9999
        assert parsed.network["destination_ip"] == "8.8.8.8"

    @patch("ransomeye.collectors.live_network._PSUTIL_AVAILABLE", True)
    @patch("ransomeye.collectors.live_network.psutil")
    def test_permission_error_handling(self, mock_psutil: MagicMock) -> None:
        mock_psutil.net_connections.side_effect = PermissionError("Access denied")
        collector = self._make_collector()
        
        # Must handle error gracefully and not crash
        conns = collector._get_established_connections()
        assert conns == set()
