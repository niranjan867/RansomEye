"""Tests for basic permission status reporting."""

from __future__ import annotations

from ransomeye.permissions import get_permission_status


def test_permission_status_shape_and_types():
    status = get_permission_status()
    assert hasattr(status, "is_administrator")
    assert hasattr(status, "platform")
    assert hasattr(status, "message")
    assert isinstance(status.is_administrator, bool)
    assert isinstance(status.platform, str)
    assert isinstance(status.message, str)
