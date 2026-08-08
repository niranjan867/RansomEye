"""Basic permission status reporting for RansomEye."""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass


@dataclass
class PermissionStatus:
    """Runtime permission information for the current process."""

    is_administrator: bool
    platform: str
    message: str


def is_administrator() -> bool:
    """Return True when the current process has administrator privileges."""
    if sys.platform == "win32":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False

    try:
        import os

        return os.geteuid() == 0
    except AttributeError:
        return False


def get_permission_status() -> PermissionStatus:
    """Report whether the current process is running with elevated privileges."""
    admin = is_administrator()
    current_platform = platform.system()

    if admin:
        message = "Process is running with administrator privileges."
    else:
        message = "Process is not running with administrator privileges."

    return PermissionStatus(
        is_administrator=admin,
        platform=current_platform,
        message=message,
    )
