# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build specification for RansomEye standalone Windows distribution.

Bundles RansomEye CLI, behavioral engines, static analyzer, local SQLite storage,
and the analyst console static assets into a single standalone distribution.
"""

from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

project_root = Path.cwd().resolve()
src_dir = project_root / "src"

# Static assets for dashboard console
datas = [
    (str(src_dir / "ransomeye" / "static"), "ransomeye/static"),
    (str(project_root / "THIRD_PARTY_NOTICES.md"), "."),
]

hiddenimports = [
    "ransomeye",
    "ransomeye.behavior",
    "ransomeye.file_behavior",
    "ransomeye.rules",
    "ransomeye.correlation",
    "ransomeye.threat_assessment",
    "ransomeye.investigation",
    "ransomeye.investigation_graph",
    "ransomeye.investigation_validation",
    "ransomeye.reconstruction",
    "ransomeye.advanced_timeline",
    "ransomeye.timeline",
    "ransomeye.storage",
    "ransomeye.evidence",
    "ransomeye.integrity",
    "ransomeye.export",
    "ransomeye.report",
    "ransomeye.sysmon_reader",
    "ransomeye.static_analyzer",
    "ransomeye.script_analyzer",
    "ransomeye.entropy",
    "ransomeye.dashboard_server",
    "ransomeye.collection",
    "ransomeye.collectors.base",
    "ransomeye.collectors.composite",
    "ransomeye.collectors.live_process",
    "ransomeye.collectors.live_file",
    "ransomeye.collectors.live_network",
    "ransomeye.collectors.canary_collector",
    "ransomeye.phishing",
]

a = Analysis(
    [str(src_dir / "ransomeye" / "commands.py")],
    pathex=[str(src_dir)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "torch"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="RansomEye",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
