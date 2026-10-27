"""Build script to create a standalone Windows RansomEye distribution."""

import subprocess
import sys
from pathlib import Path


def build() -> int:
    project_root = Path(__file__).resolve().parent.parent
    spec_file = project_root / "scripts" / "ransomeye.spec"

    print("==================================================")
    print("      BUILDING RANSOMEYE STANDALONE EXECUTABLE    ")
    print("==================================================")
    print(f"Project root: {project_root}")
    print(f"Spec file   : {spec_file}")

    try:
        import PyInstaller
        print(f"PyInstaller version: {PyInstaller.__version__}")
    except ImportError:
        print("[-] PyInstaller is not installed in the current environment.")
        print("    Install it via: pip install pyinstaller")
        print("    Then re-run this build script.")
        return 1

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        str(spec_file),
    ]

    print(f"\nExecuting: {' '.join(cmd)}\n")
    res = subprocess.run(cmd, cwd=str(project_root))
    if res.returncode == 0:
        dist_exe = project_root / "dist" / "RansomEye.exe"
        print("\n==================================================")
        print("               BUILD SUCCESSFUL!                  ")
        print("==================================================")
        print(f"Executable output: {dist_exe}")
        return 0
    else:
        print("\n[-] Build failed with exit code:", res.returncode)
        return res.returncode


if __name__ == "__main__":
    sys.exit(build())
