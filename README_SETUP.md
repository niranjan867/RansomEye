# RansomEye Setup Guide

This guide explains how to set up the RansomEye project on a new Windows computer.

## Requirements
- Python 3.13 or newer installed and added to your system PATH.
- Windows OS

## Setup Instructions

1. Copy the complete `RansomEye` folder to your new Windows computer. You can place it anywhere (e.g., `C:\RansomEye` or `Desktop\RansomEye`).
2. Double-click `start_ransomeye_setup.bat`.
3. The script will automatically perform the following steps:
   - Verify the project structure
   - Check if Python is installed
   - Create a virtual environment (`.venv`) inside the project folder
   - Upgrade basic packaging tools (`pip`, `setuptools`, `wheel`)
   - Install the RansomEye project locally (`pip install -e .`)
   - Verify the RansomEye CLI is working
   - Initialize and verify the SQLite database (`data\ransomeye.db`)
   - Run the test suite to ensure everything is functioning
4. When prompted, choose whether to start the RansomEye dashboard immediately.

## What is Installed?
- A local virtual environment (`.venv`) is created in the project folder. No system-wide packages are modified.
- The `ransomeye` package and its dependencies are installed inside `.venv`.
- `pytest` is installed inside `.venv` for running the test suite.

## Database Location
- The main SQLite database is created at `data\ransomeye.db`.
- No secondary databases or external backends (like Supabase or 12X) are used or created.

## How to Start RansomEye Manually

**To use the CLI:**
1. Open a Command Prompt or PowerShell in the RansomEye folder.
2. Run `.\.venv\Scripts\python.exe -m ransomeye.commands --help`.

**To start the Dashboard:**
1. Open a Command Prompt or PowerShell in the RansomEye folder.
2. Run `.\.venv\Scripts\python.exe -m ransomeye.dashboard_server --database data\ransomeye.db --port 8080`.
3. Open a browser to `http://localhost:8080/`.

**To stop the Dashboard:**
- Press `Ctrl+C` in the terminal where it is running.

## Common Errors
- **Python not found**: Make sure Python 3.x is installed and the "Add Python to PATH" option was checked during installation.
- **Port 8080 occupied**: If another program is using port 8080, the dashboard will fail to start. You can kill the conflicting process or modify the port argument if needed.
- **Corrupted virtual environment**: Delete the `.venv` folder and run `start_ransomeye_setup.bat` again to recreate it.
