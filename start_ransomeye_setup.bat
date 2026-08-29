@echo off
setlocal EnableDelayedExpansion

:: Step 1 - Detect project location
set "PROJECT_ROOT=%~dp0"
if "%PROJECT_ROOT:~-1%"=="\" set "PROJECT_ROOT=%PROJECT_ROOT:~0,-1%"

cd /d "%PROJECT_ROOT%"

echo ==============================================
echo        RANSOMEYE SETUP
echo ==============================================
echo.

echo [1/8] Checking project...
if not exist "pyproject.toml" (
    echo Error: pyproject.toml not found in %PROJECT_ROOT%
    echo Please make sure this script is in the RansomEye project root.
    goto :error
)
if not exist "src\ransomeye" (
    echo Error: src\ransomeye not found in %PROJECT_ROOT%
    goto :error
)
if not exist "tests" (
    echo Error: tests directory not found in %PROJECT_ROOT%
    goto :error
)
if not exist "data" (
    mkdir "data"
)
echo Project structure is valid.
echo.

echo [2/8] Checking Python...
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ========================================
    echo RANSOMEYE SETUP ERROR
    echo ========================================
    echo Python was not found.
    echo.
    echo Install Python 3.x and ensure:
    echo "Add Python to PATH"
    echo.
    echo Then run this setup again.
    echo ========================================
    goto :error
)
for /f "tokens=* usebackq" %%i in (`python --version`) do set PYTHON_VERSION=%%i
echo Detected: !PYTHON_VERSION!
echo.

echo [3/8] Creating virtual environment...
if not exist ".venv" (
    python -m venv .venv
    if !ERRORLEVEL! neq 0 (
        echo Error: Failed to create virtual environment.
        goto :error
    )
    echo Virtual environment created.
) else (
    echo Reusing existing .venv
)

if not exist ".venv\Scripts\python.exe" (
    echo Error: .venv\Scripts\python.exe not found.
    echo The virtual environment might be corrupted.
    goto :error
)
echo.

echo [4/8] Installing dependencies...
echo Upgrading basic tools...
.venv\Scripts\python.exe -m pip install --upgrade pip setuptools wheel
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to upgrade pip/setuptools.
    goto :error
)

echo Installing RansomEye...
.venv\Scripts\python.exe -m pip install -e .
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to install RansomEye.
    goto :error
)

echo Installing pytest...
.venv\Scripts\python.exe -m pip install pytest
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to install pytest.
    goto :error
)
echo Dependencies installed successfully.
echo.

echo [5/8] Verifying RansomEye...
.venv\Scripts\python.exe -m ransomeye.commands --help >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Error: RansomEye CLI verification failed.
    goto :error
)
echo RansomEye CLI: OK
echo.

echo [6/8] Setting up database...
if not exist "data\ransomeye.db" (
    echo Initializing database...
    .venv\Scripts\python.exe -m ransomeye.commands case list --database data\ransomeye.db >nul 2>&1
    if !ERRORLEVEL! neq 0 (
        echo Error: Failed to initialize database.
        goto :error
    )
) else (
    echo Reusing existing data\ransomeye.db
)

echo Verifying database...
.venv\Scripts\python.exe -m ransomeye.commands database check --database data\ransomeye.db >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Error: Database verification failed.
    goto :error
)
echo Database: OK
echo.

echo [7/8] Running tests...
.venv\Scripts\pytest
if %ERRORLEVEL% neq 0 (
    echo ========================================
    echo RANSOMEYE TEST VERIFICATION
    echo ========================================
    echo Error: Tests failed. This might indicate an environment issue.
    set TEST_RESULT=FAILED
) else (
    set TEST_RESULT=PASSED
)
echo.

echo [8/8] Starting dashboard...
.venv\Scripts\python.exe -m ransomeye.dashboard_server --help >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Error: Dashboard module could not be verified.
    goto :error
)
echo Dashboard module: OK
echo.

:: Logging
if not exist "logs" mkdir "logs"
echo [%date% %time%] Setup completed successfully on !PYTHON_VERSION! >> logs\setup.log
echo Project: %PROJECT_ROOT% >> logs\setup.log

:: Final Output
echo =============================================
echo        RANSOMEYE SETUP COMPLETE
echo =============================================
echo Project:
echo %PROJECT_ROOT%
echo.
echo Python:
echo !PYTHON_VERSION!
echo.
echo Virtual Environment:
echo READY
echo.
echo RansomEye:
echo INSTALLED
echo.
echo Database:
echo READY
echo.
echo Tests:
echo !TEST_RESULT!
echo.
echo Dashboard:
echo http://localhost:8080/
echo =============================================
echo RansomEye is ready to use.
echo.

set /p START_DASHBOARD="Setup completed. Start RansomEye dashboard? Y/N: "
if /i "!START_DASHBOARD!"=="Y" (
    echo Starting dashboard...
    start http://localhost:8080/
    .venv\Scripts\python.exe -m ransomeye.dashboard_server --database data\ransomeye.db --port 8080
)

goto :eof

:error
echo [%date% %time%] Setup failed >> logs\setup.log
echo.
echo Setup did not complete successfully.
pause
exit /b 1
