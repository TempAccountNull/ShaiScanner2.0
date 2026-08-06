@echo off
setlocal
cd /d "%~dp0\.."

where python.exe >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python was not found in PATH.
    pause
    exit /b 1
)

python tools\verify_project.py
if errorlevel 1 (
    echo [ERROR] Project verification failed.
    pause
    exit /b 1
)

echo.
echo Project verification passed.
pause
