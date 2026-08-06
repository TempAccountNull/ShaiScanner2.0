@echo off
setlocal
cd /d "%~dp0\.."

where python.exe >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python was not found in PATH.
    pause
    exit /b 1
)

python tools\generate_indicators.py
if errorlevel 1 (
    echo [ERROR] Indicator generation failed.
    pause
    exit /b 1
)

echo.
echo Embedded indicator array and feed manifest regenerated.
pause
