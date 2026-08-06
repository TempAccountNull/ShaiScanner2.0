@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "VCVARS64=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

if /I "%~1"=="--inside-vs-x64" goto :build

if not exist "%VCVARS64%" (
    echo [ERROR] Visual Studio 2022 Enterprise vcvars64.bat was not found:
    echo         %VCVARS64%
    pause
    exit /b 1
)

echo Opening the Visual Studio 2022 Enterprise x64 build environment...
rem /k is intentional: it keeps the developer prompt open after the build so
rem compiler output and the final status remain visible.
call %comspec% /k ""C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" && cd /d "%~dp0" && call "%~f0" --inside-vs-x64"
exit /b

:build
cd /d "%~dp0"

where cmake >nul 2>nul
if errorlevel 1 (
    echo [ERROR] CMake was not found in PATH.
    echo Install the Visual Studio CMake tools component or CMake 3.24+.
    pause
    exit /b 1
)

where powershell.exe >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Windows PowerShell was not found in PATH.
    pause
    exit /b 1
)

set "IMGUI_DIR=%SHAIHULUD_IMGUI_SOURCE_DIR%"
if not defined IMGUI_DIR set "IMGUI_DIR=%CD%\third_party\imgui-1.92.9b"

if not exist "%IMGUI_DIR%\imgui.cpp" (
    echo [1/6] Preparing pinned Dear ImGui v1.92.9b once...
    powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "tools\prepare_imgui.ps1" -ProjectRoot "%CD%" -Tag "v1.92.9b"
    if errorlevel 1 (
        echo [ERROR] Dear ImGui preparation failed.
        echo         Set SHAIHULUD_IMGUI_SOURCE_DIR to an existing v1.92.9b checkout for an offline build.
        pause
        exit /b 1
    )
) else (
    echo [1/6] Using existing Dear ImGui source: %IMGUI_DIR%
)

if not exist "%IMGUI_DIR%\backends\imgui_impl_win32.cpp" (
    echo [ERROR] The selected Dear ImGui directory is incomplete:
    echo         %IMGUI_DIR%
    pause
    exit /b 1
)

for %%I in ("%IMGUI_DIR%") do set "IMGUI_DIR=%%~fI"

echo [2/6] Verifying generated indicators and project layout...
py -3 tools\verify_project.py
if errorlevel 1 (
    echo [ERROR] Project verification failed.
    pause
    exit /b 1
)

echo [3/6] Configuring Visual Studio 2022 x64...
echo       CMake consumes the already-prepared ImGui tree and cannot download during the build.
cmake --fresh -S . -B build -G "Visual Studio 17 2022" -A x64 ^
    "-DSHAIHULUD_IMGUI_SOURCE_DIR:PATH=%IMGUI_DIR%" ^
    "-DCMAKE_SUPPRESS_REGENERATION:BOOL=ON"
if errorlevel 1 (
    echo [ERROR] CMake configuration failed.
    pause
    exit /b 1
)

echo [4/6] Building Release with parallel compilation...
cmake --build build --config Release --parallel
if errorlevel 1 (
    echo [ERROR] Build failed. Review the compiler output above.
    pause
    exit /b 1
)

echo [5/6] Running feed and hash regression tests...
ctest --test-dir build -C Release --output-on-failure
if errorlevel 1 (
    echo [ERROR] Regression tests failed.
    pause
    exit /b 1
)

echo [6/6] Preparing portable output...
if not exist dist mkdir dist
copy /Y "build\Release\ShaiHulud2Scanner.exe" "dist\ShaiHulud2Scanner.exe" >nul
if exist "build\Release\Dear-ImGui-LICENSE.txt" copy /Y "build\Release\Dear-ImGui-LICENSE.txt" "dist\Dear-ImGui-LICENSE.txt" >nul
copy /Y "build\Release\malicious_hashes.json" "dist\malicious_hashes.json" >nul
if exist dist\data rmdir /s /q dist\data
xcopy /E /I /Y "build\Release\data" "dist\data" >nul

echo.
echo [OK] Built: dist\ShaiHulud2Scanner.exe
echo [OK] Scan engine: bounded multithreaded producer/worker pipeline.
echo [OK] UI: Dear ImGui + Win32 + DirectX 11.
echo [OK] Dependency preparation: serialized before CMake configuration.
echo [OK] CMake regeneration: disabled during parallel MSBuild.
echo [OK] Runtime diagnostics are disabled by default; launch the EXE with --debug to enable the console, debug.log, and StepSecurity captures.
echo [OK] Extensible hash database: dist\malicious_hashes.json
pause
endlocal
exit /b 0
