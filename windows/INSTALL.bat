@echo off
REM ============================================================
REM  FALSUM — One installer. Everything.
REM  App + GUI + Browser Extension + AI Model
REM ============================================================
echo.
echo  ========================================
echo   FALSUM — Unified Installer
echo  ========================================
echo.
echo  This will install:
echo   [1] Desktop application (console + GUI)
echo   [2] Browser extension native host
echo   [3] Local AI model (optional, downloads on demand)
echo.
pause

REM Run the main installer
powershell -ExecutionPolicy Bypass -File "%~dp0INSTALL.ps1"

echo.
echo  ========================================
echo   Install AI model? (downloads ~600MB-2.5GB)
echo  ========================================
echo.
set /p AI="Install local AI? (y/n): "
if /i "%AI%"=="y" (
    powershell -ExecutionPolicy Bypass -File "%~dp0Setup-AI.ps1"
)

echo.
echo  Done. See README-SETUP.txt for browser extension steps.
pause
