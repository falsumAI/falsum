@echo off
REM Falsum One-Click Build
REM Double-click this file. That's it.
REM It builds Falsum.exe, sets up the browser link, and starts the app.

title Falsum Builder
echo.
echo  ========================================
echo   FALSUM - Building your protection...
echo  ========================================
echo.

REM Step 1: Check for .NET
where dotnet >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  ERROR: .NET is not installed.
    echo  Download it free from: https://dotnet.microsoft.com/download
    echo  Then double-click this file again.
    pause
    exit /b 1
)
echo  [1/4] .NET found.

REM Step 2: Build
echo  [2/4] Building Falsum... (this takes a minute)
cd /d "%~dp0src\FalsumApp"
dotnet build -c Release --nologo -v q
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo  BUILD FAILED. Copy the error above and send it to get help.
    pause
    exit /b 1
)
echo  [3/4] Build complete.

REM Step 3: Find the exe
set EXE="%~dp0src\FalsumApp\bin\Release\net8.0-windows\Falsum.exe"
if not exist %EXE% (
    echo  ERROR: Falsum.exe not found after build.
    pause
    exit /b 1
)
echo  [4/4] Falsum.exe ready.

echo.
echo  ========================================
echo   DONE. Starting Falsum...
echo  ========================================
echo.
start "" %EXE%
