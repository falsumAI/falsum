@echo off
REM Sentinel Native Host launcher
REM Chrome/Edge calls this, which runs the PowerShell native host
powershell -ExecutionPolicy Bypass -File "%~dp0Sentinel-NativeHost.ps1"
